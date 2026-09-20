// collector_http.m — 聚合历史查询 HTTP 服务(collector 侧,ObjC + Foundation)
//
// 按需系统 daemon 短命,退出后活引擎的 http://ip:809x 不可达、引擎内存态(DHLogStore 富视图)随进程消失。
// companion 已把每条结构化捕获(带引擎自己的 category、完整 in/out、key/iv/pki)落到
// /var/log/dh-<proc>.cap.jsonl(见 dh_shm.h cap_ring + companion dh_cap_emit)。本模块在固定聚合口
// AGG_PORT 起 HTTP,读 cap.jsonl 用 NSJSONSerialization 解析,**重建引擎那套 /api/stats、/api/logs、
// 单条详情**,并原样托管引擎 WebUI HTML(仅把绝对 '/api/ 路径按 per-daemon 前缀机械改写),于是
// **daemon 死后仍能像连活引擎一样富查询**(分类过滤/搜索/单条完整 I/O + callStack + crypto 料)。
//
// 不用 SQLite:按需 daemon 捕获量小(实测注入后 ~26s 被回收),cap.jsonl 本身即持久 store,
// 每次查询全量载入 + 内存过滤足够;换来零第三方依赖、严谨的系统级 JSON 解析。
//
// seq 归一化:引擎 seq 每次 daemon 重启从 1 重来,cap.jsonl 跨实例累积会碰撞;故本层按 tsMs 排序、
// 去重(原始 seq+tsMs+tid)后赋**稳定序号 _seq(1..N)** 作为呈现给 WebUI 的 seq(它把高 seq 当新)。
// 死 daemon 的 cap.jsonl 已冻结 → 序号稳定。

#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <fcntl.h>
#import <pthread.h>
#import <string.h>
#import <errno.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>   // _NSGetExecutablePath
#import <signal.h>        // kill(App 重启=结束进程)
#import <spawn.h>         // posix_spawn(uiopen 启动 App)
#import <sys/wait.h>      // waitpid
extern char **environ;

extern void dh_log(const char *s);                       // collector.c:带时间戳落 collector.log
extern int  dh_bridge_online(const char *proc, int *lan_port);  // collector.c:引擎是否就绪(可连活引擎)
extern int  dh_proc_alive(const char *proc);                    // collector.c:进程是否存活(sysctl),0=已退出
extern int  dh_restart_daemon(const char *proc);                // collector.c:kickstart 重启 daemon,0=成功
extern const char *dh_daemons_json(void);                       // collector.c:白名单 [{proc,disp,domain}]
extern int  dh_app_mem_read(int pid, uint32_t *port, char *bundle, size_t bcap, char *ver, size_t vcap);  // App vm_read 发现

// 注入门控 config(companion dh_enabled / collector mb_is_enabled 都读这份;与它们同路径)。
#define DH_CFG_PATH @"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"
#define DH_KEY_EXECS   @"enabledExecutables"   // 系统 daemon 注入名单(按 exec 名)
#define DH_KEY_BUNDLES @"enabledBundles"        // App 注入名单(按 bundle id)
static BOOL validProc(NSString *p);   // fwd(定义在索引页附近)
// 门控 config 读:key 下的数组是否含 val。key = DH_KEY_EXECS(daemon)/ DH_KEY_BUNDLES(App)。
static BOOL cfgHasMember(NSString *key, NSString *val) {
    NSArray *a = [NSDictionary dictionaryWithContentsOfFile:DH_CFG_PATH][key];
    return [a isKindOfClass:[NSArray class]] && [a containsObject:val];
}
static NSArray *cfgMembers(NSString *key) {
    NSArray *a = [NSDictionary dictionaryWithContentsOfFile:DH_CFG_PATH][key];
    return [a isKindOfClass:[NSArray class]] ? a : @[];
}
// 读改写:保留其它 key 与同 key 里其它成员,只加/删本 val(整份覆写会互抹 enabledBundles/Executables,见 memory)。
static BOOL cfgSetMember(NSString *key, NSString *val, BOOL on) {
    NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:DH_CFG_PATH] mutableCopy] ?: [NSMutableDictionary dictionary];
    NSMutableArray *a = [([d[key] isKindOfClass:[NSArray class]] ? d[key] : @[]) mutableCopy];
    BOOL has = [a containsObject:val];
    if (on && !has) [a addObject:val];
    else if (!on && has) [a removeObject:val];
    d[key] = a;
    return [d writeToFile:DH_CFG_PATH atomically:YES];
}

// daemon 三态:live=引擎就绪可连活引擎 / idle=进程在但没注入引擎(未启用) / dead=进程已退出仅历史。
// 返回并回填 lan_port(仅 live 有意义)。
static NSString *procState(NSString *proc, int *lanPort) {
    if (dh_bridge_online([proc UTF8String], lanPort)) return @"live";
    return dh_proc_alive([proc UTF8String]) ? @"idle" : @"dead";
}

#define AGG_PORT 8089
#define ENGINE_VER "1.27.4"   // 重建 stats 显示用(当前 vendor 引擎版本;仅展示)

static void aggLog(NSString *s) { dh_log([s UTF8String]); }

// 引擎权威 9 类表(IDA 1.27.3:dh_log_category_count()=9;dh_log_category_name:idx<=8 用表否则 "other")。
static const char *kCatNames[9] = { "digest","hmac","sym","asym","file","sys","net","keychain","other" };
static NSString *catName(NSInteger c) { return (c >= 0 && c <= 8) ? @(kCatNames[c]) : @"other"; }
static NSInteger catBucket(NSInteger c) { return (c < 0 || c > 8) ? 8 : c; }   // byCategory 归桶(照抄引擎)

// ———— 字节渲染 helpers ————
static NSString *hexOf(NSData *d) {
    if (!d.length) return @"";
    const uint8_t *p = d.bytes; NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02x", p[i]];
    return s;
}
// 可打印则返回 UTF-8 文本,否则 nil(WebUI 的 ioBody 会跳过 utf8 段)。
static NSString *utf8Of(NSData *d) {
    if (!d.length) return nil;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!s) return nil;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') return nil;   // 含控制字符 → 视为二进制
    }
    return s;
}
static NSString *hexdumpOf(NSData *d) {
    if (!d.length) return @"";
    const uint8_t *p = d.bytes; NSUInteger n = d.length;
    NSMutableString *s = [NSMutableString stringWithCapacity:n * 4];
    for (NSUInteger off = 0; off < n; off += 16) {
        [s appendFormat:@"%08lx  ", (unsigned long)off];
        NSUInteger j;
        for (j = 0; j < 16; j++) {
            if (off + j < n) [s appendFormat:@"%02x ", p[off + j]]; else [s appendString:@"   "];
            if (j == 7) [s appendString:@" "];
        }
        [s appendString:@" |"];
        for (j = 0; j < 16 && off + j < n; j++) {
            uint8_t c = p[off + j]; [s appendFormat:@"%c", (c >= 0x20 && c < 0x7f) ? c : '.'];
        }
        [s appendString:@"|\n"];
    }
    return s;
}
// 列表用短预览:输入可打印则截前 96 字节文本,否则前 24 字节 hex。
static NSString *inPreview(NSData *d) {
    if (!d.length) return @"";
    NSString *u = utf8Of(d);
    if (u) return u.length > 96 ? [u substringToIndex:96] : u;
    return hexOf([d subdataWithRange:NSMakeRange(0, MIN(d.length, (NSUInteger)24))]);
}
static NSString *outHexPreview(NSData *d) {
    if (!d.length) return @"";
    return hexOf([d subdataWithRange:NSMakeRange(0, MIN(d.length, (NSUInteger)24))]);
}
static NSData *b64(NSString *s) {
    if (![s isKindOfClass:[NSString class]] || !s.length) return nil;
    return [[NSData alloc] initWithBase64EncodedString:s options:0];
}
static NSString *fmtTs(long long ms) {
    static NSDateFormatter *df; static dispatch_once_t once;
    dispatch_once(&once, ^{ df = [NSDateFormatter new]; df.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]; });
    return [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:ms / 1000.0]];
}
static long long jint(id v) { return [v isKindOfClass:[NSNumber class]] ? [v longLongValue] : 0; }
static NSString *jstr(id v) { return [v isKindOfClass:[NSString class]] ? v : @""; }

// ———— 载入 cap.jsonl → 归一化(去重 + tsMs 排序 + 赋稳定 _seq)————
static NSString *capPath(NSString *proc) { return [NSString stringWithFormat:@"/var/log/dh-%@.cap.jsonl", proc]; }

// 单次最多读 cap.jsonl 末尾 CAP_READ_MAX:旧实现把整文件读进内存(NSData + NSString + 全行数组 三份
// 拷贝),会随文件增长撑爆 collector 的默认 jetsam 内存上限被 SIGKILL(实测 lockdownd 2.4MB 即触发,
// 前台无此限则不崩)。改流式:NSFileHandle 分块读、复用行缓冲逐行解析,峰值只跟单行 + 结果集走;再对
// 超大文件只读末尾(防 104MB 那种跑飞)。@autoreleasepool 每块回收行内临时对象。
#define CAP_READ_MAX (4ull * 1024 * 1024)
static NSArray<NSDictionary *> *loadEntries(NSString *proc) {
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:capPath(proc)];
    if (!fh) return @[];
    unsigned long long size = [fh seekToEndOfFile];
    BOOL tailed = size > CAP_READ_MAX;
    [fh seekToFileOffset:tailed ? size - CAP_READ_MAX : 0];
    NSMutableArray<NSMutableDictionary *> *rows = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSUInteger ord = 0, bad = 0;
    NSMutableData *line = [NSMutableData data];
    BOOL dropPartial = tailed;   // 从中间开读,首个可能是半行 → 丢到第一个换行
    NSData *chunk;
    while ((chunk = [fh readDataOfLength:(1u << 16)]).length > 0) {
        @autoreleasepool {
            const uint8_t *b = chunk.bytes; NSUInteger n = chunk.length, s = 0;
            for (NSUInteger i = 0; i < n; i++) {
                if (b[i] != '\n') continue;
                [line appendBytes:b + s length:i - s]; s = i + 1;
                if (dropPartial) { dropPartial = NO; line.length = 0; continue; }
                if (line.length == 0) continue;
                id obj = [NSJSONSerialization JSONObjectWithData:line options:0 error:NULL];
                if (![obj isKindOfClass:[NSDictionary class]]) {
                    // 严谨:不静默吞。坏行记日志(前 120 字节)后跳过——companion 用 NSJSONSerialization
                    // 生成,坏行必是真 bug(截断/环回绕越界),要能被看见。
                    if (bad++ < 3) {
                        NSString *p = [[NSString alloc] initWithData:[line subdataWithRange:NSMakeRange(0, MIN(line.length, (NSUInteger)120))] encoding:NSUTF8StringEncoding];
                        aggLog([NSString stringWithFormat:@"[agg] %@ cap.jsonl 坏行(跳过): %@", proc, p ?: @"<非 UTF-8>"]);
                    }
                    line.length = 0; continue;
                }
                NSDictionary *r = obj;
                // 去重:同一条(backfill 与流式罕见重叠)= 原始 seq+tsMs+tid 全同;跨实例 tsMs 不同 → 不误并。
                NSString *k = [NSString stringWithFormat:@"%lld|%lld|%lld", jint(r[@"seq"]), jint(r[@"tsMs"]), jint(r[@"tid"])];
                if (![seen containsObject:k]) {
                    [seen addObject:k];
                    NSMutableDictionary *m = [r mutableCopy]; m[@"_ord"] = @(ord++); [rows addObject:m];
                }
                line.length = 0;
            }
            [line appendBytes:b + s length:n - s];   // 尾部残留(跨块的半行),下块续上
        }
    }
    // 文件末尾无换行的半行不完整,丢弃(不 parse)。
    // 按 tsMs 升序(引擎 backfill 的 snapshot 可能按分类而非时序);tie 用原文件序,确定稳定。
    [rows sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        long long ta = jint(a[@"tsMs"]), tb = jint(b[@"tsMs"]);
        if (ta != tb) return ta < tb ? NSOrderedAscending : NSOrderedDescending;
        long long oa = jint(a[@"_ord"]), ob = jint(b[@"_ord"]);
        return oa < ob ? NSOrderedAscending : (oa > ob ? NSOrderedDescending : NSOrderedSame);
    }];
    for (NSUInteger i = 0; i < rows.count; i++) rows[i][@"_seq"] = @(i + 1);   // 稳定序号,高=新
    return rows;
}

// ———— 原始记录 → 引擎字段 ————
static NSDictionary *listItem(NSDictionary *r) {
    NSInteger cat = (NSInteger)jint(r[@"cat"]);
    NSData *in = b64(r[@"in"]), *out = b64(r[@"out"]);
    return @{
        @"seq": r[@"_seq"] ?: @0,
        @"category": @(cat), @"categoryName": catName(cat),
        @"algorithm": jstr(r[@"algo"]), @"operation": jstr(r[@"op"]), @"detail": jstr(r[@"detail"]),
        @"timestampMs": @(jint(r[@"tsMs"])), @"timestamp": fmtTs(jint(r[@"tsMs"])),
        @"threadId": @(jint(r[@"tid"])),
        @"inLen": @(jint(r[@"inLen"])), @"outLen": @(jint(r[@"outLen"])),
        @"preview": inPreview(in), @"outputHexPreview": outHexPreview(out),
    };
}
static NSDictionary *detailItem(NSDictionary *r) {
    NSMutableDictionary *d = [listItem(r) mutableCopy];
    NSData *in = b64(r[@"in"]), *out = b64(r[@"out"]);
    d[@"callStack"] = jstr(r[@"cs"]);
    d[@"input"] = @(in.length); d[@"inputHex"] = hexOf(in); d[@"inputDump"] = hexdumpOf(in);
    { NSString *u = utf8Of(in); if (u) d[@"inputUtf8"] = u; }
    d[@"output"] = @(out.length); d[@"outputHex"] = hexOf(out); d[@"outputDump"] = hexdumpOf(out);
    { NSString *u = utf8Of(out); if (u) d[@"outputUtf8"] = u; }
    // crypto 料(仅捕获到才有)
    NSData *key = b64(r[@"key"]), *iv = b64(r[@"iv"]);
    if (key.length) { d[@"key"] = @(key.length); d[@"keyHex"] = hexOf(key); }
    if (iv.length)  { d[@"iv"]  = @(iv.length);  d[@"ivHex"]  = hexOf(iv); }
    if ([r[@"pki"] isKindOfClass:[NSString class]] && [r[@"pki"] length]) d[@"publicKeyInfo"] = r[@"pki"];
    return d;
}
static NSString *deviceModel(void) {
    char buf[64]; size_t n = sizeof buf;
    if (sysctlbyname("hw.machine", buf, &n, NULL, 0) == 0) return @(buf);
    return @"";
}
static NSDictionary *statsFor(NSString *proc, NSArray<NSDictionary *> *entries) {
    NSMutableArray *byCat = [NSMutableArray arrayWithCapacity:9];
    for (int i = 0; i < 9; i++) byCat[i] = @0;
    for (NSDictionary *r in entries) { NSInteger b = catBucket((NSInteger)jint(r[@"cat"])); byCat[b] = @([byCat[b] intValue] + 1); }
    NSArray *names = @[@"digest",@"hmac",@"sym",@"asym",@"file",@"sys",@"net",@"keychain",@"other"];
    NSProcessInfo *pi = [NSProcessInfo processInfo];
    int lanPort = 0; NSString *state = procState(proc, &lanPort);   // live / idle / dead
    BOOL live = [state isEqualToString:@"live"];
    int pid = dh_proc_alive([proc UTF8String]);
    NSDictionary *process = @{
        @"deviceModel": deviceModel(), @"arch": @"arm64e", @"appName": @"",
        @"physicalMemoryMB": @((long long)(pi.physicalMemory / (1024 * 1024))),
        @"bundleId": @"", @"processName": proc,
        @"systemVersion": pi.operatingSystemVersionString ?: @"", @"pid": @(pid),
    };
    return @{
        @"paused": @NO, @"noiseEnabled": @[@YES, @YES], @"version": @ENGINE_VER,
        @"logBytes": @0, @"total": @(entries.count), @"categoryNames": names,
        // health.summary 引擎专用于「真实健康故障」——非空即弹红条「失效: …」+ 红点告警。历史重建是
        // 正常态,故留空(像健康引擎);三态区分放索引页 + 顶部胶囊(读 state),不在此误报「失效」。
        @"health": @{ @"hookFails": @0, @"httpFailed": @NO, @"localOnly": @NO, @"persistFailed": @NO, @"summary": @"" },
        @"noiseCount": @[@0, @0], @"pausedByCat": @[@NO,@NO,@NO,@NO,@NO,@NO,@NO,@NO,@NO],
        @"byCategory": byCat, @"port": @(live ? lanPort : 0), @"history": @YES,
        @"state": state,        // live=引擎就绪可连活引擎 / idle=进程在未注入引擎 / dead=已退出仅历史
        @"process": process,
    };
}

// ———— HTTP I/O ————
static void writeAll(int fd, const void *buf, size_t n) {
    const char *p = buf; size_t off = 0;
    while (off < n) { ssize_t w = write(fd, p + off, n - off); if (w <= 0) break; off += (size_t)w; }
}
static void httpSend(int fd, int code, const char *status, const char *ctype, NSData *body) {
    NSString *hdr = [NSString stringWithFormat:
        @"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
        code, status, ctype, (unsigned long)body.length];
    NSData *hd = [hdr dataUsingEncoding:NSUTF8StringEncoding];
    writeAll(fd, hd.bytes, hd.length);
    if (body.length) writeAll(fd, body.bytes, body.length);
}
static void sendJSON(int fd, id obj) {
    NSData *b = [NSJSONSerialization dataWithJSONObject:obj options:0 error:nil];
    httpSend(fd, 200, "OK", "application/json; charset=utf-8", b ?: [NSData data]);
}
static void sendHTML(int fd, NSString *s) {
    httpSend(fd, 200, "OK", "text/html; charset=utf-8", [s dataUsingEncoding:NSUTF8StringEncoding]);
}
static void sendText(int fd, NSString *s) {
    httpSend(fd, 200, "OK", "text/plain; charset=utf-8", [s dataUsingEncoding:NSUTF8StringEncoding]);
}
static void send404(int fd) { httpSend(fd, 404, "Not Found", "text/plain; charset=utf-8",
    [@"404" dataUsingEncoding:NSUTF8StringEncoding]); }

// ———— WebUI HTML(collector 同目录的快照)+ per-daemon 路径改写 ————
static NSString *webuiRaw(void) {
    static NSString *cached; static dispatch_once_t once;
    dispatch_once(&once, ^{
        char exe[4096]; uint32_t sz = sizeof exe;
        if (_NSGetExecutablePath(exe, &sz) != 0) return;
        NSString *dir = [[NSString stringWithUTF8String:exe] stringByDeletingLastPathComponent];
        cached = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:@"webui.html"]
                                           encoding:NSUTF8StringEncoding error:nil];
        if (!cached) aggLog(@"[agg] webui.html 未找到(collector 同目录),per-daemon 页只能返回占位");
    });
    return cached;
}
// WebUI 用绝对 '/api/…' 与 '/download;在 /d/<proc>/ 下托管时按前缀机械改写(全是单引号字面量,精确)。
static NSString *webuiForProc(NSString *proc) {
    NSString *raw = webuiRaw();
    if (!raw) return [NSString stringWithFormat:@"<h3>webui.html 缺失</h3><p>%@ 的历史 API 仍可用:"
        "<a href='/d/%@/api/stats'>stats</a> · <a href='/d/%@/api/logs'>logs</a></p>", proc, proc, proc];
    NSString *pfx = [NSString stringWithFormat:@"/d/%@", proc];
    NSMutableString *h = [raw mutableCopy];
    [h replaceOccurrencesOfString:@"'/api/" withString:[NSString stringWithFormat:@"'%@/api/", pfx]
                          options:0 range:NSMakeRange(0, h.length)];
    [h replaceOccurrencesOfString:@"'/download" withString:[NSString stringWithFormat:@"'%@/download", pfx]
                          options:0 range:NSMakeRange(0, h.length)];
    // 顶部胶囊标三态:引擎胶囊原本只有 已暂停/运行中,分不清「进程退了/进程在但没注入引擎/引擎就绪」。
    // 快照是我们自己 vendor 的,这里改写那两句(文案+圆点)读 stats.state(live/idle/dead)。改写失配
    // (引擎升级换了文本)只会退回原样,不崩。
    [h replaceOccurrencesOfString:@"stats.paused ? '已暂停' : '运行中'"
                      withString:@"stats.state==='dead' ? '已退出' : (stats.state==='idle' ? '进程在·未注入引擎' : (stats.paused ? '已暂停' : '运行中'))"
                         options:0 range:NSMakeRange(0, h.length)];
    [h replaceOccurrencesOfString:@"(stats.health && stats.health.summary) ? 'err' : (stats.paused ? 'paused' : 'ok')"
                      withString:@"stats.state!=='live' ? 'paused' : ((stats.health && stats.health.summary) ? 'err' : (stats.paused ? 'paused' : 'ok'))"
                         options:0 range:NSMakeRange(0, h.length)];
    return h;
}

// ———— 索引页:列所有有 cap.jsonl 的 daemon(在线/历史 + total + 最近时间)————
static BOOL validProc(NSString *p) {
    if (!p.length || p.length > 64) return NO;
    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    return [[p stringByTrimmingCharactersInSet:ok] length] == 0;
}
// 同步 GET 本机 http://127.0.0.1:<port>/api/stats → dict(在页面生成线程里,超时兜底)。连的是 collector
// 自己的 daemon 反代端口 / 或 App 进程自 bind 的引擎端口,只读请求不刷引擎网络 tab。
static NSDictionary *fetchStats(int port, double timeout) {
    if (port <= 0) return nil;
    NSURLRequest *req = [NSURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d/api/stats", port]]
                                         cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeout];
    __block NSDictionary *res = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        id j = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
        if ([j isKindOfClass:[NSDictionary class]]) res = j;
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 0.5) * NSEC_PER_SEC)));
    return res;
}
// live daemon 的引擎版本——区分「旧实例没重启=还跑旧引擎」。
static NSString *liveEngineVersion(int port) {
    NSString *v = fetchStats(port, 2.0)[@"version"];
    return [v isKindOfClass:[NSString class]] ? [v stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] : nil;
}
// (曾试过扫 8088-8108 按 bundleId 发现 App 引擎端口做「连活引擎」,但 iOS 会挂起后台第三方 App、其端口
//  不响应,扫不到——App 引擎 WebUI 只在 App 前台时活,稳定的连活引擎只有常驻不挂起的 daemon 能做。故 App
//  tab 不做连活引擎,只列表/注入/pid/运行/重启。见 memory「App 后台挂起端口扫不到」坑。)
// 引擎版本按「实例(pid)」缓存:同一 pid 只查一次活引擎(≈引擎加载后首见时),索引页刷新直接读缓存、不再
// 每次拉;daemon 重启(pid 变)自动重查。为什么不让 companion 加载引擎时自报:要看的「还跑旧引擎」的
// daemon 跑的是**旧 companion**(与旧引擎同批部署,没有自报代码),自报不了 → 只能 collector 侧查,缓存兜住效率。
static NSString *cachedEngineVersion(NSString *proc, int pid, int port) {
    static NSMutableDictionary *cache; static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary dictionary]; });
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    @synchronized(cache) {
        NSArray *e = cache[proc];   // @[pid, ver(NSString 或 NSNull), 负缓存到期]
        if (e && [e[0] intValue] == pid) {
            if ([e[1] isKindOfClass:[NSString class]]) return e[1];   // 有版本:同 pid 一直用
            if ([e[2] doubleValue] > now) return nil;                 // 负缓存未过期:仍 nil
            // 负缓存过期 → 落下去重查(修:重启后引擎架桥要 1~2s,那时查 nil 不能永久卡住)
        }
    }
    NSString *ver = liveEngineVersion(port);
    @synchronized(cache) { cache[proc] = @[@(pid), ver ?: (id)[NSNull null], @(now + (ver ? 3600 : 5))]; }
    return ver;
}
// —— 控制台数据/操作 ——
static id whitelistArray(void) {
    return [NSJSONSerialization JSONObjectWithData:[@(dh_daemons_json()) dataUsingEncoding:NSUTF8StringEncoding] options:0 error:NULL];
}
static BOOL isWhitelisted(NSString *proc) {
    id wl = whitelistArray();
    if (![wl isKindOfClass:[NSArray class]]) return NO;
    for (NSDictionary *w in wl) if ([w[@"proc"] isEqual:proc]) return YES;
    return NO;
}
// 捕获数:只数 '\n' 不解析(轻量,控制台刷新用),不去重(粗略指示)。
static NSUInteger capLineCount(NSString *proc) {
    NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:capPath(proc)];
    if (!fh) return 0;
    NSUInteger n = 0; NSData *c;
    while ((c = [fh readDataOfLength:(1u << 16)]).length)
        { const uint8_t *b = c.bytes; for (NSUInteger i = 0; i < c.length; i++) if (b[i] == '\n') n++; }
    return n;
}
// 控制台 daemon 列表:白名单 × {enabled(config), state(live/idle/dead), version, latest, count, port}。
static NSArray *controlDaemonList(void) {
    id wl = whitelistArray();
    NSMutableArray *out = [NSMutableArray array];
    if (![wl isKindOfClass:[NSArray class]]) return out;
    for (NSDictionary *w in wl) {
        NSString *proc = w[@"proc"];
        if (![proc isKindOfClass:[NSString class]]) continue;
        int lanPort = 0; NSString *state = procState(proc, &lanPort);
        BOOL live = [state isEqualToString:@"live"];
        int pid = dh_proc_alive([proc UTF8String]);
        NSString *ver = live ? cachedEngineVersion(proc, pid, lanPort) : nil;
        [out addObject:@{
            @"proc": proc, @"disp": (w[@"disp"] ?: proc), @"domain": (w[@"domain"] ?: @""),
            @"enabled": @(cfgHasMember(DH_KEY_EXECS, proc)),
            @"state": state, @"version": (ver ?: @""), @"pid": @(pid),
            @"latest": @(ver != nil && [ver isEqualToString:@ENGINE_VER]),
            @"count": @(capLineCount(proc)), @"port": @(live ? lanPort : 0),
        }];
    }
    return out;
}
// —— App 桌面可见性过滤(照抄 manager DHAppEnumerator,滤掉非桌面系统组件)——
static BOOL appTagsNonHome(id tags) {
    if (![tags isKindOfClass:[NSArray class]]) return NO;
    for (id t in (NSArray *)tags) {
        if (![t isKindOfClass:[NSString class]]) continue;
        if ([t caseInsensitiveCompare:@"hidden"] == NSOrderedSame) return YES;
        if ([t caseInsensitiveCompare:@"SBInternalAppTag"] == NSOrderedSame) return YES;
    }
    return NO;
}
static BOOL appHasIcon(NSDictionary *info) {
    id icons = info[@"CFBundleIcons"];
    id primary = [icons isKindOfClass:[NSDictionary class]] ? icons[@"CFBundlePrimaryIcon"] : nil;
    id files = [primary isKindOfClass:[NSDictionary class]] ? primary[@"CFBundleIconFiles"] : nil;
    if ([files isKindOfClass:[NSArray class]] && [files count]) return YES;
    id legacy = info[@"CFBundleIconFiles"];
    if ([legacy isKindOfClass:[NSArray class]] && [legacy count]) return YES;
    id single = info[@"CFBundleIconFile"];
    return [single isKindOfClass:[NSString class]] && [single length] > 0;
}
static BOOL appHomeDeny(NSString *bid) {
    static NSSet *deny; static dispatch_once_t o;
    dispatch_once(&o, ^{ deny = [NSSet setWithArray:@[@"com.apple.sidecar",@"com.apple.webapp",@"com.apple.previewshell",
        @"com.apple.appleseed.feedbackassistant",@"com.apple.animoji.stickersapp",@"com.apple.news",@"com.apple.smsfilter",
        @"com.apsqa.metistest"]]; });
    return [deny containsObject:bid.lowercaseString];
}

// 扫目录枚举 App(桌面可见的):系统/越狱在 /Applications、/var/jb/Applications;用户在 /var/containers/Bundle/Application/*。
// 系统 App 只留「有图标 + SBAppTags 非隐藏 + 非 denylist」(滤掉一堆非桌面系统组件);用户 App 全留;已启用的
// 一律留(即使被过滤)。springboard 绝不列(注入会 respring 循环)。读 Info.plist,缓存 30s。
static NSArray *enumApps(void) {
    static NSArray *cache; static NSTimeInterval cacheT; static NSLock *lock; static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    [lock lock];
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (cache && now - cacheT < 30) { NSArray *c = cache; [lock unlock]; return c; }
    [lock unlock];
    NSMutableDictionary *apps = [NSMutableDictionary dictionary];
    NSSet *en = [NSSet setWithArray:cfgMembers(DH_KEY_BUNDLES)];   // 已启用的一律留(即使被过滤)
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scan)(NSString *) = ^(NSString *dir) {
        for (NSString *e in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            if (![[e.pathExtension lowercaseString] isEqualToString:@"app"]) continue;
            NSString *ap = [dir stringByAppendingPathComponent:e];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[ap stringByAppendingPathComponent:@"Info.plist"]];
            NSString *bid = info[@"CFBundleIdentifier"];
            if (![bid isKindOfClass:[NSString class]] || !bid.length || apps[bid]) continue;
            NSString *lbid = bid.lowercaseString;
            // 绝不列:springboard(注入 respring 循环)、manager 自己(不分析自己)。
            if ([lbid isEqualToString:@"com.apple.springboard"] || [lbid isEqualToString:@"com.iosdecrypthub.manager"]) continue;
            BOOL isSystem = [bid hasPrefix:@"com.apple."];
            BOOL enabled = [en containsObject:bid];
            // 已启用一律留;否则:denylist 套所有 App(含用户 App,如测试 App);系统 App 还要桌面可见(有图标+SBAppTags 非隐藏)。
            if (!enabled) {
                if (appHomeDeny(bid)) continue;
                if (isSystem && (appTagsNonHome(info[@"SBAppTags"]) || !appHasIcon(info))) continue;
            }
            NSString *name = info[@"CFBundleDisplayName"]; if (![name isKindOfClass:[NSString class]] || !name.length) name = info[@"CFBundleName"];
            NSString *exec = info[@"CFBundleExecutable"];
            apps[bid] = @{ @"bundle": bid, @"name": ([name isKindOfClass:[NSString class]] && name.length) ? name : bid,
                           @"exec": ([exec isKindOfClass:[NSString class]] ? exec : @""),
                           @"system": @([bid hasPrefix:@"com.apple."]) };
        }
    };
    scan(@"/Applications"); scan(@"/var/jb/Applications");
    for (NSString *c in [fm contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application" error:nil])
        scan([@"/var/containers/Bundle/Application" stringByAppendingPathComponent:c]);
    NSArray *out = [[apps allValues] sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL sa = [a[@"system"] boolValue], sb = [b[@"system"] boolValue];
        if (sa != sb) return sa ? NSOrderedDescending : NSOrderedAscending;   // 用户 App 在前,系统在后
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
    [lock lock]; cache = out; cacheT = now; [lock unlock];
    return out;
}
// App 引擎发现(共享内存):对每个 running App 做 task_for_pid + vm_read loader 的 g_dh_app_reg,得
// bundle→@[port,ver]。比端口扫描完整——后台被挂起的 App 内存也可读(端口扫描后台扫不到)。缓存 5s。
static NSDictionary *appInjectMap(void) {
    static NSDictionary *cache; static NSTimeInterval t; static NSLock *lk; static dispatch_once_t o;
    dispatch_once(&o, ^{ lk = [NSLock new]; });
    [lk lock]; NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (cache && now - t < 5) { NSDictionary *c = cache; [lk unlock]; return c; }
    [lk unlock];
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    for (NSDictionary *a in enumApps()) {
        NSString *exec = a[@"exec"];
        int pid = exec.length ? dh_proc_alive([exec UTF8String]) : 0;
        if (!pid) continue;
        uint32_t port = 0; char b[128] = {0}, v[16] = {0};
        if (dh_app_mem_read(pid, &port, b, sizeof b, v, sizeof v))
            m[a[@"bundle"]] = @[@(port), (v[0] ? @(v) : @"")];
    }
    [lk lock]; cache = m; t = now; [lk unlock];
    return m;
}
// App 列表 + 启用/运行/注入/端口/版本(供控制台 App tab)。
static NSDictionary *controlAppData(void) {
    NSSet *en = [NSSet setWithArray:cfgMembers(DH_KEY_BUNDLES)];
    NSDictionary *ports = appInjectMap();
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *a in enumApps()) {
        NSString *bundle = a[@"bundle"], *exec = a[@"exec"];
        int pid = exec.length ? dh_proc_alive([exec UTF8String]) : 0;
        NSArray *pe = ports[bundle];   // @[port, ver] 或 nil(未注入)
        BOOL injected = pe != nil;
        [out addObject:@{ @"bundle": bundle, @"name": a[@"name"], @"system": a[@"system"],
                          @"enabled": @([en containsObject:bundle]),
                          @"running": @(pid != 0), @"pid": @(pid),
                          @"injected": @(injected),
                          @"port": injected ? pe[0] : @0,
                          @"version": injected ? ([pe[1] length] ? pe[1] : @ENGINE_VER) : @"" }];
    }
    return @{ @"apps": out, @"engineVer": @ENGINE_VER };
}
// App 重启=结束进程(iOS App 非 launchd KeepAlive,kill 后由用户/系统重新打开时带上新注入)。按枚举到的
// CFBundleExecutable 找 pid kill;只对枚举到的 App(不接受任意名),bundle 必须在 App 列表里。返回是否 kill。
// 启动 App:daemon 直接调 SpringBoardServices 的 SBSLaunchApplicationWithIdentifier 权限不足(实测失败),
// 改用越狱工具 uiopen --bundleid(它有正确上下文,实测可拉起 App)。
static BOOL launchApp(NSString *bundle) {
    const char *tool = "/var/jb/usr/bin/uiopen";
    if (access(tool, X_OK) != 0) tool = "/usr/bin/uiopen";
    if (access(tool, X_OK) != 0) return NO;
    char *const argv[] = { (char *)tool, "--bundleid", (char *)[bundle UTF8String], NULL };
    pid_t pid = 0;
    if (posix_spawn(&pid, tool, NULL, NULL, argv, environ) != 0) return NO;
    int st = 0;
    return waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}
static BOOL killAppByBundle(NSString *bundle) {
    for (NSDictionary *a in enumApps()) {
        if (![a[@"bundle"] isEqual:bundle]) continue;
        NSString *exec = a[@"exec"];
        if (!exec.length) return NO;
        int pid = dh_proc_alive([exec UTF8String]);
        if (pid > 0) { kill(pid, SIGKILL); return YES; }
        return NO;
    }
    return NO;
}

// POST /api/control/<action>:enable(kind=daemon/app)、restart(daemon)、restart-app(App)。
static void handleControl(int fd, NSString *action, NSDictionary *q) {
    if ([action isEqualToString:@"enable"]) {
        BOOL on = [q[@"on"] intValue] != 0;
        if ([q[@"kind"] isEqualToString:@"app"]) {
            NSString *bundle = q[@"bundle"];
            NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
                @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"];
            if (!bundle.length || bundle.length > 128 || [[bundle stringByTrimmingCharactersInSet:ok] length]) {
                sendJSON(fd, @{@"ok": @NO, @"err": @"非法 bundle id"}); return; }
            BOOL w = cfgSetMember(DH_KEY_BUNDLES, bundle, on);
            sendJSON(fd, @{@"ok": @(w), @"enabled": @(cfgHasMember(DH_KEY_BUNDLES, bundle))}); return;
        }
        NSString *proc = q[@"proc"];
        if (!validProc(proc) || !isWhitelisted(proc)) { sendJSON(fd, @{@"ok": @NO, @"err": @"未知进程"}); return; }
        BOOL w = cfgSetMember(DH_KEY_EXECS, proc, on);
        sendJSON(fd, @{@"ok": @(w), @"enabled": @(cfgHasMember(DH_KEY_EXECS, proc))}); return;
    }
    if ([action isEqualToString:@"restart"]) {
        NSString *proc = q[@"proc"];
        if (!validProc(proc) || !isWhitelisted(proc)) { sendJSON(fd, @{@"ok": @NO, @"err": @"未知进程"}); return; }
        int rc = dh_restart_daemon([proc UTF8String]);
        sendJSON(fd, @{@"ok": @(rc == 0)}); return;
    }
    if ([action isEqualToString:@"restart-app"]) {
        NSString *bundle = q[@"bundle"];
        if (![bundle isKindOfClass:[NSString class]] || !bundle.length) { sendJSON(fd, @{@"ok": @NO, @"err": @"缺 bundle"}); return; }
        BOOL killed = killAppByBundle(bundle);
        if (killed) usleep(400000);   // 等旧进程退干净再启动,否则 SBSLaunch 会前台已有实例(不重启)
        BOOL launched = launchApp(bundle);
        sendJSON(fd, @{@"ok": @(launched), @"killed": @(killed), @"launched": @(launched),
                       @"note": launched ? @"已重启(引擎随之注入)" : (killed ? @"已结束但启动失败(daemon 拉起 App 权限不足?手动打开)" : @"未在运行,尝试启动失败") });
        return;
    }
    send404(fd);
}

// 控制台 SPA:静态壳(collector 同目录的 panel.html),前端 fetch /api/control/list 渲染。放独立文件而非
// 内嵌 ObjC 字符串——JS 里嵌套引号多,内嵌极易出错;与 webui.html 同法托管。
static NSString *indexHTML(void) {
    static NSString *cached; static dispatch_once_t once;
    dispatch_once(&once, ^{
        char exe[4096]; uint32_t sz = sizeof exe;
        if (_NSGetExecutablePath(exe, &sz) != 0) return;
        NSString *dir = [[NSString stringWithUTF8String:exe] stringByDeletingLastPathComponent];
        cached = [NSString stringWithContentsOfFile:[dir stringByAppendingPathComponent:@"panel.html"]
                                           encoding:NSUTF8StringEncoding error:nil];
    });
    return cached ?: @"<h3>panel.html 缺失(collector 同目录)</h3>";
}

// ———— 路由 ————
static NSDictionary *parseQuery(NSString *qs) {
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    if (!qs.length) return m;
    for (NSString *pair in [qs componentsSeparatedByString:@"&"]) {
        NSRange eq = [pair rangeOfString:@"="];
        NSString *k, *v;
        if (eq.location == NSNotFound) { k = pair; v = @""; }
        else { k = [pair substringToIndex:eq.location]; v = [pair substringFromIndex:eq.location + 1]; }
        k = [k stringByRemovingPercentEncoding] ?: k;
        v = [v stringByRemovingPercentEncoding] ?: v;
        if (k.length) m[k] = v;
    }
    return m;
}
// 照抄引擎 -[DHLogStore _categorySliceLocked:] 的 cat 码语义(IDA 1.27.3):
//   -2 → 加解密组 bucket{0,1,2,3};-3 → 系统组 bucket{4,5}(file+sys);0..8 → 精确 bucket
//   (bucket[8] 含越界值,与 append 归桶一致);其余(-1/all/>8)→ 全部。
static BOOL catMatch(NSInteger raw, NSInteger code) {
    NSInteger b = catBucket(raw);
    if (code == -2) return b >= 0 && b <= 3;
    if (code == -3) return b == 4 || b == 5;
    if (code >= 0 && code <= 8) return b == code;
    return YES;
}
// 照抄引擎 snapshotMatching: 的搜索面:algorithm/operation/detail + input(utf8)+input(hex)+output(hex),
// 全小写 containsString。
static BOOL searchMatch(NSDictionary *r, NSString *needle) {
    if (!needle.length) return YES;
    NSMutableString *hay = [NSMutableString stringWithFormat:@"%@\n%@\n%@\n",
        jstr(r[@"algo"]), jstr(r[@"op"]), jstr(r[@"detail"])];
    NSData *in = b64(r[@"in"]), *out = b64(r[@"out"]);
    if (in.length) { NSString *u = utf8Of(in); if (u) [hay appendString:u]; [hay appendString:@"\n"]; [hay appendString:hexOf(in)]; [hay appendString:@"\n"]; }
    if (out.length) { [hay appendString:hexOf(out)]; }
    return [[hay lowercaseString] rangeOfString:needle].location != NSNotFound;
}
static void handleLogs(int fd, NSString *proc, NSDictionary *q) {
    NSArray<NSDictionary *> *entries = loadEntries(proc);   // 升序,_seq 已赋
    NSString *catS = q[@"cat"]; NSString *needle = [q[@"q"] lowercaseString];
    BOOL hasCat = catS.length && ![catS isEqualToString:@"all"];
    NSInteger cat = hasCat ? [catS integerValue] : 0;
    long long since = q[@"since"] ? [q[@"since"] longLongValue] : -1;
    long long before = q[@"before"] ? [q[@"before"] longLongValue] : -1;
    long long minSize = q[@"minSize"] ? [q[@"minSize"] longLongValue] : 0;
    long long maxSize = q[@"maxSize"] ? [q[@"maxSize"] longLongValue] : 0;
    NSInteger limit = q[@"limit"] ? [q[@"limit"] integerValue] : 500;
    if (limit <= 0 || limit > 5000) limit = 500;
    NSMutableArray *out = [NSMutableArray array];
    // 新→旧:倒序遍历升序数组
    for (NSInteger i = (NSInteger)entries.count - 1; i >= 0 && (NSInteger)out.count < limit; i--) {
        NSDictionary *r = entries[i];
        long long seq = jint(r[@"_seq"]);
        if (since >= 0 && seq <= since) continue;
        if (before >= 0 && seq >= before) continue;
        if (hasCat && !catMatch((NSInteger)jint(r[@"cat"]), cat)) continue;
        if (minSize > 0 && jint(r[@"inLen"]) < minSize) continue;
        if (maxSize > 0 && jint(r[@"inLen"]) > maxSize) continue;
        if (needle.length && !searchMatch(r, needle)) continue;
        [out addObject:listItem(r)];
    }
    sendJSON(fd, out);
}
static void handleConn(int fd) {
    // 读请求头(到 \r\n\r\n 或上限)
    char buf[8192]; size_t got = 0;
    while (got < sizeof buf - 1) {
        ssize_t r = read(fd, buf + got, sizeof buf - 1 - got);
        if (r <= 0) break; got += (size_t)r;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    buf[got] = 0;
    @autoreleasepool {
        // 首行:METHOD SP PATH SP HTTP/x
        char *sp1 = strchr(buf, ' '); if (!sp1) { send404(fd); return; }
        char *sp2 = strchr(sp1 + 1, ' '); if (!sp2) { send404(fd); return; }
        BOOL isGet = (strncmp(buf, "GET ", 4) == 0);
        BOOL isPost = (strncmp(buf, "POST ", 5) == 0);
        NSString *rawPath = [[NSString alloc] initWithBytes:sp1 + 1 length:(sp2 - sp1 - 1) encoding:NSUTF8StringEncoding];
        if (!rawPath) { send404(fd); return; }
        NSString *path = rawPath, *query = @"";
        NSRange qm = [rawPath rangeOfString:@"?"];
        if (qm.location != NSNotFound) { path = [rawPath substringToIndex:qm.location]; query = [rawPath substringFromIndex:qm.location + 1]; }
        path = [path stringByRemovingPercentEncoding] ?: path;
        // 控制台 API:list(GET)+ enable/restart(POST)
        if ([path isEqualToString:@"/api/control/list"]) {
            if (!isGet) { send404(fd); return; }
            NSDictionary *q = parseQuery(query);
            if ([q[@"kind"] isEqualToString:@"app"]) { sendJSON(fd, controlAppData()); return; }
            sendJSON(fd, controlDaemonList()); return;
        }
        if ([path hasPrefix:@"/api/control/"]) {
            if (!isPost) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"控制操作用 POST" dataUsingEncoding:NSUTF8StringEncoding]); return; }
            handleControl(fd, [path substringFromIndex:13], parseQuery(query)); return;   // "/api/control/"=13
        }
        if (!isGet) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"仅支持 GET" dataUsingEncoding:NSUTF8StringEncoding]); return; }

        if ([path isEqualToString:@"/"] || [path isEqualToString:@"/index.html"]) { sendHTML(fd, indexHTML()); return; }
        if (![path hasPrefix:@"/d/"]) { send404(fd); return; }

        NSString *rest = [path substringFromIndex:3];   // proc[/...]
        NSRange slash = [rest rangeOfString:@"/"];
        NSString *proc = slash.location == NSNotFound ? rest : [rest substringToIndex:slash.location];
        NSString *sub = slash.location == NSNotFound ? @"" : [rest substringFromIndex:slash.location];   // 含前导 /
        if (!validProc(proc)) { httpSend(fd, 400, "Bad Request", "text/plain", [@"非法进程名" dataUsingEncoding:NSUTF8StringEncoding]); return; }

        if ([sub isEqualToString:@""] || [sub isEqualToString:@"/"]) { sendHTML(fd, webuiForProc(proc)); return; }
        if ([sub isEqualToString:@"/api/stats"]) { sendJSON(fd, statsFor(proc, loadEntries(proc))); return; }
        if ([sub isEqualToString:@"/api/logs/download"] || [sub isEqualToString:@"/download"]) {
            NSArray *entries = loadEntries(proc);
            NSMutableString *t = [NSMutableString string];
            for (NSDictionary *r in entries) [t appendFormat:@"#%lld [%@] %@ %@ %@\n",
                jint(r[@"_seq"]), catName((NSInteger)jint(r[@"cat"])), fmtTs(jint(r[@"tsMs"])),
                jstr(r[@"algo"]), jstr(r[@"op"])];
            sendText(fd, t); return;
        }
        if ([sub isEqualToString:@"/api/logs"]) { handleLogs(fd, proc, parseQuery(query)); return; }
        if ([sub hasPrefix:@"/api/logs/"]) {
            long long seq = [[sub substringFromIndex:10] longLongValue];
            NSArray *entries = loadEntries(proc);
            if (seq >= 1 && seq <= (long long)entries.count) { sendJSON(fd, detailItem(entries[seq - 1])); return; }
            send404(fd); return;
        }
        if ([sub hasPrefix:@"/api/"]) { sendJSON(fd, @{}); return; }   // 未实现端点:空对象,避免 WebUI 硬报错
        send404(fd);
    }
}
static void *connThread(void *arg) {
    int fd = (int)(long)arg;
    handleConn(fd);
    close(fd);
    return NULL;
}
static void *aggThread(void *arg) {
    (void)arg;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { aggLog(@"[agg] socket 失败"); return NULL; }
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(AGG_PORT); sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) { aggLog([NSString stringWithFormat:@"[agg] bind :%d 失败 errno=%d", AGG_PORT, errno]); close(ls); return NULL; }
    if (listen(ls, 32) != 0) { aggLog(@"[agg] listen 失败"); close(ls); return NULL; }
    aggLog([NSString stringWithFormat:@"[agg] 聚合历史查询 HTTP 于 *:%d(索引页 / + per-daemon /d/<proc>/)", AGG_PORT]);
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        pthread_t th; if (pthread_create(&th, NULL, connThread, (void *)(long)c) == 0) pthread_detach(th);
        else close(c);
    }
    close(ls);
    return NULL;
}

void dh_agg_http_start(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, aggThread, NULL) == 0) pthread_detach(th);
}
