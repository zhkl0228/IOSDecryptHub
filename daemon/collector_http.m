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

extern void dh_log(const char *s);                       // collector.c:带时间戳落 collector.log
extern int  dh_bridge_online(const char *proc, int *lan_port);  // collector.c:引擎是否就绪(可连活引擎)
extern int  dh_proc_alive(const char *proc);                    // collector.c:进程是否存活(sysctl),0=已退出

// daemon 三态:live=引擎就绪可连活引擎 / idle=进程在但没注入引擎(未启用) / dead=进程已退出仅历史。
// 返回并回填 lan_port(仅 live 有意义)。
static NSString *procState(NSString *proc, int *lanPort) {
    if (dh_bridge_online([proc UTF8String], lanPort)) return @"live";
    return dh_proc_alive([proc UTF8String]) ? @"idle" : @"dead";
}

#define AGG_PORT 8089
#define ENGINE_VER "1.27.3"   // 重建 stats 显示用(当前 vendor 引擎版本;仅展示)

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
static NSString *indexHTML(void) {
    NSMutableString *h = [NSMutableString string];
    [h appendString:@"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>IOSDecryptHub 聚合</title><style>"
        "body{font:15px/1.5 -apple-system,Inter,sans-serif;background:#0b0d12;color:#e6e8ee;margin:0;padding:24px}"
        "h1{font-size:20px;margin:0 0 16px}table{border-collapse:collapse;width:100%;max-width:900px}"
        "th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #232838}th{color:#8b93a7;font-weight:600}"
        "a{color:#7fd6df;text-decoration:none}a:hover{text-decoration:underline}"
        ".on{color:#5fd08a}.idle{color:#d8b24a}.off{color:#8b93a7}.n{color:#c8cede;font-variant-numeric:tabular-nums}"
        "</style><h1>IOSDecryptHub · daemon 捕获聚合</h1>"];
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/log" error:nil];
    NSMutableArray *procs = [NSMutableArray array];
    for (NSString *f in files)
        if ([f hasPrefix:@"dh-"] && [f hasSuffix:@".cap.jsonl"])
            [procs addObject:[f substringWithRange:NSMakeRange(3, f.length - 3 - 10)]];   // 去 "dh-" 与 ".cap.jsonl"
    [procs sortUsingSelector:@selector(compare:)];
    if (!procs.count) { [h appendString:@"<p class=off>暂无捕获记录(还没有 daemon 产生 cap.jsonl)。</p>"]; return h; }
    [h appendString:@"<table><tr><th>进程</th><th>状态</th><th>捕获数</th><th>最近</th><th></th></tr>"];
    for (NSString *proc in procs) {
        if (!validProc(proc)) continue;
        NSArray *entries = loadEntries(proc);
        int lanPort = 0; NSString *state = procState(proc, &lanPort);   // live / idle / dead
        BOOL live = [state isEqualToString:@"live"];
        NSString *cls = live ? @"on" : ([state isEqualToString:@"idle"] ? @"idle" : @"off");
        NSString *label = live ? @"引擎就绪" : ([state isEqualToString:@"idle"] ? @"进程在·未注入" : @"已退出");
        long long lastMs = entries.count ? jint([entries lastObject][@"tsMs"]) : 0;
        [h appendFormat:@"<tr><td><a href='/d/%@/'>%@</a></td>"
            "<td class='%@'>%@</td><td class=n>%lu</td><td class=n>%@</td><td>%@</td></tr>",
            proc, proc, cls, label,
            (unsigned long)entries.count,
            lastMs ? fmtTs(lastMs) : @"—",
            live ? [NSString stringWithFormat:@"<a class=live href='#' data-port='%d'>连活引擎</a>", lanPort] : @""];
    }
    // 活引擎在各自 LAN 端口,链接的 host 服务端不知道 → 用浏览器 location.hostname 补全。
    [h appendString:@"</table><script>document.querySelectorAll('a.live').forEach(function(a){"
        "a.href='http://'+location.hostname+':'+a.dataset.port+'/';a.textContent='连活引擎 :'+a.dataset.port;});</script>"];
    return h;
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
        NSString *rawPath = [[NSString alloc] initWithBytes:sp1 + 1 length:(sp2 - sp1 - 1) encoding:NSUTF8StringEncoding];
        if (!rawPath) { send404(fd); return; }
        NSString *path = rawPath, *query = @"";
        NSRange qm = [rawPath rangeOfString:@"?"];
        if (qm.location != NSNotFound) { path = [rawPath substringToIndex:qm.location]; query = [rawPath substringFromIndex:qm.location + 1]; }
        path = [path stringByRemovingPercentEncoding] ?: path;
        if (!isGet) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"仅支持 GET(历史为只读)" dataUsingEncoding:NSUTF8StringEncoding]); return; }

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
