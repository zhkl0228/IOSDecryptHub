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
#import <dlfcn.h>         // dlopen/dlsym(SBSUndimScreen 亮屏)
#import <notify.h>        // notify_post(通知 SpringBoard 里的 DHUnlock 解锁)
extern char **environ;

extern void dh_log(const char *s);                       // collector.c:带时间戳落 collector.log
extern int  dh_bridge_online(const char *proc, int *lan_port);  // collector.c:引擎是否就绪(可连活引擎)
extern int  dh_proc_alive(const char *proc);                    // collector.c:进程是否存活(sysctl),0=已退出
extern int  dh_restart_daemon(const char *proc);                // collector.c:kickstart 重启 daemon,0=成功
extern const char *dh_daemons_json(void);                       // collector.c:白名单 [{proc,disp,domain}]
extern int  dh_app_mem_read(int pid, uint32_t *port, char *bundle, size_t bcap, char *ver, size_t vcap);  // App vm_read 发现
extern int  dh_task_suspend_count(int pid);                     // collector.c:task suspend_count,>0=后台挂起 0=前台 <0=拿不到

// 注入门控 config(companion dh_enabled / collector mb_is_enabled 都读这份;与它们同路径)。
#define DH_CFG_PATH @"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"
#define DH_KEY_EXECS   @"enabledExecutables"   // 系统 daemon 注入名单(按 exec 名)
#define DH_KEY_BUNDLES @"enabledBundles"        // App 注入名单(按 bundle id)
#define DH_KEY_FGKEEP  @"foregroundKeep"        // 「保持前台」目标 bundle id(单值;空/缺=关闭);独立于注入名单
// SpringBoard 里的 DHUnlock 读 foregroundKeep:非空即在锁屏时自动解锁(两者绑定,无单独开关)。
#define DH_UNLOCK_NOTIFY  "com.iosdecrypthub.unlock"   // 手动解锁 darwin 通知(DHUnlock 监听)
#define DH_FRIDA_DIR   @"/var/jb/usr/lib/IOSDecryptHub/frida"   // Frida JS 脚本目录(<bundle>.js)
#define DH_FRIDA_REQ   @"/var/jb/tmp/dh-frida-req"              // 写 bundle id → dh_frida daemon spawn+注入
static BOOL validProc(NSString *p);   // fwd(定义在索引页附近)
static NSString *fridaJsPath(NSString *bundle);   // fwd(Frida JS 路径,定义在 handleControl 前)
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
// 单值(字符串)config 读写:用于 foregroundKeep(单个 bundle)。读改写保留其它 key(同 cfgSetMember 顾虑)。
static NSString *cfgGetScalar(NSString *key) {
    id v = [NSDictionary dictionaryWithContentsOfFile:DH_CFG_PATH][key];
    return [v isKindOfClass:[NSString class]] ? v : @"";
}
static BOOL cfgSetScalar(NSString *key, NSString *val) {
    NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:DH_CFG_PATH] mutableCopy] ?: [NSMutableDictionary dictionary];
    if (val.length) d[key] = val; else [d removeObjectForKey:key];   // 空=清除(关闭保持前台)
    return [d writeToFile:DH_CFG_PATH atomically:YES];
}

// 亮屏:惰性 dlopen SpringBoardServices 的 SBSUndimScreen(实测 collector root 可调)。无密码设备上 uiopen
// 一个 App 会把屏点亮并越过锁屏进该 App(实测 suspend_count 1→0);此函数单独用于「解锁/亮屏」按钮。
static void dh_undim_screen(void) {
    static void (*undim)(void); static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW);
        if (h) undim = (void (*)(void))dlsym(h, "SBSUndimScreen");
    });
    if (undim) undim();
}

// 屏幕亮度(BackBoardServices,惰性 dlopen):>0=亮屏,0=息屏,<0=拿不到。用于 web 显示屏幕开关。
static float dh_screen_brightness(void) {
    static float (*bget)(void); static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices", RTLD_NOW);
        if (h) bget = (float (*)(void))dlsym(h, "BKSDisplayBrightnessGetCurrent");
    });
    return bget ? bget() : -1.0f;
}
// 电量:IOKit IOPowerSources(惰性 dlopen,root daemon 直接调,不依赖 DHUnlock)。返回 0-100 百分比,
// -1=拿不到。*charging 回填是否在充电。字段名(Current/Max Capacity、Is Charging)设备探针实测确认存在。
static int dh_battery_level(int *charging) {
    static CFTypeRef (*Info)(void); static CFArrayRef (*List)(CFTypeRef);
    static CFDictionaryRef (*Desc)(CFTypeRef, CFTypeRef); static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
        if (h) {
            Info = (CFTypeRef (*)(void))dlsym(h, "IOPSCopyPowerSourcesInfo");
            List = (CFArrayRef (*)(CFTypeRef))dlsym(h, "IOPSCopyPowerSourcesList");
            Desc = (CFDictionaryRef (*)(CFTypeRef, CFTypeRef))dlsym(h, "IOPSGetPowerSourceDescription");
        }
    });
    if (charging) *charging = 0;
    if (!Info || !List || !Desc) return -1;
    CFTypeRef blob = Info();
    if (!blob) return -1;
    int pct = -1;
    CFArrayRef list = List(blob);
    if (list && CFArrayGetCount(list) > 0) {
        CFDictionaryRef d = Desc(blob, CFArrayGetValueAtIndex(list, 0));  // Get:不 release
        if (d) {
            int cur = -1, max = -1;
            CFNumberRef cn = CFDictionaryGetValue(d, CFSTR("Current Capacity"));
            CFNumberRef mn = CFDictionaryGetValue(d, CFSTR("Max Capacity"));
            if (cn) CFNumberGetValue(cn, kCFNumberIntType, &cur);
            if (mn) CFNumberGetValue(mn, kCFNumberIntType, &max);
            if (max > 0 && cur >= 0) pct = cur * 100 / max;
            CFBooleanRef ch = CFDictionaryGetValue(d, CFSTR("Is Charging"));
            if (charging && ch) *charging = CFBooleanGetValue(ch) ? 1 : 0;
        }
    }
    if (list) CFRelease(list);   // Copy:要 release
    CFRelease(blob);             // Copy:要 release
    return pct;
}
// 锁屏状态:读 DHUnlock 写的 /var/jb/tmp/dh_lockstate("1"锁/"0"解);无文件(没装 DHUnlock)返回 -1=未知。
// collector 读不到 SpringBoard 的 SBLockScreenManager,精确锁屏态由 SpringBoard 里的 DHUnlock 落文件转达。
static int dh_screen_locked(void) {
    NSString *s = [NSString stringWithContentsOfFile:@"/var/jb/tmp/dh_lockstate" encoding:NSUTF8StringEncoding error:nil];
    if (!s.length) return -1;
    return [s hasPrefix:@"1"] ? 1 : 0;
}
// 是否装了 Frida(dh_frida daemon 二进制需 devkit 构建才有 + frida-server 已装)。web 据此显示/隐藏 Frida 功能。
static BOOL dh_frida_available(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    return [fm fileExistsAtPath:@"/var/jb/usr/lib/IOSDecryptHub/IOSDecryptHubFrida"]
        && [fm fileExistsAtPath:@"/var/jb/usr/sbin/frida-server"];
}
// frida 真就绪:二进制在 + frida-server 27042 可连(重启后 frida-server 晚起,二进制在≠就绪)。
// 保活自启的 frida spawn 据此判断——没就绪就先别启动、等 frida 起来,避免拿无 frida 方式把 App 占位。
static BOOL dh_frida_ready(void) {
    if (!dh_frida_available()) return NO;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return NO;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(27042); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv = {1, 0}; setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    return r == 0;
}

// daemon 三态:live=引擎就绪可连活引擎 / idle=进程在但没注入引擎(未启用) / dead=进程已退出仅历史。
// 返回并回填 lan_port(仅 live 有意义)。
static NSString *procState(NSString *proc, int *lanPort) {
    if (dh_bridge_online([proc UTF8String], lanPort)) return @"live";
    return dh_proc_alive([proc UTF8String]) ? @"idle" : @"dead";
}

#define AGG_PORT 8089
#define ENGINE_VER "1.27.5"   // 重建 stats 显示用(当前 vendor 引擎版本;仅展示)

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
    NSString *fgKeep = cfgGetScalar(DH_KEY_FGKEEP);   // 当前「保持前台」目标(单值)
    // 前台判定优先用【真 frontmost】:SpringBoard 里的 DHUnlock 把 _accessibilityFrontMostApplication 写
    // /var/jb/tmp/dh_frontmost(唯一、切换即时准确)。文件 nil=没装 DHUnlock → 退回 suspend_count 猜(对 VPN 类
    // 后台常驻 App 长期 suspend=0、切后台宽限期都会误判,且可能同时报多个)。文件为空="桌面/无前台"。
    NSString *fmRaw = [NSString stringWithContentsOfFile:@"/var/jb/tmp/dh_frontmost" encoding:NSUTF8StringEncoding error:nil];
    BOOL haveFm = (fmRaw != nil);
    NSString *fmBundle = [(fmRaw ?: @"") stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSMutableArray *out = [NSMutableArray array];
    NSMutableArray *fgNames = [NSMutableArray array]; // fallback(无 DHUnlock):suspend==0 的 App 名
    NSString *fmName = @"";                            // 有 DHUnlock:真 frontmost App 名
    for (NSDictionary *a in enumApps()) {
        NSString *bundle = a[@"bundle"], *exec = a[@"exec"];
        int pid = exec.length ? dh_proc_alive([exec UTF8String]) : 0;
        int sc = pid ? dh_task_suspend_count(pid) : -1;   // 仍上报供参考;前台判定优先真 frontmost
        BOOL foreground = haveFm ? (pid != 0 && fmBundle.length && [bundle isEqualToString:fmBundle])
                                 : (pid != 0 && sc == 0);
        if (foreground) { [fgNames addObject:a[@"name"]]; fmName = a[@"name"]; }
        NSArray *pe = ports[bundle];   // @[port, ver] 或 nil(未注入)
        BOOL injected = pe != nil;
        [out addObject:@{ @"bundle": bundle, @"name": a[@"name"], @"system": a[@"system"],
                          @"enabled": @([en containsObject:bundle]),
                          @"running": @(pid != 0), @"pid": @(pid),
                          @"suspend": @(sc), @"foreground": @(foreground),
                          @"keepFg": @([bundle isEqualToString:fgKeep]),
                          @"fridaJS": @([[NSFileManager defaultManager] fileExistsAtPath:fridaJsPath(bundle)]),
                          @"injected": @(injected),
                          @"port": injected ? pe[0] : @0,
                          @"version": injected ? ([pe[1] length] ? pe[1] : @ENGINE_VER) : @"" }];
    }
    // 有 DHUnlock:显示真 frontmost 名(列表里没匹配到就退回 bundle id);无 DHUnlock:suspend==0 的名(可能多个)
    NSString *fgShow = haveFm ? (fmName.length ? fmName : fmBundle)
                              : [fgNames componentsJoinedByString:@" / "];
    float bright = dh_screen_brightness();
    int charging = 0;
    int batt = dh_battery_level(&charging);
    return @{ @"apps": out, @"engineVer": @ENGINE_VER,
              @"fgKeep": fgKeep ?: @"",
              @"foreground": fgShow,
              @"screenOn": @(bright > 0.0f),        // 亮屏/息屏(collector 直接读亮度)
              @"locked": @(dh_screen_locked()),     // 1=锁屏 0=已解锁 -1=未知(没装 DHUnlock)
              @"battery": @(batt),                  // 电量 0-100,-1=拿不到
              @"charging": @(charging != 0),        // 是否在充电
              @"fridaAvail": @(dh_frida_available()) };  // 装了 Frida 才显示 web 上的 Frida 功能
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

// bundle id 合法性(防路径穿越/命令注入):只允许 [A-Za-z0-9.-_],长度 ≤128。
static BOOL validBundle(NSString *b) {
    if (!b.length || b.length > 128) return NO;
    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"];
    return [[b stringByTrimmingCharactersInSet:ok] length] == 0;
}
static NSString *fridaJsPath(NSString *bundle) {
    return [DH_FRIDA_DIR stringByAppendingPathComponent:[bundle stringByAppendingString:@".js"]];
}
// 智能启动(冷启动场景用):配了 Frida JS 且 frida 可用 → 写请求让 dh_frida frida spawn+注入;否则 uiopen。
// 保持前台的退出自启、restart-app 都用它,保证配了 JS 的 App「启动即带 frida」。仅用于进程不在时(冷启动);
// App 在运行时(后台拉回)不能用——frida spawn 是冷启动会冲突,那种情况用 launchApp(uiopen)激活。
// 返回 YES=已启动 或 已发起 frida 注入请求;NO=配了 JS 但 frida 未就绪(没启动,调用方应稍后重试)。
static BOOL launchAppSmart(NSString *bundle) {
    BOOL hasJs = [[NSFileManager defaultManager] fileExistsAtPath:fridaJsPath(bundle)];
    if (hasJs) {
        if (!dh_frida_ready()) return NO;   // 配了 JS 但 frida 没就绪 → 不用无 frida 方式占位启动,等下轮
        return [bundle writeToFile:DH_FRIDA_REQ atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    return launchApp(bundle);   // 没配 JS → 普通 uiopen
}
// 读 HTTP 请求 body:handleConn 已把 header(可能连带部分 body)读进 buf,body 从 \r\n\r\n 后开始,按
// Content-Length 续读到齐。用于保存 Frida JS 脚本(POST body 是脚本内容)。
static NSData *readReqBody(int fd, const char *buf, size_t got) {
    const char *bs = strstr(buf, "\r\n\r\n");
    if (!bs) return [NSData data];
    bs += 4;
    NSMutableData *d = [NSMutableData dataWithBytes:bs length:got - (size_t)(bs - buf)];
    const char *cl = strcasestr(buf, "\r\ncontent-length:");
    long clen = cl ? atol(cl + 17) : -1;
    if (clen < 0) return d;
    char tmp[4096];
    while ((long)d.length < clen) {
        ssize_t r = read(fd, tmp, sizeof tmp);
        if (r <= 0) break;
        [d appendBytes:tmp length:(NSUInteger)r];
    }
    if ((long)d.length > clen) [d setLength:(NSUInteger)clen];
    return d;
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
        if (killed) usleep(400000);   // 等旧进程退干净再冷启动
        // 智能:配了 Frida JS 且 frida 可用 → 写请求让 dh_frida spawn+注入(冷启动即注入);否则 uiopen 普通启动。
        BOOL hasJs = [[NSFileManager defaultManager] fileExistsAtPath:fridaJsPath(bundle)];
        if (hasJs && dh_frida_ready()) {
            BOOL w = [bundle writeToFile:DH_FRIDA_REQ atomically:YES encoding:NSUTF8StringEncoding error:nil];
            sendJSON(fd, @{@"ok": @(w), @"killed": @(killed), @"frida": @YES,
                           @"note": w ? @"已请求 frida 启动并注入 JS(看脚本日志)" : @"写 frida 请求失败"});
            return;
        }
        BOOL launched = launchApp(bundle);
        sendJSON(fd, @{@"ok": @(launched), @"killed": @(killed), @"launched": @(launched), @"frida": @NO,
                       @"note": launched ? (hasJs ? @"已重启(uiopen;frida 未就绪,未注入)" : @"已重启(uiopen 普通启动)") : (killed ? @"已结束但启动失败(权限?手动打开)" : @"未在运行,尝试启动失败") });
        return;
    }
    // 保持前台:单值目标(bundle 空=关闭)。独立于注入名单;监控线程按 suspend_count 判定 + uiopen 拉前台。
    if ([action isEqualToString:@"keep-fg"]) {
        NSString *bundle = [q[@"bundle"] isKindOfClass:[NSString class]] ? q[@"bundle"] : @"";
        if (bundle.length) {
            NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
                @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"];
            if (bundle.length > 128 || [[bundle stringByTrimmingCharactersInSet:ok] length]) {
                sendJSON(fd, @{@"ok": @NO, @"err": @"非法 bundle id"}); return; }
        }
        BOOL w = cfgSetScalar(DH_KEY_FGKEEP, bundle);   // 空=清除(关闭保持前台)
        if (w && bundle.length) { dh_undim_screen(); launchApp(bundle); }   // 设了目标即立刻亮屏拉前台一次
        sendJSON(fd, @{@"ok": @(w), @"fgKeep": cfgGetScalar(DH_KEY_FGKEEP)}); return;
    }
    // 解锁:亮屏(SBSUndimScreen)+ 发 darwin 通知让 SpringBoard 里的 DHUnlock 调 unlockUIFromSource:0。
    // 真正 dismiss 锁屏必须在 SpringBoard 进程内(实测外部只能亮屏);DHUnlock 没装则只亮屏。
    if ([action isEqualToString:@"unlock"]) {
        dh_undim_screen();
        notify_post(DH_UNLOCK_NOTIFY);
        sendJSON(fd, @{@"ok": @YES, @"undim": @YES, @"notified": @YES}); return;
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
        // Frida:保存 JS(POST body=脚本)/ 读 JS(GET)/ 启动注入(POST 写请求文件,dh_frida daemon 执行)
        if ([path isEqualToString:@"/api/frida/save"]) {
            if (!isPost) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"用 POST" dataUsingEncoding:NSUTF8StringEncoding]); return; }
            NSString *bundle = parseQuery(query)[@"bundle"];
            if (!validBundle(bundle)) { sendJSON(fd, @{@"ok": @NO, @"err": @"非法 bundle"}); return; }
            NSData *js = readReqBody(fd, buf, got);
            [[NSFileManager defaultManager] createDirectoryAtPath:DH_FRIDA_DIR withIntermediateDirectories:YES attributes:nil error:nil];
            BOOL w = [js writeToFile:fridaJsPath(bundle) atomically:YES];
            sendJSON(fd, @{@"ok": @(w), @"bytes": @(js.length)}); return;
        }
        if ([path isEqualToString:@"/api/frida/get"]) {
            NSString *bundle = parseQuery(query)[@"bundle"];
            if (!validBundle(bundle)) { send404(fd); return; }
            NSString *js = [NSString stringWithContentsOfFile:fridaJsPath(bundle) encoding:NSUTF8StringEncoding error:nil];
            sendText(fd, js ?: @""); return;
        }
        if ([path isEqualToString:@"/api/frida/launch"]) {
            if (!isPost) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"用 POST" dataUsingEncoding:NSUTF8StringEncoding]); return; }
            NSString *bundle = parseQuery(query)[@"bundle"];
            if (!validBundle(bundle)) { sendJSON(fd, @{@"ok": @NO, @"err": @"非法 bundle"}); return; }
            if (![[NSFileManager defaultManager] fileExistsAtPath:fridaJsPath(bundle)]) { sendJSON(fd, @{@"ok": @NO, @"err": @"该 App 未设置 Frida JS"}); return; }
            BOOL w = [bundle writeToFile:DH_FRIDA_REQ atomically:YES encoding:NSUTF8StringEncoding error:nil];
            sendJSON(fd, @{@"ok": @(w), @"note": @"已请求 dh_frida spawn+注入(需 frida-server + dh_frida daemon)"}); return;
        }
        // Frida 脚本消息(console.log/send):读 dh_frida 落的 /var/log/dh-frida.jsonl 尾部,可按 bundle 过滤。
        if ([path isEqualToString:@"/api/frida/log"]) {
            NSDictionary *q = parseQuery(query);
            NSString *fb = q[@"bundle"];
            NSInteger lim = [q[@"limit"] length] ? [q[@"limit"] integerValue] : 200;
            if (lim <= 0 || lim > 2000) lim = 200;
            NSMutableArray *out = [NSMutableArray array];
            NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:@"/var/log/dh-frida.jsonl"];
            if (fh) {
                unsigned long long sz = [fh seekToEndOfFile], cap = 512 * 1024;
                [fh seekToFileOffset:(sz > cap ? sz - cap : 0)];
                NSData *d = [fh readDataToEndOfFile]; [fh closeFile];
                NSString *raw = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"";
                for (NSString *ln in [raw componentsSeparatedByString:@"\n"]) {
                    if (!ln.length) continue;
                    NSDictionary *o = [NSJSONSerialization JSONObjectWithData:[ln dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
                    if (![o isKindOfClass:[NSDictionary class]]) continue;   // 尾部截断的首行/坏行跳过
                    if (fb.length && ![o[@"bundle"] isEqualToString:fb]) continue;
                    [out addObject:o];
                }
            }
            if ((NSInteger)out.count > lim) [out removeObjectsInRange:NSMakeRange(0, out.count - lim)];
            sendJSON(fd, @{@"items": out}); return;
        }
        // 清空 Frida 脚本日志(删整个 jsonl;dh_frida 下次 append 会重建)
        if ([path isEqualToString:@"/api/frida/clearlog"]) {
            if (!isPost) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"用 POST" dataUsingEncoding:NSUTF8StringEncoding]); return; }
            [[NSFileManager defaultManager] removeItemAtPath:@"/var/log/dh-frida.jsonl" error:nil];
            sendJSON(fd, @{@"ok": @YES}); return;
        }
        // 清空脚本:删该 App 的 frida/<bundle>.js(之后 fridaJS=false,启动/重启不再注入)
        if ([path isEqualToString:@"/api/frida/delete"]) {
            if (!isPost) { httpSend(fd, 405, "Method Not Allowed", "text/plain", [@"用 POST" dataUsingEncoding:NSUTF8StringEncoding]); return; }
            NSString *bundle = parseQuery(query)[@"bundle"];
            if (!validBundle(bundle)) { sendJSON(fd, @{@"ok": @NO, @"err": @"非法 bundle"}); return; }
            [[NSFileManager defaultManager] removeItemAtPath:fridaJsPath(bundle) error:nil];
            sendJSON(fd, @{@"ok": @YES}); return;
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
static int g_agg_ls = -1;   // agg HTTP 监听 socket(dh_agg_http_start 同步 bind,accept 在下面线程)
static void *aggAcceptThread(void *arg) {
    (void)arg;
    for (;;) {
        int c = accept(g_agg_ls, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        pthread_t th; if (pthread_create(&th, NULL, connThread, (void *)(long)c) == 0) pthread_detach(th);
        else close(c);
    }
    close(g_agg_ls);
    return NULL;
}

// 「保持前台」监控:每 ~12s 检查 foregroundKeep 目标——进程退了就拉起(退出自启),被系统挂起(后台)
// 持续 ≥60s 就 uiopen 拉回前台。全用 collector 现成能力(dh_proc_alive / dh_task_suspend_count /
// launchApp / dh_undim_screen),零注入面。目标由 web 单选,独立于是否注入引擎。
static NSString *fgExecForBundle(NSString *bundle) {
    for (NSDictionary *a in enumApps()) if ([a[@"bundle"] isEqualToString:bundle]) return a[@"exec"];
    return @"";
}
static void *fgKeepThread(void *arg) {
    (void)arg;
    NSString *lastBundle = @"";
    NSTimeInterval bgSince = 0;            // 首次发现目标被挂起的时刻;0=当前在前台/无目标
    const NSTimeInterval kBgLimit = 60;    // 被挂起(后台)超过这么久就拉回前台
    for (;;) {
        @autoreleasepool {
            NSString *bundle = cfgGetScalar(DH_KEY_FGKEEP);
            if (![bundle isEqualToString:lastBundle]) { lastBundle = bundle; bgSince = 0; }   // 目标切换,重置计时
            if (bundle.length) {
                NSString *exec = fgExecForBundle(bundle);
                int pid = exec.length ? dh_proc_alive([exec UTF8String]) : 0;
                NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
                if (pid == 0) {
                    dh_undim_screen();
                    if (launchAppSmart(bundle))
                        aggLog([NSString stringWithFormat:@"[fg-keep] %@ 已退出,拉起", bundle]);
                    else   // 配了 JS 但 frida 未就绪:不用无 frida 方式占位启动,下轮(pid 仍 0)自动重试,frida 就绪后 spawn 注入
                        aggLog([NSString stringWithFormat:@"[fg-keep] %@ 已退出,frida 未就绪,等待重试", bundle]);
                    bgSince = 0;
                } else {
                    int sc = dh_task_suspend_count(pid);
                    if (sc == 0) { bgSince = 0; }              // 前台/活跃
                    else if (sc > 0) {                          // 被系统挂起=在后台
                        if (bgSince == 0) bgSince = now;
                        else if (now - bgSince >= kBgLimit) {
                            aggLog([NSString stringWithFormat:@"[fg-keep] %@ 后台 %.0fs,拉回前台", bundle, now - bgSince]);
                            dh_undim_screen(); launchApp(bundle); bgSince = 0;
                        }
                    }
                    // sc<0:task_for_pid 失败(进程正退/受保护),不动,下轮 dh_proc_alive 反映
                }
            }
        }
        sleep(12);
    }
    return NULL;
}

void dh_agg_http_start(void) {
    // 同步 bind+listen:返回时 :8089 已可连(不等内存桥等慢活)。collector main 里最先调它,
    // 保证重启后面板端口第一时间就绪——之前放线程里被内存桥(扫严格 daemon+task_for_pid)抢占,晚 ~9s+。
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { aggLog(@"[agg] socket 失败"); return; }
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(AGG_PORT); sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0) { aggLog([NSString stringWithFormat:@"[agg] bind :%d 失败 errno=%d", AGG_PORT, errno]); close(ls); return; }
    if (listen(ls, 32) != 0) { aggLog(@"[agg] listen 失败"); close(ls); return; }
    g_agg_ls = ls;
    aggLog([NSString stringWithFormat:@"[agg] 聚合历史查询 HTTP 于 *:%d 已就绪(索引页 / + per-daemon /d/<proc>/)", AGG_PORT]);
    pthread_t th; if (pthread_create(&th, NULL, aggAcceptThread, NULL) == 0) pthread_detach(th);
    pthread_t fg; if (pthread_create(&fg, NULL, fgKeepThread, NULL) == 0) pthread_detach(fg);   // 保持前台监控
}
