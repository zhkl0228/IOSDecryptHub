// companion.m — 无 filter... 不,白名单 companion:被注入进策展白名单里的系统 daemon。
//
// 职责(两段式):
//   1) 常驻:向 collector(root)注册报活体(在线发现),不载引擎、开销极小;
//   2) 若该 daemon 在 enabledExecutables 名单里:用 PAC-correct fishhook 把引擎 WebUI 的
//      bind/listen/accept 重定向成 connect-out 到 collector(逃出 sandbox 的 inbound-bind 禁令),
//      再 dlopen 引擎。collector 把这些数据连接反代成一个 LAN 端口。
//
// 关键(M0 实测):dyld __interpose 对「后 dlopen 的引擎」不生效,必须 fishhook;且只能
// 对引擎镜像重绑(全局会改坏 host daemon 自己的 socket)。fishhook 写入按 arm64e auth_got
// 模式 PAC 签名(见 fishhook.c 的 ptrauth 补丁)。

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <pthread.h>
#import <syslog.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <stdbool.h>
#import <sys/socket.h>
#import <sys/un.h>
#import <netinet/in.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import "dh_bridge.h"
#import "dh_daemons.h"
#import "dh_shared.h"   // DH_KEY_EXECS(与 manager 共享的名单 key)

#define TAG "[DHCompanion]"

// 总闸:该文件在 → companion 立刻退出,什么都不做(白名单模式注入面已很小,这是便宜保险)。
#define DH_KILLSWITCH   "/var/jb/tmp/dh-companion-off"
#define DH_ENGINE_PATH  "/var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib"
#define DH_CONFIG_PATH  @"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"

static char g_proc[DH_PROC_MAX];

static int (*real_bind)(int, const struct sockaddr *, socklen_t);
static int (*real_listen)(int, int);
static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int g_engine_fd = -1;         // 引擎 WebUI 监听 socket 的 fd

// 连到 collector,发定长头,返回连接 fd(失败 -1)。
static int dh_connect(uint8_t type) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un u;
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    strncpy(u.sun_path, DH_BRIDGE_SOCK, sizeof(u.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&u, sizeof u) != 0) { close(fd); return -1; }
    struct dh_bridge_hdr h;
    memset(&h, 0, sizeof h);
    h.magic = DH_BRIDGE_MAGIC;
    h.type = type;
    h.pid = (uint32_t)getpid();
    strncpy(h.proc, g_proc, DH_PROC_MAX - 1);
    if (write(fd, &h, sizeof h) != (ssize_t)sizeof h) { close(fd); return -1; }
    return fd;
}

// —— 只重绑引擎镜像的三个 socket 调用 ——

static int my_bind(int s, const struct sockaddr *a, socklen_t l) {
    if (a && a->sa_family == AF_INET) {
        int port = ntohs(((const struct sockaddr_in *)a)->sin_port);
        if (port >= 8088 && port <= 8108) {   // 引擎 WebUI 端口区,假装 bind 成功
            g_engine_fd = s;
            syslog(LOG_NOTICE, TAG " 拦截引擎 bind(:%d)-> 假成功 fd=%d", port, s);
            return 0;
        }
    }
    return real_bind ? real_bind(s, a, l) : -1;
}
static int my_listen(int s, int b) {
    if (s == g_engine_fd) { syslog(LOG_NOTICE, TAG " 拦截引擎 listen fd=%d", s); return 0; }
    return real_listen ? real_listen(s, b) : -1;
}
static int my_accept(int s, struct sockaddr *a, socklen_t *l) {
    if (s == g_engine_fd) {
        // 懒连接:开一条 DATA 连接后**阻塞**读 collector 的 go(见 dh_bridge.h)。
        // collector 只在真有 LAN 客户端要 splice 时才发 go,所以引擎的 accept 停在这里等待、
        // 不空转洪泛;收到 go 即表示这条连接马上有真实 HTTP 请求,引擎照常在该 fd 上 serve。
        int fd = dh_connect(DH_CONN_DATA);
        if (fd < 0) { errno = ECONNABORTED; return -1; }
        char go = 0;
        ssize_t r = read(fd, &go, 1);
        if (r != 1 || (unsigned char)go != DH_BRIDGE_GO) {
            // 连接被 collector 关闭(如目标下线清池)或收到异常字节:放弃这条,引擎会重试 accept。
            close(fd);
            errno = ECONNABORTED;
            return -1;
        }
        return fd;
    }
    return real_accept ? real_accept(s, a, l) : -1;
}

// —— 引擎日志重定向到 collector(daemon sandbox 写不了任何文件目录)——
//
// 引擎(闭源)经 -[DHLogStore _openLogHandleLocked] 用 NSFileHandle 落盘到
// NSDocumentDirectory/decrypt_helper.log(见 IDA)。nsurlsessiond sandbox 下,Documents/
// Caches/AppSupport/tmp/var-jb-tmp/tmp 全部拒写(实测),文件落盘走不通。改法:swizzle
// _openLogHandleLocked,把引擎的 _logFH 换成一条连往 root collector 的 socket 的 NSFileHandle,
// 引擎 writeData 的字节由 collector 落盘 /var/log/dh-<proc>.log;_rotateLocked 置空(socket
// 不能 seek/truncate)。收字节的连接类型 = DH_CONN_LOG。
static void (*orig_openLogHandleLocked)(id, SEL);

static void my_openLogHandleLocked(id self, SEL _cmd) {
    Ivar iv = class_getInstanceVariable([self class], "_logFH");
    if (!iv) { if (orig_openLogHandleLocked) orig_openLogHandleLocked(self, _cmd); return; }
    if (object_getIvar(self, iv)) return;   // 已有句柄
    int fd = dh_connect(DH_CONN_LOG);
    if (fd < 0) return;                      // collector 没在,下次 _persist 再试
    // closeOnDealloc:YES —— 引擎 dealloc 时连带关掉 socket,不泄漏。
    NSFileHandle *fh = [[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES];
    object_setIvar(self, iv, fh);            // 非 ARC:alloc 的所有权转移给 ivar
    syslog(LOG_NOTICE, TAG " 引擎日志句柄改接 collector(fd=%d)", fd);
}

static void my_rotateLocked(id self, SEL _cmd) { (void)self; (void)_cmd; /* socket 不可 rotate */ }

static void dh_swizzle_logstore(void) {
    static bool done = false;
    if (done) return;   // 只 swizzle 一次(dh_img_added 早触发 + dlopen 后兜底,取先成功的)
    Class cls = NSClassFromString(@"DHLogStore");
    if (!cls) return;   // 类还没注册,等 dlopen 后那次兜底
    done = true;
    Method m1 = class_getInstanceMethod(cls, NSSelectorFromString(@"_openLogHandleLocked"));
    if (m1) {
        orig_openLogHandleLocked = (void (*)(id, SEL))method_getImplementation(m1);
        method_setImplementation(m1, (IMP)my_openLogHandleLocked);
    }
    Method m2 = class_getInstanceMethod(cls, NSSelectorFromString(@"_rotateLocked"));
    if (m2) method_setImplementation(m2, (IMP)my_rotateLocked);
    syslog(LOG_NOTICE, TAG " 已重定向 DHLogStore 落盘 -> collector(/var/log)");
}

// 用 ellekit 的 MSHookFunction(本项目已依赖 ellekit)对引擎两个**导出 C 函数**做 inline hook,
// 从根上消除「落盘失败」——daemon sandbox 写不了文件、日志已改走 collector,这类报错没有意义:
//   1) dh_health_persist_fail:纯 setter(atomic_store(1,&g_persist_failed)+fprintf+diag,见 IDA),
//      no-op 它 → health 标志从不置真;
//   2) dh_diag_append:所有 diag 事件的入口,只过滤掉含「落盘失败/无法打开」的条目(精确匹配,
//      其余 diag 照常)→ diag 时间线不再出现落盘失败。
// 为什么不 hook _persist:/_openLogHandleLocked —— 它们是 local 符号(dlsym 拿不到),只能等 ObjC
// 类注册后 swizzle,赶不上构造函数里最初几次 _persist;而这两个是导出符号,dlsym 可达,能在构造
// 函数**之前**(dh_img_added 时)就 hook 到,首次也拦得住。MSHookFunction 正确处理 arm64e 的
// PAC/text 保护(手动 vm_protect 改 text 会 kr=1);按符号名定位,不依赖 offset。
static void my_health_persist_fail(unsigned int err) { (void)err; /* no-op */ }

static long (*orig_dh_diag_append)(int, const char *, const char *);
static long my_dh_diag_append(int board, const char *level, const char *msg) {
    if (msg && (strstr(msg, "落盘失败") || strstr(msg, "无法打开"))) return 0;  // 丢弃落盘失败类
    return orig_dh_diag_append ? orig_dh_diag_append(board, level, msg) : 0;
}

static void dh_install_health_hooks(void) {
    static bool done = false;
    if (done) return;
    void *pf = dlsym(RTLD_DEFAULT, "dh_health_persist_fail");
    void *da = dlsym(RTLD_DEFAULT, "dh_diag_append");
    if (!pf || !da) return;   // 符号未解析到,留给下次兜底
    void (*MSHookFunction)(void *, void *, void **) =
        (void (*)(void *, void *, void **))dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!MSHookFunction) {
        // ellekit 的 substrate 兼容符号在 libellekit(libsubstrate 软链到它),按需 dlopen 引入。
        void *h = dlopen("/var/jb/usr/lib/libsubstrate.dylib", RTLD_LAZY | RTLD_GLOBAL);
        if (!h) h = dlopen("/var/jb/usr/lib/libellekit.dylib", RTLD_LAZY | RTLD_GLOBAL);
        if (h) MSHookFunction = (void (*)(void *, void *, void **))dlsym(h, "MSHookFunction");
    }
    if (!MSHookFunction) { syslog(LOG_NOTICE, TAG " 无 MSHookFunction,health hook 未装"); return; }
    MSHookFunction(pf, (void *)my_health_persist_fail, NULL);
    MSHookFunction(da, (void *)my_dh_diag_append, (void **)&orig_dh_diag_append);
    done = true;
    syslog(LOG_NOTICE, TAG " 已 inline-hook dh_health_persist_fail + dh_diag_append(滤落盘失败)");
}

// 引擎镜像载入(构造函数之前)时,只对它重绑 bind/listen/accept。
static void dh_img_added(const struct mach_header *mh, intptr_t slide) {
    Dl_info info;
    if (dladdr(mh, &info) == 0 || !info.dli_fname) return;
    if (!strstr(info.dli_fname, "decrypt_helper")) return;
    struct rebinding r[] = {
        { "bind",   (void *)my_bind,   (void **)&real_bind },
        { "listen", (void *)my_listen, (void **)&real_listen },
        { "accept", (void *)my_accept, (void **)&real_accept },
    };
    rebind_symbols_image((void *)mh, slide, r, 3);
    // 构造函数前:inline-hook 落盘失败上报(首次也静默),并尝试 swizzle 日志句柄(类若已注册)。
    dh_install_health_hooks();
    dh_swizzle_logstore();
    syslog(LOG_NOTICE, TAG " 已重绑引擎 socket + 日志改接 collector");
}

// —— 自检 ——

static bool dh_killswitch(void) { return access(DH_KILLSWITCH, F_OK) == 0; }

static bool dh_hard_blocked(const char *p) {
#define BLK(x) if (strcmp(p, x) == 0) return true;
    DH_DAEMON_HARD_BLOCK(BLK)
#undef BLK
    return false;
}
static bool dh_whitelisted(const char *p) {
#define CHK(exec, disp, dom, lbl, rst) if (strcmp(p, exec) == 0) return true;
    DH_DAEMON_LIST(CHK)
#undef CHK
    return false;
}

// 是否已在 manager 里开启注入(读 jb 配置的 enabledExecutables;沙盒目标读这份)。
static bool dh_enabled(const char *p) {
    @autoreleasepool {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:DH_CONFIG_PATH];
        NSArray *arr = d[DH_KEY_EXECS];
        if (![arr isKindOfClass:[NSArray class]]) return false;
        return [arr containsObject:[NSString stringWithUTF8String:p]];
    }
}

// 常驻 control 连接:在 = 该 daemon 在线;断了每 2 秒重连。
static void *dh_control_thread(void *arg) {
    (void)arg;
    for (;;) {
        int fd = dh_connect(DH_CONN_CONTROL);
        if (fd >= 0) {
            char buf[64];
            // 阻塞读到断开(collector 关连接或进程退出);未来命令通道也走这里。
            while (read(fd, buf, sizeof buf) > 0) { /* ignore for now */ }
            close(fd);
        }
        sleep(2);
    }
    return NULL;
}

__attribute__((constructor))
static void dh_companion_init(void) {
    const char *prog = getprogname();
    if (!prog || !*prog) return;
    strncpy(g_proc, prog, DH_PROC_MAX - 1);

    if (dh_killswitch()) return;
    if (dh_hard_blocked(g_proc)) return;
    if (!dh_whitelisted(g_proc)) return;   // Filter 已 scope,这里兜底

    syslog(LOG_NOTICE, TAG " 进驻 %s pid=%d", g_proc, getpid());

    // 报活体(在线发现)
    pthread_t th;
    if (pthread_create(&th, NULL, dh_control_thread, NULL) == 0) pthread_detach(th);

    // 已开启 → 架桥载引擎
    if (dh_enabled(g_proc)) {
        syslog(LOG_NOTICE, TAG " %s 已启用,架桥载引擎", g_proc);
        _dyld_register_func_for_add_image(dh_img_added);   // 引擎载入(构造函数前)触发重绑
        void *h = dlopen(DH_ENGINE_PATH, RTLD_NOW);
        syslog(LOG_NOTICE, TAG " dlopen 引擎 %s", h ? "成功" : "失败");
        // 引擎类已注册,把它的日志句柄改接 collector(daemon sandbox 写不了文件)。
        // dh_img_added 时若符号/类还没就绪,这里兜底(hook 需在首次 _persist 前才能防标志,
        // 正常应在 dh_img_added 那次已生效)。
        if (h) { dh_install_health_hooks(); dh_swizzle_logstore(); }
    }
}
