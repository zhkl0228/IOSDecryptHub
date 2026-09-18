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
#import <poll.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import "dh_bridge.h"
#import "dh_daemons.h"
#import "dh_shared.h"   // DH_KEY_EXECS(与 manager 共享的名单 key)
#import "dh_shm.h"      // 内存桥(严格 daemon:sandbox 全封 socket 出口时用)

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

// —— 内存桥(g_mem_bridge=true 时启用;collector connect-out 被 sandbox 拒的严格 daemon)——
// 引擎 accept 得到真 socketpair fd,companion pump 线程搬运到 g_dh_shm ring;collector vm_read/write 它。
static dh_shm_t g_dh_shm;          // collector 扫 DHCompanion 镜像找 magic 定位本结构
static bool g_mem_bridge = false;

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
            if (g_mem_bridge) g_dh_shm.engine_port = (uint32_t)port;
            syslog(LOG_NOTICE, TAG " 拦截引擎 bind(:%d)-> 假成功 fd=%d%s", port, s, g_mem_bridge ? "(内存桥)" : "");
            return 0;
        }
    }
    return real_bind ? real_bind(s, a, l) : -1;
}
static int my_listen(int s, int b) {
    if (s == g_engine_fd) { syslog(LOG_NOTICE, TAG " 拦截引擎 listen fd=%d", s); return 0; }
    return real_listen ? real_listen(s, b) : -1;
}

// —— 内存桥:引擎 accept 得到**真 socketpair fd**(poll/read/write 全正常),companion pump 线程在
// socketpair ↔ g_dh_shm ring 之间搬运,collector 经 vm_read/write 与 ring 交换字节。
// (引擎 HTTP serve 用 poll/select 等 fd 可读,虚拟 fd 内核不认——实测 accept 认领后不 read,故必须给真 fd。)
typedef struct { int b; int idx; } dh_pump_arg_t;
static void *dh_mem_pump(void *arg) {
    dh_pump_arg_t pa = *(dh_pump_arg_t *)arg; free(arg);
    int b = pa.b; dh_conn_t *c = &g_dh_shm.conn[pa.idx];
    uint8_t buf[16384]; int wr_shut = 0;
    for (;;) {
        int did = 0;
        struct pollfd p = { b, POLLIN, 0 };
        int pr = poll(&p, 1, 5);
        if (pr > 0 && (p.revents & POLLIN)) {          // 引擎响应:socketpair → out 环
            ssize_t n = read(b, buf, sizeof buf);
            if (n > 0) {
                uint32_t sent = 0;
                while (sent < (uint32_t)n) {
                    uint32_t space = DH_RING_SZ - (c->out_head - c->out_tail);
                    if (space == 0) { usleep(1000); continue; }
                    uint32_t k = ((uint32_t)n - sent) < space ? ((uint32_t)n - sent) : space;
                    uint32_t pos = c->out_head & (DH_RING_SZ - 1);
                    uint32_t first = (pos + k <= DH_RING_SZ) ? k : (DH_RING_SZ - pos);
                    memcpy(&c->out[pos], buf + sent, first);
                    if (k > first) memcpy(&c->out[0], buf + sent + first, k - first);
                    c->out_head += k; sent += k;
                }
                did = 1;
            } else { c->engine_closed = 1; break; }    // 引擎关连接
        }
        uint32_t avail = c->in_head - c->in_tail;      // collector 请求:in 环 → socketpair
        if (avail) {
            uint32_t k = avail < sizeof buf ? avail : (uint32_t)sizeof buf;
            uint32_t pos = c->in_tail & (DH_RING_SZ - 1);
            uint32_t first = (pos + k <= DH_RING_SZ) ? k : (DH_RING_SZ - pos);
            memcpy(buf, &c->in[pos], first);
            if (k > first) memcpy(buf + first, &c->in[0], k - first);
            ssize_t w = write(b, buf, k);
            if (w > 0) { c->in_tail += (uint32_t)w; did = 1; }
        }
        if (c->lan_closed && !wr_shut) { shutdown(b, SHUT_WR); wr_shut = 1; }   // LAN 关 → 引擎 read EOF
        if (pr > 0 && (p.revents & (POLLHUP | POLLERR | POLLNVAL))) { c->engine_closed = 1; break; }
        if (!did) usleep(1000);
    }
    close(b);
    return NULL;
}
// 引擎侧认领锁:若引擎用多线程 accept,两线程可能同时扫到同一条 REQ 都认领 → 与 collector 侧同类
// 的串味。锁内「扫 REQ + 置 SERVING」原子认领(单线程 accept 时无竞争,加锁也无害)。
static pthread_mutex_t g_dh_accept_lock = PTHREAD_MUTEX_INITIALIZER;
static int dh_mem_accept(void) {
    int idx = -1;
    for (;;) {   // 等 collector 占用一条连接(state=REQ)
        pthread_mutex_lock(&g_dh_accept_lock);
        idx = -1;
        for (int i = 0; i < DH_MAX_CONN; i++) if (g_dh_shm.conn[i].state == DH_CS_REQ) { idx = i; break; }
        if (idx >= 0) g_dh_shm.conn[idx].state = DH_CS_SERVING;   // 锁内认领,防多 accept 线程抢同一条
        pthread_mutex_unlock(&g_dh_accept_lock);
        if (idx >= 0) break;
        usleep(2000);
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { g_dh_shm.conn[idx].state = DH_CS_FREE; errno = ECONNABORTED; return -1; }
    dh_pump_arg_t *pa = malloc(sizeof *pa); pa->b = sv[1]; pa->idx = idx;
    pthread_t th;
    if (pthread_create(&th, NULL, dh_mem_pump, pa) != 0) {
        close(sv[0]); close(sv[1]); free(pa); g_dh_shm.conn[idx].state = DH_CS_FREE; errno = ECONNABORTED; return -1;
    }
    pthread_detach(th);
    return sv[0];   // 引擎用真 socketpair fd
}
static int my_accept(int s, struct sockaddr *a, socklen_t *l) {
    if (s == g_engine_fd) {
        if (g_mem_bridge) return dh_mem_accept();
        // socket 桥懒连接:开一条 DATA 连接后**阻塞**读 collector 的 go(见 dh_bridge.h)。
        int fd = dh_connect(DH_CONN_DATA);
        if (fd < 0) { errno = ECONNABORTED; return -1; }
        char go = 0;
        ssize_t r = read(fd, &go, 1);
        if (r != 1 || (unsigned char)go != DH_BRIDGE_GO) {
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

// 引擎的悬浮窗(DHFloatingController)给 App 显示 ip:port;daemon 里没有可用的 UIWindowScene,
// -[DHFloatingController createFloatingWindow] 落到 initWithFrame: 分支后,系统为无 scene 的
// UIWindow 自建 UIWindowScene 会断言崩(实测 trustd 注入即 SIGABRT)。companion 只注入 daemon,
// 故无条件把 -[DHFloatingController build] 置空——daemon 不需要悬浮窗;App 走 loader 注入不受影响。
static void my_floating_build(id self, SEL _cmd) { (void)self; (void)_cmd; /* daemon 不建悬浮窗 */ }

static void dh_disable_floating_window(void) {
    static bool done = false;
    if (done) return;
    Class cls = NSClassFromString(@"DHFloatingController");
    if (!cls) return;   // 类还没注册,等 dlopen 后那次兜底
    Method m = class_getInstanceMethod(cls, NSSelectorFromString(@"build"));
    if (!m) return;
    method_setImplementation(m, (IMP)my_floating_build);
    done = true;
    syslog(LOG_NOTICE, TAG " 已禁用引擎悬浮窗(daemon 无 UIScene,-[DHFloatingController build] 置空)");
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

// 内存桥:等 collector 置 cmd_load(它读了 config 确认本 daemon 已开启),再 dlopen 引擎架桥。
static void *dh_mem_load_thread(void *arg) {
    (void)arg;
    for (;;) {
        if (g_dh_shm.cmd_load) {
            g_dh_shm.dbg_enabled = 1;
            syslog(LOG_NOTICE, TAG " 收到 collector cmd_load,dlopen 引擎架桥(内存桥)");
            _dyld_register_func_for_add_image(dh_img_added);
            void *h = dlopen(DH_ENGINE_PATH, RTLD_NOW);
            g_dh_shm.dbg_dlopen = h ? 1 : 0;
            syslog(LOG_NOTICE, TAG " dlopen 引擎 %s", h ? "成功" : "失败");
            if (h) { dh_install_health_hooks(); dh_swizzle_logstore(); dh_disable_floating_window(); }
            return NULL;
        }
        usleep(200000);
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

    // 自适应选桥:探测能否 connect-out 到 collector。通=socket 桥;被 sandbox 拒=内存桥
    // (严格 daemon 如 securityd,靠 collector task_for_pid + vm_read/write 读写 g_dh_shm)。
    int probe = dh_connect(DH_CONN_CONTROL);
    if (probe >= 0) {
        close(probe);
        g_mem_bridge = false;
        pthread_t th;   // socket 桥:常驻 control 报活体
        if (pthread_create(&th, NULL, dh_control_thread, NULL) == 0) pthread_detach(th);

        // socket 桥:能读 config,自己判断是否已开启并架桥
        if (dh_enabled(g_proc)) {
            syslog(LOG_NOTICE, TAG " %s 已启用,架桥载引擎(socket 桥)", g_proc);
            _dyld_register_func_for_add_image(dh_img_added);
            void *h = dlopen(DH_ENGINE_PATH, RTLD_NOW);
            syslog(LOG_NOTICE, TAG " dlopen 引擎 %s", h ? "成功" : "失败");
            if (h) { dh_install_health_hooks(); dh_swizzle_logstore(); dh_disable_floating_window(); }
        }
    } else {
        // 内存桥:严格 daemon 读不了 jb config,不能自判是否开启;设 magic 后起线程等 collector 的
        // cmd_load(collector 能读 config,代为通知),收到再 dlopen 引擎架桥。
        g_mem_bridge = true;
        g_dh_shm.magic = DH_SHM_MAGIC;
        g_dh_shm.version = DH_SHM_VERSION;
        syslog(LOG_NOTICE, TAG " connect collector 被拒,启用内存桥,等 collector 通知架桥");
        pthread_t th;
        if (pthread_create(&th, NULL, dh_mem_load_thread, NULL) == 0) pthread_detach(th);
    }
}
