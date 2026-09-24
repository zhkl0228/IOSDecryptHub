// companion.m — 无 filter... 不,白名单 companion:被注入进策展白名单里的系统 daemon。
//
// 职责(两段式):
//   1) 常驻:向 collector(root)注册报活体(在线发现),不载引擎、开销极小;
//   2) 若该 daemon 在 enabledExecutables 名单里:用 ellekit MSHookFunction 对 libSystem 的
//      bind/listen/accept 做 inline hook,把引擎 WebUI 的 socket I/O 重定向(普通 daemon:connect-out
//      到 collector;严格 daemon:走内存桥),再 dlopen 引擎。collector 反代成一个 LAN 端口。
//
// 关键:hook 早在引擎镜像载入(构造函数前)就装,赶在引擎 bind 之前;guard 保证只对引擎的 WebUI
// socket(bind 端口 8088-8108、listen/accept 的 g_engine_fd)动手,daemon 自身及其它 socket 全透传。
// 曾用 fishhook 只重绑引擎镜像 GOT,但实测 1.27.x 引擎在 **lockdownd** 里调 accept 会**绕过**那个
// GOT 槽(bind/listen 不绕、mobileactivationd 不绕)→ 引擎不 serve;改用 inline hook 拦真实函数本体,
// 不管调用方走不走 GOT 都命中,对所有 daemon 稳(见 dh_install_socket_hooks)。

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
#import <objc/message.h>   // objc_msgSend(回填 backlog:+[DHLogStore shared] / -snapshot)
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

// 把 fd 标记为引擎内部,免得 1.27.x 引擎的网络 hook 把 companion 自己连 collector 的连接当成目标
// daemon 的网络活动捕获(实测 socket 桥 8090 的 WebUI 网络 tab 被 dh_connect 的 AF_UNIX connect 刷屏)。
// dh_net_mark_internal_fd 是引擎导出符号(1.27.x+,置 g_dh_fd_state[fd]=2);1.25.6 无此符号则跳过。
// 惰性 dlsym:引擎 dlopen 后才解析得到,故不缓存失败、每次未命中重试。
static void dh_mark_internal_fd(int fd) {
    static void (*fn)(int) = NULL;
    if (!fn) fn = (void (*)(int))dlsym(RTLD_DEFAULT, "dh_net_mark_internal_fd");
    if (fn) fn(fd);
}

// 连到 collector,发定长头,返回连接 fd(失败 -1)。
static int dh_connect(uint8_t type) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    dh_mark_internal_fd(fd);   // 标记内部,免被引擎网络 hook 捕获(见上)

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
    // 本 hook 只严格 daemon 内存桥装(见 dh_img_added:socket hook 仅 g_mem_bridge);普通 daemon 走引擎
    // UDS 直连、不装本 hook。故命中引擎监听 fd 必走内存桥的 socketpair。
    if (s == g_engine_fd) return dh_mem_accept();
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

// 内存桥日志 pump:引擎把日志写到 socketpair 一端,本线程从另一端读出,塞进 g_dh_shm.log_ring,
// collector vm_read 落盘 /var/log/dh-<proc>.log。环满时丢弃剩余(尽力聚合,不阻塞引擎日志)。
// (引擎写 _logFH 在其 reentrancy guard 内,不会被网络/文件 hook 捕获,故不会重现 socket 直连的
//  100% CPU 正反馈。)
static void *dh_log_pump(void *arg) {
    int b = (int)(long)arg;
    uint8_t buf[8192];
    for (;;) {
        ssize_t n = read(b, buf, sizeof buf);
        if (n <= 0) break;   // 引擎关了日志句柄(dealloc)
        uint32_t off = 0;
        while (off < (uint32_t)n) {
            uint32_t space = DH_LOG_RING_SZ - (g_dh_shm.log_head - g_dh_shm.log_tail);
            if (space == 0) break;   // 环满 → 丢弃这批剩余字节
            uint32_t k = ((uint32_t)n - off) < space ? ((uint32_t)n - off) : space;
            uint32_t pos = g_dh_shm.log_head & (DH_LOG_RING_SZ - 1);
            uint32_t first = (pos + k <= DH_LOG_RING_SZ) ? k : (DH_LOG_RING_SZ - pos);
            memcpy(&g_dh_shm.log_ring[pos], buf + off, first);
            if (k > first) memcpy(&g_dh_shm.log_ring[0], buf + off + first, k - first);
            g_dh_shm.log_head += k; off += k;
        }
    }
    close(b);
    return NULL;
}

static void my_openLogHandleLocked(id self, SEL _cmd) {
    Ivar iv = class_getInstanceVariable([self class], "_logFH");
    if (!iv) { if (orig_openLogHandleLocked) orig_openLogHandleLocked(self, _cmd); return; }
    if (object_getIvar(self, iv)) return;   // 已有句柄
    int fd;
    if (g_mem_bridge) {
        // 严格 daemon:sandbox 封 socket,不能像普通 daemon 那样 dh_connect 到 collector(必 EPERM,
        // /var/log 从来没有 dh-securityd/lockdownd.log 就是证据)。改走内存桥:给引擎一端 socketpair,
        // pump 线程把另一端字节搬进 g_dh_shm.log_ring,collector vm_read 落盘。
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return;
        pthread_t th;
        if (pthread_create(&th, NULL, dh_log_pump, (void *)(long)sv[1]) != 0) { close(sv[0]); close(sv[1]); return; }
        pthread_detach(th);
        fd = sv[0];
        syslog(LOG_NOTICE, TAG " 引擎日志改接内存桥 log ring(fd=%d)", fd);
    } else {
        // socket 桥(普通 daemon):连 collector,由它落盘 /var/log/dh-<proc>.log。
        fd = dh_connect(DH_CONN_LOG);
        if (fd < 0) return;                  // collector 没在,下次 _persist 再试
        syslog(LOG_NOTICE, TAG " 引擎日志句柄改接 collector(fd=%d)", fd);
    }
    // closeOnDealloc:YES —— 引擎 dealloc 时连带关掉 fd(socket/socketpair 一端),不泄漏。
    NSFileHandle *fh = [[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES];
    object_setIvar(self, iv, fh);            // 非 ARC:alloc 的所有权转移给 ivar
}

static void my_rotateLocked(id self, SEL _cmd) { (void)self; (void)_cmd; /* socket 不可 rotate */ }

// —— 结构化捕获聚合(P1)——
// 引擎每条捕获经 -[DHLogStore append:](self,entry) 进来,entry 是 DHLogEntry(getter 全齐,IDA 确认)。
// swizzle 它:先让引擎照常处理,再读 entry 字段(含引擎自己的 category)序列化成一行 JSON,写进
// g_dh_shm.cap_ring;collector vm_read 落盘 /var/log/dh-<proc>.cap.jsonl。仅内存桥 daemon(P1 目标;
// socket 桥 P2 走 DH_CONN_CAP)。大 payload 截断到 8K(记原长,全量留 P3)。
@interface DHLogEntry : NSObject
- (NSInteger)category;
- (NSString *)algorithm;
- (NSString *)operation;
- (NSData *)input;
- (NSData *)output;
- (id)callStack;
- (NSString *)detail;
- (long long)timestampMs;
- (long long)threadId;
- (long long)seq;   // 引擎单调递增序号(唯一);回填与流式并集靠它去重
- (NSData *)key;              // 对称密钥(IDA 确认 NSData*);crypto 分析核心料
- (NSData *)iv;               // 初始向量(NSData*)
- (NSString *)publicKeyInfo;  // 非对称公钥信息(NSString*)
@end

// 把整条记录(JSON+换行)写进 cap_ring;放不下则整条丢弃(保持行边界,尽力不阻塞引擎)。
// 加锁:流式经 _persist:(引擎串行队列,彼此串行),但一次性 backlog 回填跑在 dlopen 线程,会与
// 队列上的 _persist: 并发写 cap_head,故整个入环操作上锁。序列化(JSON/base64)在锁外,不占锁。
static pthread_mutex_t g_cap_lock = PTHREAD_MUTEX_INITIALIZER;
static void dh_cap_push(const uint8_t *data, uint32_t n) {
    if (n == 0 || n > DH_CAP_RING_SZ) return;
    pthread_mutex_lock(&g_cap_lock);
    uint32_t space = DH_CAP_RING_SZ - (g_dh_shm.cap_head - g_dh_shm.cap_tail);
    if (n <= space) {
        uint32_t pos = g_dh_shm.cap_head & (DH_CAP_RING_SZ - 1);
        uint32_t first = (pos + n <= DH_CAP_RING_SZ) ? n : (DH_CAP_RING_SZ - pos);
        memcpy(&g_dh_shm.cap_ring[pos], data, first);
        if (n > first) memcpy(&g_dh_shm.cap_ring[0], data + first, n - first);
        g_dh_shm.cap_head += n;
    }
    pthread_mutex_unlock(&g_cap_lock);
}

// 引擎导出的序列化(dlsym dh_cap_serialize):DHLogEntry → 一行 cap.jsonl JSON(NSData*)。**单一格式源**
// 在引擎 log_store.m。严格 daemon swizzle 后用它序列化 → 推 cap_ring(collector vm_read);普通 daemon 由
// 引擎源码级自 emit(log_store dh_cap_emit_daemon,直接 connect collector),不经 companion——故 socket 桥
// 的 dh_cap_sock_write 已废除。
static NSData *(*dh_cap_serialize_fn)(id) = NULL;

// swizzle 引擎 **_persist:noisy:**(双参!——引擎方法签名是 _persist:noisy:;旧代码 swizzle 单参 _persist:
// 会 selector 失配、装不上,引擎源码化后暴露)。_persist 在引擎串行队列、setSeq: 之后被调(seq 已就绪、
// 彼此串行)。**仅严格 daemon(内存桥)装**:先让引擎正常落盘(flat/WebUI 照旧),再用引擎 dh_cap_serialize
// 序列化推 cap_ring(严格 daemon 引擎 connect 不出去,只能 companion 代推)。普通 daemon 不装(引擎自 emit)。
static void (*orig_persist)(id, SEL, id, BOOL);
static void my_persist(id self, SEL _cmd, id entryObj, BOOL noisy) {
    if (orig_persist) orig_persist(self, _cmd, entryObj, noisy);
    if (dh_cap_serialize_fn && entryObj) {
        @autoreleasepool {
            NSData *line = dh_cap_serialize_fn(entryObj);
            if (line.length) dh_cap_push(line.bytes, (uint32_t)line.length);
        }
    }
}

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
    // cap:引擎导出 dh_cap_serialize(单一格式源);swizzle **_persist:noisy:**(双参,引擎真实 selector——
    // 旧代码 swizzle 单参 _persist: 会失配、装不上)。仅严格 daemon 装(dh_swizzle_logstore 只在 g_mem_bridge
    // 分支调用;普通 daemon 引擎源码级自 emit)。
    dh_cap_serialize_fn = (NSData *(*)(id))dlsym(RTLD_DEFAULT, "dh_cap_serialize");
    Method m3 = class_getInstanceMethod(cls, NSSelectorFromString(@"_persist:noisy:"));
    if (m3 && dh_cap_serialize_fn) {
        orig_persist = (void (*)(id, SEL, id, BOOL))method_getImplementation(m3);
        method_setImplementation(m3, (IMP)my_persist);
        // 回填 backlog:引擎在本 swizzle 装上之前(dlopen/init 期)已 persist 若干条(实测启动即 5 条 sys),
        // 没经 _persist:noisy: 入口。短命 daemon 死后永久丢失,故一次性 snapshot 补进 cap_ring;带 seq,
        // 与流式并集由 collector 重建层按 seq 去重(无损、确定)。
        id store = ((id (*)(id, SEL))objc_msgSend)((id)cls, NSSelectorFromString(@"shared"));
        id backlog = store ? ((id (*)(id, SEL))objc_msgSend)(store, NSSelectorFromString(@"snapshot")) : nil;
        if ([backlog isKindOfClass:[NSArray class]]) {
            for (id e in (NSArray *)backlog) { NSData *l = dh_cap_serialize_fn(e); if (l.length) dh_cap_push(l.bytes, (uint32_t)l.length); }
            syslog(LOG_NOTICE, TAG " swizzle _persist:noisy: + 回填 backlog %lu 条", (unsigned long)[(NSArray *)backlog count]);
        }
    } else {
        syslog(LOG_NOTICE, TAG " swizzle _persist:noisy: 跳过(m3=%p serialize=%p)", (void *)m3, (void *)dh_cap_serialize_fn);
    }
    syslog(LOG_NOTICE, TAG " 已重定向 DHLogStore 落盘 -> collector(严格 daemon 内存桥)");
}

// 落盘失败抑制不再靠 hook 引擎的 dh_health_persist_fail/dh_diag_append —— 引擎源码级 dh_daemon_env()
// (companion 已 setenv DH_DAEMON=1)在这两个函数内自判 daemon 环境并 no-op/滤除,companion 不再介入。
// 下面的 dh_get_mshook + socket inline hook 仅严格 daemon 内存桥仍需(重定向引擎 WebUI socket)。

// 取 ellekit 的 MSHookFunction(substrate 兼容符号在 libellekit,libsubstrate 软链到它)。
static void *dh_get_mshook(void) {
    void *ms = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!ms) {
        void *h = dlopen("/var/jb/usr/lib/libsubstrate.dylib", RTLD_LAZY | RTLD_GLOBAL);
        if (!h) h = dlopen("/var/jb/usr/lib/libellekit.dylib", RTLD_LAZY | RTLD_GLOBAL);
        if (h) ms = dlsym(h, "MSHookFunction");
    }
    return ms;
}

// 用 MSHookFunction 对 libSystem 的 bind/listen/accept 做 inline hook(拦真实函数本体)。
// 为何不用 fishhook 只重绑引擎镜像的 GOT:实测 1.27.x 引擎在 **lockdownd** 里调 accept 会**绕过**
// 引擎镜像的 GOT 槽(bind/listen 没绕、mobileactivationd 也没绕),fishhook 拦不到 → 引擎在 faked fd
// 上空转 real accept、不 serve。inline hook 拦的是真实函数本体,不管调用方走不走那个 GOT 都命中,
// 对所有 daemon 都稳。guard(bind 认端口 8088-8108、listen/accept 认 g_engine_fd)保证只对引擎的
// WebUI socket 动手,daemon 自身及其它 socket 全部透传。早期(dh_img_added,构造函数前)装,赶在
// 引擎 bind 之前。real_bind/real_listen/real_accept 由 MSHookFunction 设为调用原函数的 trampoline。
static void dh_install_socket_hooks(void) {
    static bool done = false;
    if (done) return;
    void (*MSHookFunction)(void *, void *, void **) =
        (void (*)(void *, void *, void **))dh_get_mshook();
    if (!MSHookFunction) return;   // ellekit 还没就绪,留给下次兜底
    void *b = dlsym(RTLD_DEFAULT, "bind");
    void *l = dlsym(RTLD_DEFAULT, "listen");
    void *ac = dlsym(RTLD_DEFAULT, "accept");
    if (!b || !l || !ac) return;
    MSHookFunction(b,  (void *)my_bind,   (void **)&real_bind);
    MSHookFunction(l,  (void *)my_listen, (void **)&real_listen);
    MSHookFunction(ac, (void *)my_accept, (void **)&real_accept);
    done = true;
    syslog(LOG_NOTICE, TAG " 已 inline-hook bind/listen/accept(引擎 WebUI socket 重定向)");
}

// 引擎镜像载入(构造函数之前)时触发:仅严格 daemon 内存桥装 socket inline hook(赶在引擎 bind 前)
// + swizzle logstore。落盘失败/悬浮窗抑制已交给引擎源码级 dh_daemon_env(),不在此处 hook。
// socket hook 用 inline(见 dh_install_socket_hooks:fishhook GOT 在 lockdownd 会被引擎的 accept 调用绕过)。
static void dh_img_added(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    Dl_info info;
    if (dladdr(mh, &info) == 0 || !info.dli_fname) return;
    if (!strstr(info.dli_fname, "decrypt_helper")) return;
    // 落盘失败/悬浮窗抑制已由引擎源码级 dh_daemon_env() 处理(companion 已 setenv DH_DAEMON=1),不再 hook。
    // 严格 daemon 内存桥仍需趁早(引擎镜像载入、constructor 前)装 socket hook(拦引擎 bind/accept 转
    // socketpair)+ swizzle logstore(把 cap/log 推内存桥 ring;严格 daemon 无 UDS 出站,引擎自 emit 不通)。
    // 普通 daemon 走引擎 UDS 直连、不本地 bind、cap/log 引擎源码级自 emit,dh_img_added 无需做任何事。
    if (g_mem_bridge) {
        dh_install_socket_hooks();
        dh_swizzle_logstore();
        syslog(LOG_NOTICE, TAG " 已装 socket+swizzle(严格 daemon 内存桥,引擎镜像载入)");
    }
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
            // 落盘失败/悬浮窗抑制走引擎 dh_daemon_env()(已 setenv DH_DAEMON=1);此处只补 swizzle
            // logstore(严格 daemon 无 UDS 出站,cap/log 靠内存桥 ring)——dh_img_added 若已装则幂等跳过。
            if (h) dh_swizzle_logstore();
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

    // 告知引擎「运行在 daemon 环境」(先于任何 dlopen,故引擎 constructor 里首次 dh_daemon_env() 就读到)。
    // 引擎据此源码级自调整:落盘失败不算健康故障、diag 不记落盘失败、不建悬浮窗——替代 companion 过去
    // 对 dh_health_persist_fail/dh_diag_append 的 inline hook 与对 DHFloatingController 的 swizzle。
    // 与 DH_DAEMON_UDS_SOCK(仅普通 daemon 设、管 cap/log 传输)解耦:两种 daemon 都设 DH_DAEMON=1。
    setenv("DH_DAEMON", "1", 1);

    // 自适应选桥:探测能否 connect-out 到 collector。通=socket 桥;被 sandbox 拒=内存桥
    // (严格 daemon 如 securityd,靠 collector task_for_pid + vm_read/write 读写 g_dh_shm)。
    int probe = dh_connect(DH_CONN_CONTROL);
    if (probe >= 0) {
        close(probe);
        g_mem_bridge = false;
        pthread_t th;   // socket 桥:常驻 control 报活体
        if (pthread_create(&th, NULL, dh_control_thread, NULL) == 0) pthread_detach(th);

        // 普通 daemon(sandbox 放行 AF_UNIX 出站):能读 config,自己判断是否已开启并架桥。引擎自己
        // connect-out collector(UDS 直连),companion 不 hook bind/listen/accept。用环境变量在 dlopen **前**
        // 告知——先于引擎 constructor 里 dispatch_async 的 dh_http_start,无竞态。引擎与 companion 同批
        // 部署、一定认 env,不做旧引擎回退。
        if (dh_enabled(g_proc)) {
            syslog(LOG_NOTICE, TAG " %s 已启用,载引擎(UDS 直连)", g_proc);
            setenv("DH_DAEMON_UDS_SOCK", DH_BRIDGE_SOCK, 1);
            setenv("DH_DAEMON_UDS_PROC", g_proc, 1);
            // 普通 daemon:落盘失败/悬浮窗抑制走引擎 dh_daemon_env()(DH_DAEMON=1 已设),cap/log 引擎源码级
            // 自 emit(UDS 直连 collector),不本地 bind——companion 无需 hook 或 swizzle,也无需注册
            // dh_img_added(它只为严格 daemon 内存桥装 socket hook + swizzle,对普通 daemon 是 no-op)。
            void *h = dlopen(DH_ENGINE_PATH, RTLD_NOW);
            syslog(LOG_NOTICE, TAG " dlopen 引擎 %s", h ? "成功" : "失败");
            (void)h;
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
