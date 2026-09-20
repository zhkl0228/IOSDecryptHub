// collector.c — IOSDecryptHubCollector:root 常驻收集器/反向代理。
//
// 数据平面(见 src/dh_bridge.h):被注入 daemon 里的 companion 因 sandbox 禁 bind,把引擎
// WebUI 的服务端连接 connect-out 到本进程的 UNIX socket;本进程按进程名把它们**反代成一个
// LAN 端口**,于是每个 daemon-engine 就像今天的 App-engine 一样 = 一个 ip:809x(/api + /api/mcp
// 原样,idh/浏览器/manager 端口扫描全复用)。本进程 root、能 bind 所有网卡。
//
// 连接生命周期(解决 M0 的 accept 洪泛):DATA 连接被**池住不动**(不发请求、不关),引擎的
// serve 线程因此阻塞在 read、不空转;只有 LAN 客户端来了才取一条池中连接与之裸字节 splice。

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>      // posix_spawn(重启 daemon:launchctl kickstart)
#include <sys/wait.h>   // waitpid
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <sys/sysctl.h>
#include <sys/param.h>   // MAXCOMLEN:p_comm 被截断到此长度(16)
#include <stddef.h>
#include <time.h>
#include <mach-o/dyld_images.h>
#include "../src/dh_bridge.h"
#include "../src/dh_daemons.h"
#include "../src/dh_shm.h"

extern kern_return_t task_for_pid(mach_port_t target, int pid, mach_port_t *task);

#define MAX_TARGETS   32
#define LAN_PORT_BASE 8090
#define POOL_MAX      16

typedef struct {
    char  proc[DH_PROC_MAX];
    int   used;
    int   online;                 // CONTROL 活体:companion 已注入并报活体(socket 桥无条件起,≠引擎就绪)
    int   engine_ready;           // 引擎真架桥:收到过 DATA 连接(引擎 dlopen 后必 accept→connect-out)=可连活引擎
    int   lan_port;
    int   lan_fd;                 // LAN 监听 fd,-1 未绑
    int   pool[POOL_MAX];         // 池住的引擎数据连接 fd
    int   pool_n;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
} target_t;

static target_t g_t[MAX_TARGETS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// 每个白名单 daemon 按它在 DH_DAEMON_LIST 里的固定序号分配 LAN 端口(LAN_PORT_BASE+slot):
// socket 桥与内存桥共用同一映射 → 端口唯一、两套桥永不撞。旧代码 socket 桥用 (t-g_t)、内存桥用
// g_mb_n,两套独立编号会重叠(实测 trustd 内存桥撞到了 nsurlsessiond 的 socket 桥端口 8092)。
// name 可能是被 MAXCOMLEN 截断的 p_comm,用 strncmp 匹配;找不到返回 -1。
static int dh_daemon_slot(const char *name) {
    int i = 0, slot = -1;
    #define SLOT(exec, disp, dom, lbl, rst) do { if (strncmp(name, exec, MAXCOMLEN) == 0) slot = i; i++; } while (0);
    DH_DAEMON_LIST(SLOT)
    #undef SLOT
    return slot;
}

static void logts(const char *fmt, ...) {
    char ts[32]; time_t now = time(NULL); struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
    printf("[%s] ", ts);
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap); va_end(ap); printf("\n"); fflush(stdout);
}


static ssize_t readn(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0) return r;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static target_t *target_get(const char *proc) {
    pthread_mutex_lock(&g_lock);
    target_t *t = NULL, *free_slot = NULL;
    for (int i = 0; i < MAX_TARGETS; i++) {
        if (g_t[i].used && strcmp(g_t[i].proc, proc) == 0) { t = &g_t[i]; break; }
        if (!g_t[i].used && !free_slot) free_slot = &g_t[i];
    }
    if (!t && free_slot) {
        t = free_slot;
        memset(t, 0, sizeof *t);
        t->used = 1;
        t->lan_fd = -1;
        int slot = dh_daemon_slot(proc);
        t->lan_port = LAN_PORT_BASE + (slot >= 0 ? slot : (int)(t - g_t));
        strncpy(t->proc, proc, DH_PROC_MAX - 1);
        pthread_mutex_init(&t->lock, NULL);
        pthread_cond_init(&t->cond, NULL);
    }
    pthread_mutex_unlock(&g_lock);
    return t;
}

// 双向裸字节 splice,任一端关就收工。
static void *splice_thread(void *arg) {
    int *fds = arg; int a = fds[0], b = fds[1]; free(fds);
    struct pollfd p[2] = { { a, POLLIN, 0 }, { b, POLLIN, 0 } };
    char buf[16384];
    for (;;) {
        p[0].revents = p[1].revents = 0;
        if (poll(p, 2, -1) <= 0) break;
        if (p[0].revents & POLLIN) { ssize_t n = read(a, buf, sizeof buf); if (n <= 0) break; if (write(b, buf, (size_t)n) != n) break; }
        if (p[1].revents & POLLIN) { ssize_t n = read(b, buf, sizeof buf); if (n <= 0) break; if (write(a, buf, (size_t)n) != n) break; }
        if ((p[0].revents | p[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) break;
    }
    close(a); close(b);
    return NULL;
}

// 每个 target 一条 LAN 监听线程:LAN 客户端来 → 取一条池中引擎连接 → splice。
static void *lan_thread(void *arg) {
    target_t *t = arg;
    logts("[collector] %s 反代于 *:%d", t->proc, t->lan_port);
    for (;;) {
        int c = accept(t->lan_fd, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        // 取一条待命连接并发 go 唤醒它(见 dh_bridge.h);write 失败=这条已是僵尸,丢弃再取。
        int d = -1;
        for (;;) {
            pthread_mutex_lock(&t->lock);
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 5;
            while (t->pool_n == 0) {
                if (pthread_cond_timedwait(&t->cond, &t->lock, &ts) == ETIMEDOUT) break;
            }
            d = (t->pool_n > 0) ? t->pool[--t->pool_n] : -1;
            pthread_mutex_unlock(&t->lock);
            if (d < 0) break;                              // 5 秒内没等到待命连接
            unsigned char go = DH_BRIDGE_GO;
            if (write(d, &go, 1) == 1) break;              // 唤醒成功,d 上马上会有引擎响应
            close(d); d = -1;                              // 僵尸连接,丢弃继续取
        }
        if (d < 0) { close(c); continue; }   // 引擎没在(未开启/无待命连接),放弃这个 LAN 请求
        int *fds = malloc(2 * sizeof(int)); fds[0] = c; fds[1] = d;
        pthread_t th;
        if (pthread_create(&th, NULL, splice_thread, fds) == 0) pthread_detach(th);
        else { close(c); close(d); free(fds); }
    }
    return NULL;
}

static void target_ensure_lan(target_t *t) {
    pthread_mutex_lock(&t->lock);
    if (t->lan_fd < 0) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((uint16_t)t->lan_port); a.sin_addr.s_addr = INADDR_ANY;
        if (bind(s, (struct sockaddr *)&a, sizeof a) == 0 && listen(s, 16) == 0) {
            t->lan_fd = s;
            pthread_t th;
            if (pthread_create(&th, NULL, lan_thread, t) == 0) pthread_detach(th);
        } else { logts("[collector] %s LAN bind :%d 失败 errno=%d", t->proc, t->lan_port, errno); close(s); }
    }
    pthread_mutex_unlock(&t->lock);
}

// DH_CONN_LOG:引擎日志字节流(companion 把引擎的 NSFileHandle 接到这条连接)。
// daemon 自己的 sandbox 写不了任何文件目录,collector 是 root、能写 /var/log,替它落盘。
// companion→collector 的字节流(引擎日志 DH_CONN_LOG 或结构化捕获 DH_CONN_CAP)落盘。
// pair[0]=fd,pair[1]=strdup(proc),pair[2]=后缀(".log" / ".cap.jsonl",字面量,不 free)。
static void *file_reader(void *arg) {
    void **pair = arg; int fd = (int)(long)pair[0]; char *proc = pair[1]; const char *suffix = pair[2]; free(pair);
    // proc 只允许字母数字/._-,防路径注入(getprogname 不会有别的,这里兜底)。
    char safe[DH_PROC_MAX];
    size_t j = 0;
    for (size_t i = 0; proc[i] && j < sizeof(safe) - 1; i++) {
        char ch = proc[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-') safe[j++] = ch;
    }
    safe[j] = 0;
    free(proc);
    if (safe[0] == 0) { close(fd); return NULL; }
    char path[160];
    snprintf(path, sizeof path, "/var/log/dh-%s%s", safe, suffix);
    int out = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (out < 0) { logts("[collector] 落盘文件打开失败 %s errno=%d", path, errno); close(fd); return NULL; }
    logts("[collector] %s 落盘 -> %s", safe, path);
    char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) { ssize_t w = write(out, buf + off, (size_t)(n - off)); if (w <= 0) break; off += w; }
    }
    close(out);
    close(fd);
    return NULL;
}

// CONTROL 连接的守护:读到断开就下线。
static void *control_reader(void *arg) {
    void **pair = arg; target_t *t = pair[0]; int fd = (int)(long)pair[1]; free(pair);
    char buf[64];
    while (read(fd, buf, sizeof buf) > 0) { /* 未来命令通道 */ }
    close(fd);
    pthread_mutex_lock(&g_lock); t->online = 0; t->engine_ready = 0; pthread_mutex_unlock(&g_lock);
    // 目标进程已退出(如 kickstart):池里残留的待命 DATA 连接都成了僵尸,清掉,
    // 否则下一个 LAN 请求会 splice 到一条对端已死的连接。
    pthread_mutex_lock(&t->lock);
    while (t->pool_n > 0) close(t->pool[--t->pool_n]);
    pthread_mutex_unlock(&t->lock);
    logts("[collector] %s 下线", t->proc);
    return NULL;
}

// 收 companion 连接,按头分派。
static void *accept_thread(void *arg) {
    int ls = (int)(long)arg;
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        struct dh_bridge_hdr h;
        if (readn(c, &h, sizeof h) != (ssize_t)sizeof h || h.magic != DH_BRIDGE_MAGIC) { close(c); continue; }
        h.proc[DH_PROC_MAX - 1] = 0;
        target_t *t = target_get(h.proc);
        if (!t) { close(c); continue; }
        if (h.type == DH_CONN_CONTROL) {
            pthread_mutex_lock(&g_lock); t->online = 1; pthread_mutex_unlock(&g_lock);
            logts("[collector] %s 上线 pid=%u port=%d", h.proc, h.pid, t->lan_port);
            void **pair = malloc(2 * sizeof(void *)); pair[0] = t; pair[1] = (void *)(long)c;
            pthread_t th;
            if (pthread_create(&th, NULL, control_reader, pair) == 0) pthread_detach(th);
            else { close(c); free(pair); }
        } else if (h.type == DH_CONN_LOG || h.type == DH_CONN_CAP) {
            // 引擎日志(.log)/ 结构化捕获(.cap.jsonl)字节流:起线程落盘(daemon 自己写不了文件)。
            void **pair = malloc(3 * sizeof(void *));
            pair[0] = (void *)(long)c; pair[1] = strdup(h.proc);
            pair[2] = (h.type == DH_CONN_CAP) ? (void *)".cap.jsonl" : (void *)".log";
            pthread_t th;
            if (pthread_create(&th, NULL, file_reader, pair) == 0) pthread_detach(th);
            else { close(c); free(pair[1]); free(pair); }
        } else { // DATA
            pthread_mutex_lock(&g_lock); t->engine_ready = 1; pthread_mutex_unlock(&g_lock);   // 引擎已 dlopen 并 accept
            target_ensure_lan(t);
            pthread_mutex_lock(&t->lock);
            if (t->pool_n < POOL_MAX) { t->pool[t->pool_n++] = c; pthread_cond_signal(&t->cond); logts("[collector] %s DATA 入池 pool_n=%d", h.proc, t->pool_n); pthread_mutex_unlock(&t->lock); }
            else { pthread_mutex_unlock(&t->lock); logts("[collector] %s DATA 池满丢弃", h.proc); close(c); }
        }
    }
    return NULL;
}

// ===================== 内存桥(严格 daemon:collector 反读 companion 的 g_dh_shm)=====================

// 遍历目标 dyld image 列表,找 DHCompanion.dylib 加载基址。
static int mb_rd(mach_port_t task, uint64_t addr, void *buf, size_t n) {
    vm_size_t rd = 0;
    return (vm_read_overwrite(task, (vm_address_t)addr, (vm_size_t)n, (vm_address_t)buf, &rd) == KERN_SUCCESS && rd == n) ? 0 : -1;
}
static int mb_wr(mach_port_t task, uint64_t addr, const void *buf, size_t n) {
    return vm_write(task, (vm_address_t)addr, (vm_offset_t)buf, (mach_msg_type_number_t)n) == KERN_SUCCESS ? 0 : -1;
}

// 从目标进程读一个 NUL 结尾 C 字符串。dyld 的 imageFilePath 常紧邻页边界,一次性读固定长度
// (旧代码 511 字节)会跨进未映射页 → vm_read_overwrite 整体返回失败,把本来完全映射的短字符串
// 也一并丢掉(DHCompanion 的路径偶尔就撞上,于是 mb_companion_base 误判「找不到 companion」)。
// 改为按 4K 页边界分段读:读到 NUL(完整)、满 cap、或某段读失败(真跨到未映射页)为止。
static int mb_read_cstr(mach_port_t task, uint64_t addr, char *out, size_t cap) {
    if (cap == 0) return -1;
    size_t got = 0;
    while (got < cap - 1) {
        uint64_t cur = addr + got;
        uint64_t page_end = (cur + 0x1000) & ~(uint64_t)0xFFF;   // 下一 4K 页边界
        size_t chunk = (size_t)(page_end - cur);
        if (chunk > cap - 1 - got) chunk = cap - 1 - got;
        vm_size_t rd = 0;
        if (vm_read_overwrite(task, (vm_address_t)cur, (vm_size_t)chunk,
                              (vm_address_t)(out + got), &rd) != KERN_SUCCESS || rd == 0)
            break;   // 该段读失败(可能跨到未映射页):用已读到的部分
        for (vm_size_t i = 0; i < rd; i++) if (out[got + i] == 0) return 0;   // 命中 NUL,完整字符串
        got += rd;
    }
    out[got] = 0;
    return got > 0 ? 0 : -1;
}


// 在目标进程的 dyld image 列表里找镜像名含 needle 的基址(companion / loader 通用)。
static uint64_t mb_image_base(mach_port_t task, const char *needle) {
    task_dyld_info_data_t di; mach_msg_type_number_t c = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &c) != KERN_SUCCESS) return 0;
    struct dyld_all_image_infos aii;
    if (mb_rd(task, (uint64_t)di.all_image_info_addr, &aii, sizeof aii) != 0) return 0;
    uint32_t n = aii.infoArrayCount;
    if (n == 0 || n > 8192) return 0;
    size_t arrsz = n * sizeof(struct dyld_image_info);
    struct dyld_image_info *arr = malloc(arrsz);
    if (!arr) return 0;
    uint64_t base = 0;
    if (mb_rd(task, (uint64_t)aii.infoArray, arr, arrsz) == 0) {
        for (uint32_t i = 0; i < n; i++) {
            char path[512] = {0};
            if (mb_read_cstr(task, (uint64_t)arr[i].imageFilePath, path, sizeof path) != 0) continue;
            if (strstr(path, needle)) { base = (uint64_t)arr[i].imageLoadAddress; break; }
        }
    }
    free(arr);
    return base;
}
static uint64_t mb_companion_base(mach_port_t task) { return mb_image_base(task, "DHCompanion"); }

// 从镜像基址附近的可写段扫 magic,定位对应全局结构的运行时地址。
static uint64_t mb_scan_magic(mach_port_t task, uint64_t base, uint32_t magic) {
    vm_address_t addr = (vm_address_t)base;
    for (int r = 0; r < 256; r++) {
        vm_size_t size = 0; vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj = MACH_PORT_NULL;
        if (vm_region_64(task, &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((uint64_t)addr > base + 32ull * 1024 * 1024) break;   // 只在镜像附近扫
        if (info.protection & VM_PROT_WRITE) {
            for (vm_address_t p = addr; p + 4 <= addr + size; p += 4096) {
                uint32_t buf[1024]; vm_size_t rd = 0;
                if (vm_read_overwrite(task, p, sizeof buf, (vm_address_t)buf, &rd) != KERN_SUCCESS) continue;
                for (size_t k = 0; k * 4 < rd; k++)
                    if (buf[k] == magic) return (uint64_t)(p + k * 4);
            }
        }
        addr += size;
    }
    return 0;
}
static uint64_t mb_find_shm(mach_port_t task, uint64_t base) { return mb_scan_magic(task, base, DH_SHM_MAGIC); }

// [App 共享内存发现] task_for_pid(App)+ 找 IOSDecryptHubLoader 镜像 + 扫 DH_APP_REG_MAGIC + vm_read
// struct dh_app_reg。比端口扫描完整——后台被挂起的 App 内存也可读。返回 1=读到(回填 port/bundle/version)。
int dh_app_mem_read(int pid, uint32_t *port, char *bundle, size_t bcap, char *ver, size_t vcap) {
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) return 0;
    int found = 0;
    uint64_t base = mb_image_base(task, "IOSDecryptHubLoader");
    if (base) {
        uint64_t a = mb_scan_magic(task, base, DH_APP_REG_MAGIC);
        if (a) {
            struct dh_app_reg r;
            if (mb_rd(task, a, &r, sizeof r) == 0 && r.magic == DH_APP_REG_MAGIC) {
                if (port) *port = r.port;
                r.bundle[sizeof(r.bundle) - 1] = 0; r.version[sizeof(r.version) - 1] = 0;
                if (bundle && bcap) { strncpy(bundle, r.bundle, bcap - 1); bundle[bcap - 1] = 0; }
                if (ver && vcap) { strncpy(ver, r.version, vcap - 1); ver[vcap - 1] = 0; }
                found = 1;
            }
        }
    }
    mach_port_deallocate(mach_task_self(), task);
    return found;
}
#define MB_CONN(shm, i)  ((shm) + offsetof(dh_shm_t, conn) + (uint64_t)(i) * sizeof(dh_conn_t))
#define MB_F(ca, field)  ((ca) + offsetof(dh_conn_t, field))

typedef struct { int lan_fd; mach_port_t task; uint64_t shm; } mb_conn_arg_t;

// 抢占 ring 空闲 conn 的临界区锁:每条 LAN 连接各起一个 mb_conn_thread,并发抢 conn 必须互斥
// (否则两线程扫到同一条 FREE、都置 REQ、都用同一 ring → 响应串味)。跨 target 共用一把即可,
// 临界区只是扫 16 个 state + 几个 u32 写,极短。
static pthread_mutex_t g_mb_conn_lock = PTHREAD_MUTEX_INITIALIZER;

// 一条 LAN 连接 ↔ 一条内存 ring 连接:LAN 请求 vm_write 进 in 环,out 环 vm_read 回 LAN。
static void *mb_conn_thread(void *arg) {
    mb_conn_arg_t a = *(mb_conn_arg_t *)arg; free(arg);
    int lan = a.lan_fd; mach_port_t task = a.task; uint64_t shm = a.shm;
    // 找一条空闲连接并占用(清零 head/tail/flags,置 REQ 让引擎 accept 认领)。
    // 「扫描 FREE + 置 REQ」必须在锁内完成,否则并发线程会抢到同一条 conn(见 g_mb_conn_lock)。
    uint64_t ca = 0;
    pthread_mutex_lock(&g_mb_conn_lock);
    for (int i = 0; i < DH_MAX_CONN; i++) {
        uint64_t x = MB_CONN(shm, i); uint32_t st = 1;
        if (mb_rd(task, MB_F(x, state), &st, 4) != 0) continue;
        if (st == DH_CS_FREE) {
            uint32_t z = 0;
            mb_wr(task, MB_F(x, in_head), &z, 4);  mb_wr(task, MB_F(x, in_tail), &z, 4);
            mb_wr(task, MB_F(x, out_head), &z, 4); mb_wr(task, MB_F(x, out_tail), &z, 4);
            mb_wr(task, MB_F(x, lan_closed), &z, 4); mb_wr(task, MB_F(x, engine_closed), &z, 4);
            uint32_t req = DH_CS_REQ; mb_wr(task, MB_F(x, state), &req, 4);
            ca = x; break;
        }
    }
    pthread_mutex_unlock(&g_mb_conn_lock);
    if (!ca) { logts("[collector] 内存桥无空闲 conn,放弃 LAN"); close(lan); return NULL; }
    uint32_t in_head = 0, out_tail = 0; int lan_eof = 0;
    uint8_t buf[16384];
    for (;;) {
        // task 存活探测:daemon 退出、或桥被 teardown(mach_port_deallocate)后 vm_read 失败 → 退出。
        // 否则 task 失效时本线程只会空转(旧代码仅 lan_eof/engine_closed 才退),销毁桥时线程卡住。
        uint32_t alive; if (mb_rd(task, MB_F(ca, state), &alive, 4) != 0) { lan_eof = 1; break; }
        int did = 0;
        if (!lan_eof) {
            struct pollfd p = { lan, POLLIN, 0 };
            if (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) {
                ssize_t rn = read(lan, buf, sizeof buf);
                if (rn > 0) {
                    ssize_t off = 0;
                    while (off < rn) {
                        uint32_t in_tail = 0; mb_rd(task, MB_F(ca, in_tail), &in_tail, 4);
                        uint32_t space = DH_RING_SZ - (in_head - in_tail);
                        if (space == 0) { usleep(1000); continue; }
                        uint32_t k = (uint32_t)((rn - off) < (ssize_t)space ? (rn - off) : space);
                        uint32_t pos = in_head & (DH_RING_SZ - 1);
                        uint32_t first = (pos + k <= DH_RING_SZ) ? k : (DH_RING_SZ - pos);
                        mb_wr(task, MB_F(ca, in) + pos, buf + off, first);
                        if (k > first) mb_wr(task, MB_F(ca, in), buf + off + first, k - first);
                        in_head += k; off += k;
                        mb_wr(task, MB_F(ca, in_head), &in_head, 4);
                    }
                    did = 1;
                } else if (rn == 0) {
                    lan_eof = 1; uint32_t one = 1; mb_wr(task, MB_F(ca, lan_closed), &one, 4);
                }
            }
        }
        uint32_t out_head = 0; mb_rd(task, MB_F(ca, out_head), &out_head, 4);
        while ((int32_t)(out_head - out_tail) > 0) {
            uint32_t avail = out_head - out_tail;
            uint32_t k = avail < sizeof buf ? avail : (uint32_t)sizeof buf;
            uint32_t pos = out_tail & (DH_RING_SZ - 1);
            uint32_t first = (pos + k <= DH_RING_SZ) ? k : (DH_RING_SZ - pos);
            mb_rd(task, MB_F(ca, out) + pos, buf, first);
            if (k > first) mb_rd(task, MB_F(ca, out), buf + first, k - first);
            ssize_t wn = write(lan, buf, k);
            if (wn <= 0) { lan_eof = 1; break; }
            out_tail += k; mb_wr(task, MB_F(ca, out_tail), &out_tail, 4); did = 1;
            mb_rd(task, MB_F(ca, out_head), &out_head, 4);
        }
        uint32_t eng = 0; mb_rd(task, MB_F(ca, engine_closed), &eng, 4);
        if (eng) { mb_rd(task, MB_F(ca, out_head), &out_head, 4); if (out_head - out_tail == 0) break; }
        if (lan_eof) break;   // LAN 关(客户端走)即结束回收,不等引擎(靠 lan_closed 让引擎 read EOF)
        if (!did) usleep(2000);
    }
    uint32_t one = 1; mb_wr(task, MB_F(ca, lan_closed), &one, 4);
    uint32_t fr = DH_CS_FREE; mb_wr(task, MB_F(ca, state), &fr, 4);
    close(lan);
    return NULL;
}

typedef struct { char proc[DH_PROC_MAX]; int pid; int lan_port; mach_port_t task; uint64_t shm; int lan_fd; } mb_target_t;

// 抽一条内存桥单向环(companion 生产 head / collector 消费 tail)落到 out_fd。失同步(读到垃圾/丢
// 数据、avail 超过环容量)即跳到 head 丢弃这段(防狂写)。返回 -1 = task 失效(mb_rd 失败),调用方收尾退出。
static int mb_drain(mach_port_t task, uint64_t base, size_t head_off, size_t tail_off,
                    size_t ring_off, uint32_t ring_sz, uint32_t *tail, int out_fd) {
    uint32_t head = 0;
    if (mb_rd(task, base + head_off, &head, 4) != 0) return -1;
    if ((uint32_t)(head - *tail) > ring_sz) { *tail = head; mb_wr(task, base + tail_off, tail, 4); }
    uint8_t buf[8192];
    while ((int32_t)(head - *tail) > 0) {
        uint32_t k = head - *tail; if (k > sizeof buf) k = (uint32_t)sizeof buf;
        uint32_t pos = *tail & (ring_sz - 1);
        uint32_t first = (pos + k <= ring_sz) ? k : (ring_sz - pos);
        if (mb_rd(task, base + ring_off + pos, buf, first) != 0) return -1;
        if (k > first && mb_rd(task, base + ring_off, buf + first, k - first) != 0) return -1;
        ssize_t off = 0;
        while (off < (ssize_t)k) { ssize_t w = write(out_fd, buf + off, (size_t)(k - off)); if (w <= 0) break; off += w; }
        *tail += k;
        mb_wr(task, base + tail_off, tail, 4);
        if (mb_rd(task, base + head_off, &head, 4) != 0) return -1;
    }
    return 0;
}

// 内存桥落盘:严格 daemon 的引擎日志/结构化捕获走不了 socket,companion 写进 g_dh_shm 的 log_ring /
// cap_ring,本线程 vm_read 落 /var/log/dh-<proc>.log 与 dh-<proc>.cap.jsonl。每轮先校验 magic(端口
// 复用防读垃圾狂写),task 失效即退出。单消费者:只有本线程读这两环并前移各自 tail。
static void *mb_log_thread(void *arg) {
    mb_target_t *t = arg;
    char safe[DH_PROC_MAX]; size_t j = 0;
    for (size_t i = 0; t->proc[i] && j < sizeof(safe) - 1; i++) {
        char ch = t->proc[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-') safe[j++] = ch;
    }
    safe[j] = 0;
    if (safe[0] == 0) return NULL;
    char path[128]; snprintf(path, sizeof path, "/var/log/dh-%s.log", safe);
    int out = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (out < 0) { logts("[collector] %s 内存桥日志打开失败 %s errno=%d", safe, path, errno); return NULL; }
    char cpath[160]; snprintf(cpath, sizeof cpath, "/var/log/dh-%s.cap.jsonl", safe);
    int capf = open(cpath, O_WRONLY | O_CREAT | O_APPEND, 0644);   // 结构化捕获(可选,失败不致命)
    logts("[collector] %s 内存桥落盘 -> %s%s", safe, path, capf >= 0 ? " (+cap.jsonl)" : "(cap open 失败)");
    uint64_t base = t->shm;
    uint32_t ltail = 0, ctail = 0;
    mb_rd(t->task, base + offsetof(dh_shm_t, log_tail), &ltail, 4);
    if (capf >= 0) mb_rd(t->task, base + offsetof(dh_shm_t, cap_tail), &ctail, 4);
    for (;;) {
        uint32_t mg = 0;
        if (mb_rd(t->task, base + offsetof(dh_shm_t, magic), &mg, 4) != 0 || mg != DH_SHM_MAGIC) break;
        if (mb_drain(t->task, base, offsetof(dh_shm_t, log_head), offsetof(dh_shm_t, log_tail),
                     offsetof(dh_shm_t, log_ring), DH_LOG_RING_SZ, &ltail, out) != 0) break;
        if (capf >= 0 && mb_drain(t->task, base, offsetof(dh_shm_t, cap_head), offsetof(dh_shm_t, cap_tail),
                                  offsetof(dh_shm_t, cap_ring), DH_CAP_RING_SZ, &ctail, capf) != 0) break;
        usleep(200000);   // 200ms 轮询
    }
    close(out);
    if (capf >= 0) close(capf);
    return NULL;
}

static void *mb_lan_thread(void *arg) {
    mb_target_t *t = arg;
    logts("[collector] %s 内存桥反代于 *:%d(pid=%d shm=%#llx)", t->proc, t->lan_port, t->pid, (unsigned long long)t->shm);
    for (;;) {
        int c = accept(t->lan_fd, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        mb_conn_arg_t *ca = malloc(sizeof *ca); ca->lan_fd = c; ca->task = t->task; ca->shm = t->shm;
        pthread_t th; if (pthread_create(&th, NULL, mb_conn_thread, ca) == 0) pthread_detach(th);
        else { close(c); free(ca); }
    }
    return NULL;
}

// collector(root)读 jb config,判断某 daemon 是否在 enabledExecutables 里(严格 daemon 自己读不了)。
static int mb_is_enabled(const char *nm) {
    FILE *f = fopen("/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist", "r");
    if (!f) return 0;
    char buf[16384]; size_t n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f);
    char needle[80]; snprintf(needle, sizeof needle, "<string>%s</string>", nm);
    return strstr(buf, needle) != NULL;
}

// 周期扫描白名单 daemon:socket 桥没上线、但能 task_for_pid + 找到 g_dh_shm 的,起内存桥。
// 已建桥登记表(存 mb_target_t*):记录建桥时的 pid,daemon 换 pid(重启)或退出即销毁重建。
static mb_target_t *g_mb[64];
static int g_mb_n = 0;

// 内存桥建桥失败的节流诊断:每个 daemon(按 slot)每种失败只记一条,建桥成功时清零。
// 不再静默 continue —— 卡在哪步(task_for_pid / 找 companion / 找 shm)要能从日志看出来。
static uint32_t g_mb_diag[64];
static void mb_diag(const char *nm, int code, const char *msg) {
    int slot = dh_daemon_slot(nm);
    if (slot < 0 || slot >= 64) { logts("[collector] %s 内存桥跳过:%s", nm, msg); return; }
    if (g_mb_diag[slot] & (1u << code)) return;   // 该 daemon 该步已记过,节流
    g_mb_diag[slot] |= (1u << code);
    logts("[collector] %s 内存桥跳过:%s", nm, msg);
}

static int mb_already(const char *proc) {
    for (int i = 0; i < g_mb_n; i++) if (strcmp(g_mb[i]->proc, proc) == 0) return 1;
    return 0;
}

// 某 daemon(完整 exec 名)当前的 pid;不在跑返回 0。p_comm 可能被 MAXCOMLEN 截断,用 strncmp。
static pid_t mb_pid_of(const char *proc, struct kinfo_proc *procs, int cnt) {
    for (int i = 0; i < cnt; i++)
        if (strncmp(procs[i].kp_proc.p_comm, proc, MAXCOMLEN) == 0) return procs[i].kp_proc.p_pid;
    return 0;
}

// 销毁一条内存桥:关 LAN 监听(mb_lan_thread 的 accept 返回而退出)、释放 task(在跑的 mb_conn_thread
// 靠 task 存活探测发现 vm 失败后退出)。t 本身不 free —— detach 线程无法 join,故意保留(每 daemon
// 重启才泄漏一个 ~80B 结构,可忽略),避免 use-after-free。
static void mb_teardown(mb_target_t *t) {
    if (t->lan_fd >= 0) { close(t->lan_fd); t->lan_fd = -1; }
    if (t->task != MACH_PORT_NULL) { mach_port_deallocate(mach_task_self(), t->task); t->task = MACH_PORT_NULL; }
}
static void *mem_bridge_manager(void *arg) {
    (void)arg;
    for (;;) {
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 }; size_t len = 0;
        if (sysctl(mib, 4, NULL, &len, NULL, 0) == 0 && len) {
            struct kinfo_proc *procs = malloc(len);
            if (procs && sysctl(mib, 4, procs, &len, NULL, 0) == 0) {
                int cnt = (int)(len / sizeof(struct kinfo_proc));
                // 对账已建桥表:daemon 退出(mb_pid_of=0)或重启换 pid → 旧 task 已失效,拆桥并从表
                // 移除(struct 故意不 free,detach 线程靠 task 存活探测自行收尾),本轮后续按新 pid 重建。
                // 否则 mb_already 一直按名字命中、死抱旧 pid 的僵尸桥(task 失效→curl 无响应);
                // lockdownd 换进程重启正靠这条恢复。
                for (int mi = 0; mi < g_mb_n; ) {
                    pid_t cur = mb_pid_of(g_mb[mi]->proc, procs, cnt);
                    if (cur == g_mb[mi]->pid) { mi++; continue; }
                    logts("[collector] %s 内存桥失效(pid %d→%d),拆桥重建", g_mb[mi]->proc, g_mb[mi]->pid, (int)cur);
                    int dslot = dh_daemon_slot(g_mb[mi]->proc);
                    if (dslot >= 0 && dslot < 64) g_mb_diag[dslot] = 0;   // 重建时允许重新记诊断
                    mb_teardown(g_mb[mi]);
                    g_mb[mi] = g_mb[--g_mb_n];   // 末项补位(struct 泄漏,与 mb_teardown 注释一致)
                }
                for (int i = 0; i < cnt; i++) {
                    pid_t pid = procs[i].kp_proc.p_pid;
                    const char *nm = procs[i].kp_proc.p_comm;
                    if (pid <= 0) continue;
                    // p_comm 被 MAXCOMLEN(16) 截断(如 mobileactivationd→"mobileactivation"):
                    // 用 strncmp 定位白名单条目,再一律改用列表里的完整 exec 名——mb_is_enabled 查
                    // config、mb_already 去重、日志都要完整名才对得上截断前的真实进程。
                    const char *full = NULL;
                    #define CHK(exec, disp, dom, lbl, rst) if (strncmp(nm, exec, MAXCOMLEN) == 0) full = exec;
                    DH_DAEMON_LIST(CHK)
                    #undef CHK
                    if (!full || mb_already(full)) continue;
                    nm = full;   // 此后 nm 一律为完整 exec 名(非截断 p_comm)
                    target_t *st = target_get(nm);
                    if (st && st->online) continue;   // socket 桥已接管
                    mach_port_t task = MACH_PORT_NULL;
                    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) { mb_diag(nm, 1, "task_for_pid 失败(权限/受保护进程?)"); continue; }
                    uint64_t base = mb_companion_base(task);
                    if (!base) { mb_diag(nm, 2, "找不到 DHCompanion 基址(companion 未注入?)"); continue; }
                    uint64_t shm = mb_find_shm(task, base);
                    if (!shm) { mb_diag(nm, 3, "找不到 g_dh_shm magic(companion 未进内存桥?)"); continue; }
                    // 严格 daemon 读不了 jb config,由 collector 代读并置 cmd_load 通知 companion 架桥。
                    if (!mb_is_enabled(nm)) { continue; }   // 未开启:不通知、不起桥(companion idle 等)
                    uint32_t cl = 1; mb_wr(task, shm + offsetof(dh_shm_t, cmd_load), &cl, 4);
                    // 等引擎 dlopen + bind(engine_port 非 0)——最多等 ~10s
                    uint32_t ep = 0;
                    for (int w = 0; w < 100; w++) {
                        mb_rd(task, shm + offsetof(dh_shm_t, engine_port), &ep, 4);
                        if (ep != 0) break;
                        usleep(100000);
                    }
                    uint32_t ver = 0, ddl = 0;
                    mb_rd(task, shm + offsetof(dh_shm_t, version), &ver, 4);
                    mb_rd(task, shm + offsetof(dh_shm_t, dbg_dlopen), &ddl, 4);
                    logts("[collector] %s 内存桥就绪 shm@%#llx ver=%u engine_port=%u dbg_dlopen=%u", nm, (unsigned long long)shm, ver, ep, ddl);
                    if (ep == 0) { continue; }   // 引擎没起 HTTP,下轮再试
                    mb_target_t *t = calloc(1, sizeof *t);
                    strncpy(t->proc, nm, DH_PROC_MAX - 1); t->pid = pid; t->task = task; t->shm = shm;
                    int mslot = dh_daemon_slot(nm);
                    t->lan_port = mslot >= 0 ? (LAN_PORT_BASE + mslot) : (st ? st->lan_port : (LAN_PORT_BASE + g_mb_n));
                    int s = socket(AF_INET, SOCK_STREAM, 0);
                    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
                    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
                    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)t->lan_port); sa.sin_addr.s_addr = INADDR_ANY;
                    if (bind(s, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(s, 16) == 0) {
                        t->lan_fd = s;
                        pthread_t th; if (pthread_create(&th, NULL, mb_lan_thread, t) == 0) pthread_detach(th);
                        pthread_t lt; if (pthread_create(&lt, NULL, mb_log_thread, t) == 0) pthread_detach(lt);   // 引擎日志落盘
                        g_mb[g_mb_n++] = t;   // 登记(含 pid),供重启检测/销毁
                    } else { logts("[collector] %s 内存桥 bind :%d 失败 errno=%d", nm, t->lan_port, errno); close(s); free(t); }
                }
            }
            free(procs);
        }
        sleep(5);
    }
    return NULL;
}

// —— 供聚合 HTTP 模块(collector_http.m)调用的桥接 ——
void dh_log(const char *s) { logts("%s", s); }

// proc 的引擎是否**就绪可连活引擎**(≠仅 companion 活体):内存桥在 g_mb(engine_port 已确认)、
// socket 桥 engine_ready(收到过 DATA=引擎已 dlopen 并 accept)。有则回其 LAN 端口。无锁读:g_mb 结构
// 故意不 free(见 mb_teardown),g_t 槽复用但 proc/标志是良性竞态,索引页用途容忍瞬时不一致。
int dh_bridge_online(const char *proc, int *lan_port) {
    for (int i = 0; i < g_mb_n; i++)
        if (strcmp(g_mb[i]->proc, proc) == 0) { if (lan_port) *lan_port = g_mb[i]->lan_port; return 1; }
    for (int i = 0; i < MAX_TARGETS; i++)
        if (g_t[i].used && g_t[i].engine_ready && strcmp(g_t[i].proc, proc) == 0) { if (lan_port) *lan_port = g_t[i].lan_port; return 1; }
    return 0;
}

// proc 进程当前是否存活(查进程表),返回 pid(0=已退出)。用于区分「进程在但没注入引擎」与「已退出」。
// p_comm 被 MAXCOMLEN(16)截断,用 strncmp。进程表缓存 1 秒:控制台一次刷新对十几个 daemon 各查一次,
// 不缓存就是十几次全进程枚举;缓存后复用一次。
static pthread_mutex_t g_proc_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct kinfo_proc *g_proc_cache = NULL;
static int g_proc_cache_cnt = 0;
static time_t g_proc_cache_t = 0;
int dh_proc_alive(const char *proc) {
    pthread_mutex_lock(&g_proc_cache_lock);
    time_t now = time(NULL);
    if (!g_proc_cache || now != g_proc_cache_t) {   // 1 秒 TTL
        int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 }; size_t len = 0;
        if (sysctl(mib, 4, NULL, &len, NULL, 0) == 0 && len) {
            struct kinfo_proc *np = realloc(g_proc_cache, len);
            if (np) {
                g_proc_cache = np;
                if (sysctl(mib, 4, g_proc_cache, &len, NULL, 0) == 0) { g_proc_cache_cnt = (int)(len / sizeof(struct kinfo_proc)); g_proc_cache_t = now; }
                else g_proc_cache_cnt = 0;
            }
        }
    }
    int pid = 0;
    for (int i = 0; i < g_proc_cache_cnt; i++)
        if (strncmp(g_proc_cache[i].kp_proc.p_comm, proc, MAXCOMLEN) == 0) { pid = g_proc_cache[i].kp_proc.p_pid; break; }
    pthread_mutex_unlock(&g_proc_cache_lock);
    return pid;
}

// 查进程 task 的 suspend_count:>0=被系统挂起(App 转后台后被冻结),0=活跃(前台,或极少数有后台执行权的),
// <0=拿不到(task_for_pid 失败/进程已退)。collector 有 task_for_pid entitlement,第三方 App 可读(实测)。
// 前台判定 / 保持前台 / 前台 App 显示都用它——SBSCopyFrontmostApplicationDisplayIdentifier 在本机恒
// 返回 null(该老 API 失效),suspend_count 是当前可靠的「App 是否在前台」信号。
int dh_task_suspend_count(int pid) {
    if (pid <= 0) return -1;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) return -1;
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(task, MACH_TASK_BASIC_INFO, (task_info_t)&info, &cnt);
    mach_port_deallocate(mach_task_self(), task);
    return (kr == KERN_SUCCESS) ? (int)info.suspend_count : -1;
}

// 按可执行名 kickstart 重启 daemon(companion 随之重新注入)。domain/label 取自 DH_DAEMON_LIST 的
// 硬编码常量(绝不用请求里的 proc 拼命令,只用它 strcmp 匹配白名单;命令参数全是编译期常量,无注入),
// user 域用 uid 501(mobile);collector 是 root,能 kickstart user/501。返回 0 成功。
extern char **environ;
int dh_restart_daemon(const char *proc) {
    const char *dom = NULL, *lbl = NULL;
    #define R(exec, disp, d, l, rst) if (strcmp(proc, exec) == 0) { dom = (d); lbl = (l); }
    DH_DAEMON_LIST(R)
    #undef R
    if (!lbl) return -1;
    char target[128];
    if (strcmp(dom, "system") == 0) snprintf(target, sizeof target, "system/%s", lbl);
    else snprintf(target, sizeof target, "%s/501/%s", dom, lbl);
    const char *tools[] = { "/var/jb/usr/bin/launchctl", "/usr/bin/launchctl", "/bin/launchctl" };
    for (int i = 0; i < 3; i++) {
        if (access(tools[i], X_OK) != 0) continue;
        char *const argv[] = { (char *)tools[i], "kickstart", "-k", target, NULL };
        pid_t pid = 0;
        if (posix_spawn(&pid, tools[i], NULL, NULL, argv, environ) != 0) continue;
        int st = 0;
        if (waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
            logts("[collector] 重启 %s -> %s", proc, target); return 0;
        }
    }
    logts("[collector] 重启 %s 失败(%s)", proc, target);
    return -1;
}

// 白名单 JSON(供聚合控制台列出所有可注入 daemon):[{"proc","disp","domain"}]。静态,建一次。
// disp 都是无引号/反斜杠的中文名,直接内嵌安全。
const char *dh_daemons_json(void) {
    static char buf[4096]; static int built = 0;
    if (!built) {
        int o = 0, first = 1;
        o += snprintf(buf + o, sizeof buf - o, "[");
        #define J(exec, disp, dom, lbl, rst) do { \
            o += snprintf(buf + o, sizeof buf - o, "%s{\"proc\":\"%s\",\"disp\":\"%s\",\"domain\":\"%s\"}", \
                          first ? "" : ",", exec, disp, dom); first = 0; } while (0);
        DH_DAEMON_LIST(J)
        #undef J
        o += snprintf(buf + o, sizeof buf - o, "]");
        built = 1;
    }
    return buf;
}

extern void dh_agg_http_start(void);   // 聚合历史查询 HTTP 服务(collector_http.m),内部起线程即返回

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    { pthread_t mbt; if (pthread_create(&mbt, NULL, mem_bridge_manager, NULL) == 0) pthread_detach(mbt); }
    dh_agg_http_start();   // 聚合口(8089):索引页 + per-daemon 历史重建(死 daemon 仍可富查询)
    unlink(DH_BRIDGE_SOCK);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { logts("[collector] socket 失败 errno=%d", errno); return 1; }
    struct sockaddr_un u; memset(&u, 0, sizeof u); u.sun_family = AF_UNIX;
    strncpy(u.sun_path, DH_BRIDGE_SOCK, sizeof(u.sun_path) - 1);
    if (bind(ls, (struct sockaddr *)&u, sizeof u) != 0) { logts("[collector] bind %s 失败 errno=%d", DH_BRIDGE_SOCK, errno); return 1; }
    chmod(DH_BRIDGE_SOCK, 0777);   // 让沙盒里的 companion 能 connect
    listen(ls, 64);
    logts("[collector] 启动,监听 %s", DH_BRIDGE_SOCK);
    accept_thread((void *)(long)ls);   // 主线程即 accept 循环
    return 0;
}
