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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../src/dh_bridge.h"
#include "../src/dh_daemons.h"

#define MAX_TARGETS   32
#define LAN_PORT_BASE 8090
#define POOL_MAX      16

typedef struct {
    char  proc[DH_PROC_MAX];
    int   used;
    int   online;
    int   lan_port;
    int   lan_fd;                 // LAN 监听 fd,-1 未绑
    int   pool[POOL_MAX];         // 池住的引擎数据连接 fd
    int   pool_n;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
} target_t;

static target_t g_t[MAX_TARGETS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void logts(const char *fmt, ...) {
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
        t->lan_port = LAN_PORT_BASE + (int)(t - g_t);
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
static void *log_reader(void *arg) {
    void **pair = arg; int fd = (int)(long)pair[0]; char *proc = pair[1]; free(pair);
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
    char path[128];
    snprintf(path, sizeof path, "/var/log/dh-%s.log", safe);
    int out = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (out < 0) { logts("[collector] 日志文件打开失败 %s errno=%d", path, errno); close(fd); return NULL; }
    logts("[collector] %s 日志落盘 -> %s", safe, path);
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
    pthread_mutex_lock(&g_lock); t->online = 0; pthread_mutex_unlock(&g_lock);
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
        } else if (h.type == DH_CONN_LOG) {
            // 引擎日志字节流:起线程落盘 /var/log/dh-<proc>.log(daemon 自己写不了文件)。
            void **pair = malloc(2 * sizeof(void *)); pair[0] = (void *)(long)c; pair[1] = strdup(h.proc);
            pthread_t th;
            if (pthread_create(&th, NULL, log_reader, pair) == 0) pthread_detach(th);
            else { close(c); free(pair[1]); free(pair); }
        } else { // DATA
            target_ensure_lan(t);
            pthread_mutex_lock(&t->lock);
            if (t->pool_n < POOL_MAX) { t->pool[t->pool_n++] = c; pthread_cond_signal(&t->cond); logts("[collector] %s DATA 入池 pool_n=%d", h.proc, t->pool_n); pthread_mutex_unlock(&t->lock); }
            else { pthread_mutex_unlock(&t->lock); logts("[collector] %s DATA 池满丢弃", h.proc); close(c); }
        }
    }
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
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
