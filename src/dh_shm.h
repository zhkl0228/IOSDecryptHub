// dh_shm.h — 内存桥:严格 daemon(securityd 等)sandbox 全封 socket/mach 出口,
// 但 collector(root+task-port entitlement)能 task_for_pid + vm_read/vm_write 读写其内存。
//
// 思路:companion 在 daemon 内把引擎的 socket I/O 重定向到本结构(g_dh_shm,companion 全局);
// 引擎照常 accept→read 请求→write 响应(以为在 socket 上,实为读写内存)。collector 在外面
// task_for_pid + 扫 DHCompanion 镜像找 magic 定位本结构,vm_write 把 LAN 请求塞进 in 环、
// 轮询 vm_read out 环取响应,在 collector 侧 bind LAN 端口做桥 → http://ip:port 体验不变。
//
// 每条连接两个单生产者单消费者字节环(流式,不必装下整个响应):
//   in : collector 写(生产)/ 引擎读(消费)—— LAN 请求
//   out: 引擎写(生产)/ collector 读(消费)—— HTTP 响应
// head/tail 单调递增(uint32 自然回绕),可用字节 = head - tail,环内偏移 = pos & (RING_SZ-1)。

#ifndef DH_SHM_H
#define DH_SHM_H

#include <stdint.h>

#define DH_SHM_MAGIC   0x44485348u   // 'DHSH'
#define DH_SHM_VERSION 1u
#define DH_RING_SZ     (64u * 1024u) // 必须是 2 的幂
// 并发连接数上限。引擎响应带 Connection: close(每请求用完即释放 conn,不长占),故这里只需覆盖
// **瞬时并发**:浏览器对单 host 默认开 ~6 条并行连接,4 条不够 → 超出的请求抢不到 conn、被
// collector「无空闲 conn」直接关掉,body 空(WebUI 表现为「进程信息不可用」时有时无)。取 16
// 对齐 socket 桥的 POOL_MAX,留足余量。代价:companion 的静态 g_dh_shm ≈ 16×128KB=2MB BSS,
// 对 daemon(设备 2.9GB)可忽略。改此值须 companion 与 collector 一起重建、daemon 重启换新桥。
#define DH_MAX_CONN    16
#define DH_LOG_RING_SZ (256u * 1024u) // 引擎日志聚合环大小,必须是 2 的幂

// 连接状态:collector 与引擎经 vm_read/write 观察对方,靠这些标志推进。
enum {
    DH_CS_FREE    = 0,   // 空闲,collector 可占用
    DH_CS_REQ     = 1,   // collector 已占用并写入请求,等引擎 accept 认领
    DH_CS_SERVING = 2,   // 引擎已认领,正在 serve
};

typedef struct {
    volatile uint32_t state;         // DH_CS_*
    volatile uint32_t in_head;       // collector 生产位置(LAN 请求写入)
    volatile uint32_t in_tail;       // 引擎消费位置
    volatile uint32_t out_head;      // 引擎生产位置(响应写入)
    volatile uint32_t out_tail;      // collector 消费位置
    volatile uint32_t lan_closed;    // collector 侧(LAN)已关
    volatile uint32_t engine_closed; // 引擎侧已关(响应结束)
    volatile uint32_t _pad;
    uint8_t in[DH_RING_SZ];
    uint8_t out[DH_RING_SZ];
} dh_conn_t;

typedef struct {
    volatile uint32_t magic;         // DH_SHM_MAGIC(companion init 时写,collector 扫描定位)
    volatile uint32_t version;       // DH_SHM_VERSION
    volatile uint32_t engine_port;   // 引擎自报的 WebUI 端口(bind 拦到的,信息用)
    volatile uint32_t dbg_enabled;   // [诊断] dh_enabled 结果
    volatile uint32_t dbg_dlopen;    // [诊断] dlopen 引擎结果(1 成功 / 0 失败)
    volatile uint32_t cmd_load;      // collector 置 1 = 让 companion dlopen 引擎架桥
                                     // (严格 daemon 读不了 jb config,由能读 config 的 collector 代为通知)
    volatile uint32_t _pad[2];
    dh_conn_t conn[DH_MAX_CONN];
    // —— 引擎日志聚合(严格 daemon 内存桥)——
    // 严格 daemon 沙盒封 socket,引擎日志走不了 collector 的 UNIX socket;改由 companion 把引擎
    // _logFH 的字节写进这条单向环(log_head 生产),collector vm_read 后落盘 /var/log/dh-<proc>.log
    // (log_tail 消费)。head/tail 单调递增(uint32 回绕),可用 = head - tail,环内偏移 = pos & (SZ-1)。
    // 满时 companion 丢新字节(尽力聚合,不阻塞引擎日志)。
    volatile uint32_t log_head;      // companion 生产位置(写入引擎日志字节)
    volatile uint32_t log_tail;      // collector 消费位置(落盘后前移)
    uint8_t log_ring[DH_LOG_RING_SZ];
} dh_shm_t;

#endif // DH_SHM_H
