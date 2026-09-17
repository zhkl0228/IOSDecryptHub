// dh_bridge.h — companion(被注入的 daemon 内)与 collector(root)之间的桥接协议。
//
// 背景:daemon sandbox 禁 inbound bind(实测 deny network-bind),但放行 outbound
// connect(AF_UNIX)。所以引擎 WebUI 的服务端 socket 由 companion 用 fishhook 重定向成
// 「connect-out 到 collector 的 UNIX socket」,collector 再把它反代成一个 LAN 端口。
//
// 每条 companion→collector 连接开头发一个定长头,collector 据此分派:
//   CONTROL:companion 常驻注册(报活体);连接在 = 该 daemon 在线。
//   DATA   :引擎一次 accept() 产生的数据连接(承载引擎的 HTTP/MCP),collector 池住,
//            有 LAN 客户端时与之裸字节 splice。

#ifndef DH_BRIDGE_H
#define DH_BRIDGE_H

#include <stdint.h>

// collector 监听的 UNIX socket(root 建;sandbox 内 daemon 可 connect,M0 实测 AF_UNIX 出站放行)
#define DH_BRIDGE_SOCK   "/var/jb/tmp/dh-bridge.sock"
#define DH_BRIDGE_MAGIC  0x44484331u   // 'DHC1'

enum {
    DH_CONN_CONTROL = 0,   // 注册/心跳/命令
    DH_CONN_DATA    = 1,   // 引擎一次 accept 的数据连接
    DH_CONN_LOG     = 2,   // 引擎日志字节流:daemon sandbox 写不了任何文件目录,改由 companion
                           // 把引擎的日志 NSFileHandle 接到本连接,collector 落盘 /var/log/dh-<proc>.log
};

// 懒连接握手:companion 的 my_accept 建一条 DATA 连接后**阻塞**读这一个字节,
// collector 只在真有 LAN 客户端要 splice 时才发它。没有它,引擎的 accept 会空转洪泛
// (M0 实测:每次 accept 立即 connect-out,连接池瞬间被短命连接塞满)。收到 go 才代表
// 「这条连接马上有真实 HTTP 请求进来」,引擎随即在该 fd 上正常 serve。
#define DH_BRIDGE_GO  0x67u   // 'g'

#define DH_PROC_MAX 32

struct dh_bridge_hdr {
    uint32_t magic;              // DH_BRIDGE_MAGIC
    uint8_t  type;               // DH_CONN_CONTROL / DH_CONN_DATA
    uint8_t  _pad[3];
    uint32_t pid;                // 被注入进程 pid
    char     proc[DH_PROC_MAX];  // 可执行名(getprogname),NUL 结尾
};

#endif // DH_BRIDGE_H
