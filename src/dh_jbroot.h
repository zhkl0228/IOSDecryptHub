// dh_jbroot.h — 运行时越狱根探测(rootless / rootful 自适应)。
//
// 背景:本 fork 的 deb 此前只出过 rootless(/var/jb 前缀)与 roothide;现在要支持 rootful
// (无 /var/jb,文件直接装在 /usr/lib/IOSDecryptHub 等真实根路径)。线 B 组件(companion /
// collector / DHUnlock)里大量硬编码 /var/jb/... 在 rootful 上全部失效(实测 collector 因
// bind /var/jb/tmp/dh-bridge.sock 失败 errno=2(目录不存在)而 exit 1,被 launchd KeepAlive
// 无限重启)。故统一在此做运行时探测:
//   /var/jb/usr/lib/IOSDecryptHub 存在 → 根 "/var/jb"(rootless / roothide)
//   否则 /usr/lib/IOSDecryptHub 存在  → 根 ""(rootful,真实根)
//   否则默认 "/var/jb"(未安装时保持现状行为)
// 结果进程级静态缓存;探测期的良性竞争(多线程同刻各探一次)忽略,任一结果都正确。

#ifndef DH_JBROOT_H
#define DH_JBROOT_H

#include <unistd.h>
#include <string.h>
#include <stdio.h>

static inline const char *dh_jbroot(void) {
    static char root[16] = "";
    if (root[0]) return root;
    const char *r;
    if (access("/var/jb/usr/lib/IOSDecryptHub", F_OK) == 0) r = "/var/jb";
    else if (access("/usr/lib/IOSDecryptHub", F_OK) == 0) r = "";   // rootful:真实根
    else r = "/var/jb";                                             // 未安装:保持现状
    strncpy(root, r, sizeof(root) - 1);
    return root;
}

// 拼 <jbroot>/<rel>(rel 须带前导 '/';rootful 时 jbroot 为空串,结果即 "<rel>",无重复斜杠)。
static inline void dh_jb_path(char *buf, size_t n, const char *rel) {
    snprintf(buf, n, "%s%s", dh_jbroot(), rel);
}

#endif // DH_JBROOT_H
