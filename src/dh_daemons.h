// dh_daemons.h — 支持注入的系统 daemon 策展白名单(单一来源)。
//
// 一处定义、多处消费:
//   * build_deb.sh 从本文件 grep `DH_DAEMON(` 生成 companion 的 Filter → Executables;
//   * companion 用它做硬白名单校验(只在这些进程里干活);
//   * collector 用它做重启(每个 daemon 的 launchd 域/label/策略各不相同);
//   * manager 用它 + 在线表列「系统进程」。
//
// 每条 DH_DAEMON(exec, display, launchd_domain, launchd_label, restart):
//   exec          可执行名(getprogname / p_comm,注意 MAXCOMLEN=16 截断)
//   display       manager 里显示名
//   launchd_domain "system" | "user" | "gui"(user/gui 需拼 uid,如 user/501)
//   launchd_label  launchd 服务标识,kickstart 用
//   restart        "kickstart" | "sigkill" | "manual"
//
// 加新 daemon = 加一行 + 补它的重启配置,重签 respring。初版仅 nsurlsessiond。

#ifndef DH_DAEMONS_H
#define DH_DAEMONS_H

#define DH_DAEMON_LIST(DH_DAEMON) \
    DH_DAEMON("nsurlsessiond", "网络", "user", "com.apple.nsurlsessiond", "kickstart")

// 绝不注入(崩了进不去系统)。companion 自检兜底,与 loader 的 dh_is_blocked 精神一致。
#define DH_DAEMON_HARD_BLOCK(X) \
    X("launchd") X("backboardd") X("SpringBoard") X("dumpster") X("watchdogd")

#endif // DH_DAEMONS_H
