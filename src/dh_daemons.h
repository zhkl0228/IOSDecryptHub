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

// spike 中:除 nsurlsessiond 已端到端验证外,其余为候选,先验 sandbox 是否放行 connect-out
// (companion 注册报活体即通过),通过再逐个验架桥反代。domain/label 取自设备实测
// (多数 daemon uid 501 → user 域;locationd uid 0 → system 域)。
#define DH_DAEMON_LIST(DH_DAEMON) \
    DH_DAEMON("nsurlsessiond",     "网络",              "user",   "com.apple.nsurlsessiond",     "kickstart") \
    DH_DAEMON("apsd",              "推送(APNS)",        "user",   "com.apple.apsd",              "kickstart") \
    DH_DAEMON("identityservicesd", "iMessage/IDS",      "user",   "com.apple.identityservicesd", "kickstart") \
    DH_DAEMON("imagent",           "iMessage",          "user",   "com.apple.imagent",           "kickstart") \
    DH_DAEMON("appstored",         "App Store",         "user",   "com.apple.appstored",         "kickstart") \
    DH_DAEMON("amsaccountsd",      "媒体账户(AMS)",     "user",   "com.apple.amsaccountsd",       "kickstart") \
    DH_DAEMON("akd",               "Apple 账户(AuthKit)","user",  "com.apple.akd",               "kickstart") \
    DH_DAEMON("accountsd",         "账户",              "user",   "com.apple.accountsd",         "kickstart") \
    DH_DAEMON("devicecheckd",      "设备认证",          "user",   "com.apple.devicecheckd",      "kickstart") \
    DH_DAEMON("locationd",         "定位",              "system", "com.apple.locationd",         "kickstart") \
    DH_DAEMON("securityd",         "安全(securityd)",   "system", "com.apple.securityd",         "kickstart") \
    DH_DAEMON("trustd",            "证书信任(trustd)",  "system", "com.apple.trustd",            "kickstart") \
    DH_DAEMON("mobileactivationd", "设备激活",          "system", "com.apple.mobileactivationd", "kickstart") \
    DH_DAEMON("lockdownd",         "锁定(lockdownd)",   "system", "com.apple.mobile.lockdown",   "kickstart")
// securityd/trustd/mobileactivationd/lockdownd:sandbox 禁 network-outbound(连带 mach-lookup),
// socket/mach 出口全封 → 走**内存桥**:companion 注入后 connect collector 不通即自动切内存桥
// (引擎 accept 得真 socketpair,pump 线程搬到 g_dh_shm ring),collector task_for_pid + vm_read/write
// 反读该 ring 并 bind LAN 端口。securityd 已端到端跑通(/api + 139KB WebUI + diag,不崩);见 dh_shm.h。
// 实测坑(2026-09,iPad iOS18.5):
//   * trustd 进程 uid 282,但 launchd 服务在 system 域(非 user/282),label com.apple.trustd。
//   * mobileactivationd 名长 17 > MAXCOMLEN(16),collector 侧 p_comm 会截成 "mobileactivation";
//     mem_bridge_manager 用 strncmp(p_comm, exec, MAXCOMLEN) 定位后,一律改用列表里的完整 exec 名。
//   * lockdownd(/usr/libexec/lockdownd)uid 0、launchd 在 **system 域**、label
//     com.apple.mobile.lockdown(plist 在 /System/Library/LaunchDaemons);此前误标 user/501,
//     kickstart user/501/... 那个服务不存在,pid 不变=没重启。正解 system/com.apple.mobile.lockdown,
//     实测 pid 会变(1669→新)才算真重启,companion 才会重新注入。

// 绝不注入(崩了进不去系统)。companion 自检兜底,与 loader 的 dh_is_blocked 精神一致。
#define DH_DAEMON_HARD_BLOCK(X) \
    X("launchd") X("backboardd") X("SpringBoard") X("dumpster") X("watchdogd")

#endif // DH_DAEMONS_H
