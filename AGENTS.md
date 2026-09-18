# AGENTS.md — IOSDecryptHubJB(zhkl0228 fork)

Always respond in Chinese-simplified

> 本仓库是 `decrypthub/IOSDecryptHub` 的 **fork,已有意分叉**。上游 AGENTS.md 那条
> 「不得加入 hook / inline hook / 常驻 daemon」**只约束上游那个克制产品,不约束本 fork**。
> 本 fork 面向**专用越狱分析机(崩溃可接受)**——为拿到系统 daemon 里的数据,**允许 hook 与常驻 daemon**。
> 新会话按下面两条线理解,别再拿上游旧规则来卡。

## 线 A — App-loader(原始克制路径,保持干净)
ElleKit 把 `IOSDecryptHubLoader.dylib` 装进 UIKit App → 读 `enabledBundles.plist` → 允许则 `dlopen`
`vendor` 里的 `decrypt_helper.dylib`。这条**保持不加 hook、不常驻**(注入面小、稳)。

## 线 B — 系统 daemon 分析(本 fork 扩展,允许 hook + 常驻 daemon)
系统 App 把 crypto/keychain/iMessage E2E/推送都甩给系统 daemon,只有 hook daemon 才拿得到这些数据。故本 fork:
- **companion**(`DHCompanion.dylib`,`Filter → Executables` 注入白名单 daemon):用 **ellekit `MSHookFunction`
  inline hook + ObjC swizzle** 重定向引擎 socket I/O(普通 daemon connect-out 到 collector;严格 daemon 走内存桥)
  + 引擎日志/health hook。→ **本 fork 允许 inline hook / MSHookFunction / swizzle**。
- **collector**(`IOSDecryptHubCollector`,root **常驻 launchd daemon**,RunAtLoad+KeepAlive):按进程名反代出
  LAN 端口(8090+ slot)、内存桥 `task_for_pid`+`vm_read/write`、引擎日志聚合落 `/var/log/dh-<proc>.log`。
  → **本 fork 允许常驻 daemon / 监听端口**。
- 白名单单一来源 `src/dh_daemons.h`;详见 plan `~/.claude/plans/iterative-sprouting-flurry.md` 与聚合方案
  `~/.claude/plans/collector-aggregation-history.md`。

## 通用
- **引擎**(`vendor/dylib/{rootless,roothide}/decrypt_helper.dylib`,闭源):由 `tools/vendor_engine.sh <ver>`
  从上游 release 同步(arm64e 切片自动过 `tools/patch_engine_arm64e_pac.py` 打 PAC 补丁);当前 **1.27.3**。
- **updater daemon**(`com.iosdecrypthub.updated`):一次性——launchd 按需拉起、跑完即退,只做引擎更新检查/安装/回滚,
  不 hook、不常驻、不监听端口。
- **版本号**:`Makefile` 的 `VERSION`。
- **构建**:`make deb`(或 `./build_deb.sh rootless|roothide`)。
