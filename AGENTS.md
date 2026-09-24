# AGENTS.md — IOSDecryptHubJB(zhkl0228 fork)

Always respond in Chinese-simplified

> 本仓库是 `decrypthub/IOSDecryptHub` 的 **fork,已有意分叉**。上游那条「加载器与 updater 不得加 hook /
> inline hook,也不得改成常驻型 daemon;hook 全部在引擎里」**约束的是上游那条克制注入链路,本 fork 线 A
> 照守**;但本 fork 面向**专用越狱分析机(崩溃可接受)**——为拿到系统 daemon 里的数据,在**线 B**额外
> **允许 hook 与常驻 daemon**。新会话按下面两条线理解,别再拿上游旧规则来卡线 B。

本仓含两部分:**引擎**(`src/core|hooks|server|ui`,源码在本仓,由 `make` 编译)与**越狱注入链路**
(`src/loader.m` 加载器、`app/` 管理器 App、`daemon/` updater),外加本 fork 的**线 B 组件**
(`src/companion.m`、`daemon/collector*`、`src/dh_frida.c`、`src/dh_unlock.m`)。

## 线 A — App-loader(原始克制路径,保持干净)
ElleKit 把 `IOSDecryptHubLoader.dylib` 装进 UIKit App → 读 `enabledBundles.plist` → 允许则 `dlopen`
引擎 `decrypt_helper.dylib`(由本仓 `src/` 源码编译、落在 `vendor/dylib/<variant>/`)。这条**保持不加
hook、不常驻**(注入面小、稳):**加载器与 updater 不得加 hook/inline hook,也不得改成常驻 daemon;
hook 全在引擎里(`src/hooks/`),由引擎 constructor 完成**——上游这条约束本 fork 线 A 照守。

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
- **引擎**(`decrypt_helper.dylib`):**源码在本仓 `src/`**(core/hooks/server/ui + 内附 fishhook/capstone),
  由 `make VARIANT=rootless/roothide` 编译,产物落 `vendor/dylib/<variant>/`(不入库,由 make 产出)。
  arm64e PAC 已由 `src/core/fishhook.c` 源码原生处理(`__AUTH_CONST` 扫描 + ptrauth strip/re-sign),
  **不再需要二进制 PAC 补丁**(原 `tools/vendor_engine.sh`、`tools/patch_engine_arm64e_pac.py` 已退休删除)。
  版本以 `Makefile` 的 `VERSION` 为准。
- **updater daemon**(`com.iosdecrypthub.updated`):一次性——launchd 按需拉起、跑完即退,只做引擎更新检查/
  安装/回滚,不 hook、不常驻、不监听端口。
- **克制边界(只约束线 A / updater / 引擎注入链路,不约束线 B)**:
  - ❌ **加载器 / updater**里出现 `MSHookFunction` / `%hook` / 常驻 daemon;引擎的 hook 全在 `src/hooks/`。
  - ✅ **线 B 例外**:companion 用 `MSHookFunction`/swizzle、collector 常驻监听端口——见上「线 B」。
- **版本号**:`Makefile` 的 `VERSION`。
- **构建**:`make deb`(源码编引擎 rootless=arm64 / roothide=arm64+arm64e → `build_deb.sh` 打全包)。
