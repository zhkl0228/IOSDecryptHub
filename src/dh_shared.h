// dh_shared.h — 管理器 App 与 updater daemon 的共享约定
//
// 单一事实源（两边只认这些路径与键，不各自发明）：
//   名单: 管理器写 /var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist
//         （App 一定写得动）以及 cfprefsd 域 com.iosdecrypthub.loader / enabledBundles
//         沙盒目标进程读不到这份 prefs，必须再有一份 jb 配置：
//         <bootstrap>/usr/lib/IOSDecryptHub/config/enabledBundles.plist
//         rootless 上 App 可直接写 jb；rootHide 上 App/daemon Mach-O 对 /usr/lib 是
//         EPERM，由 updated.sh（launchd 的 /bin/sh）把 prefs 拷过去。
//         loader：prefs 读到数组就用；读不到再回退 jb。空数组=全关。
//   引擎: <bootstrap>/usr/lib/IOSDecryptHub/decrypt_helper.dylib
//         由 dpkg 安装；OTA 时 Mach-O 下载到 DH_STAGE_DIR，updated.sh（launchd 的 /bin/sh）落位。
//   元信息: <bootstrap>/usr/lib/IOSDecryptHub/version.plist              {version, variant, arch}
//   状态: DH_STATE_PATH（mobile 可写）；引擎目录里的 state.plist 仅作 rootless 兼容镜像
//   请求: DH_REQUEST_PATH
//         (mobile 可写，daemon 读；launchd 用 WatchPaths 监听它；内容不可信，
//          daemon 只取 action 与可选的 version —— 下载地址一律自己按发布命名约定
//          推导，绝不采用请求里的地址)
//         action: check / install / rollback / restart / stop / set-enabled / none
//         version: 可选，指定要安装的版本（历史版本），如 "1.25.1"
//         bundle:  可选，restart / stop 要操作的 App（bundle id）
//                  restart = 结束进程并尽量重新打开；stop = 只结束进程
//         enabledBundles: set-enabled 时的完整名单（字符串数组；内容不可信，daemon 只收 NSString）

#define DH_DOMAIN_LOADER  @"com.iosdecrypthub.loader"
#define DH_KEY_BUNDLES    @"enabledBundles"
// 系统 daemon 注入名单(按可执行名,非 bundleId)。与 enabledBundles 同存一份 plist:
//   manager 写、companion(注入进 daemon 侧)读。daemon 没有 bundleId,只能按 exec 名门控。
#define DH_KEY_EXECS      @"enabledExecutables"

// 相对 bootstrap 根目录。旧值少了 usr/lib/，App 会写到 <jbroot>/IOSDecryptHub/...，
// 开关表现为「写入启用名单失败」。
#define DH_CONFIG_REL     @"usr/lib/IOSDecryptHub/config/enabledBundles.plist"
#define DH_ENGINE_NAME    @"decrypt_helper.dylib"
#define DH_ENGINE_BAK     @"decrypt_helper.dylib.bak"
#define DH_ENGINE_NEW     @"decrypt_helper.dylib.new"
#define DH_BAK_META       @"decrypt_helper.dylib.bak.plist"
#define DH_VERSION_FILE   @"version.plist"
#define DH_STATE_FILE     @"state.plist"

#define DH_REQUEST_PATH   @"/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist"
// roothide 下 App 对 /var/mobile 的原子写可能被容器映射/权限挡住；jb config 是
// App 一定可写的路径。App 双写，updated.sh 在启动 daemon 前把它转交到 DH_REQUEST_PATH。
#define DH_REQUEST_JB_REL @"usr/lib/IOSDecryptHub/config/updater.request.plist"
// App 自己的共享缓存目录（postinst 已 chown mobile + 0777），是 roothide 下
// 最可靠的请求投递点；launchd 监听它，updated.sh 转交到 DH_REQUEST_PATH。
#define DH_REQUEST_CACHE_PATH @"/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist"
#define DH_LOADER_PREFS   @"/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
#define DH_STATE_PATH     @"/var/mobile/Library/Preferences/com.iosdecrypthub.updater.state.plist"
#define DH_LOCK_PATH      @"/var/mobile/Library/Preferences/com.iosdecrypthub.updated.lock"
#define DH_STAGE_DIR      @"/var/mobile/Library/Caches/com.iosdecrypthub"
#define DH_JB_LOCK_REL    @"var/log/com.iosdecrypthub.updated.lock"
#define DH_JB_STATE_REL   @"var/log/com.iosdecrypthub.updater.state.plist"
#define DH_JB_STAGE_REL   @"var/cache/com.iosdecrypthub"
#define DH_NOTIFY_STATE   @"com.iosdecrypthub.updater.state"

// 更新来源：先走 releases/latest 的 302 拿 tag（不耗 GitHub API 配额，共享出口/VPN
// 用户不会莫名被 403 掐掉），资产地址按发布流程的命名约定拼；命名变化时由 API 兜底。
#define DH_RELEASE_LATEST @"https://github.com/decrypthub/IOSDecryptHub/releases/latest"
#define DH_ASSET_FMT      @"https://github.com/decrypthub/IOSDecryptHub/releases/download/%@/decrypt_helper-%@.dylib"
// 兜底：API 能拿到资产列表，容忍引擎改名
#define DH_GITHUB_LATEST  @"https://api.github.com/repos/decrypthub/IOSDecryptHub/releases/latest"

#define DH_REQ_CHECK      @"check"
#define DH_REQ_INSTALL    @"install"
#define DH_REQ_ROLLBACK   @"rollback"
#define DH_REQ_RESTART    @"restart"
#define DH_REQ_STOP       @"stop"
#define DH_REQ_SET_ENABLED @"set-enabled"
// rootHide 兜底:App 写不动 jb 的 enabledExecutables 时投这个请求,daemon 落盘(见 daemon)
#define DH_REQ_SET_EXECS  @"set-execs"
#define DH_REQ_NONE       @"none"
