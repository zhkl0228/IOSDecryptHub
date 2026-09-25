// dh_unlock.m — DHUnlock.dylib:注入 SpringBoard 的自动解锁 + 锁屏组件(照 zhkl0228 的 rp tweak 实现)
//
// 背景:无密码设备的锁屏 UI dismiss 必须在 SpringBoard 进程内调 SBLockScreenManager 的
//   unlockUIFromSource:(实测外部 daemon 的 SBSUndimScreen/uiopen/MKBUnlockDevice 都只能亮屏、进不了桌面)。
//   故本组件由 ElleKit 按 Filter Bundles=com.apple.springboard 注入 SpringBoard。
//
// 解锁流程严格照 rp.dylib 逆向(IDA:lockStateChanged→tryUnlockDevice__block_invoke),缺一步就不生效:
//   1. 通知回调收到后 dispatch_after 1.5 秒到【主队列】才动手——等锁屏状态稳定,且 UI 操作必须主线程(rp 原 3s,收紧到 1.5s)
//      (曾经在通知回调线程直接裸调 unlockUIFromSource,日志显示"已执行"但 locked 仍为 1,就是没在主线程)。
//   2. 主线程:[SBLockScreenManager sharedInstance] isUILocked → unlockUIFromSource:0 withOptions:nil。
//   3. 再 dispatch_after 1 秒主队列:[UIApplication sharedApplication] setIdleTimerDisabled:YES
//      + 模拟按 HOME 键去桌面(只解锁不去桌面会停在锁屏下的界面)。app 即 SpringBoard(UIApplication 子类),
//      调 _simulateHomeButtonPressWithCompletion:(系统合成 HOME 事件,不依赖物理键,Face ID 设备/新系统同样有效;
//      设备 DSC 实证存在),级联兜底 rp 原版的 _returnToHomeScreenWithCompletion:。见 dh_do_unlock_main。
//
// 锁屏(本 fork 扩展,与解锁对称):collector 发 com.iosdecrypthub.lock → 主队列调
//   [SBLockScreenManager sharedInstance] lockUIFromSource:withOptions:(unlockUIFromSource:withOptions: 的对称方法,
//   设备 DSC 实证存在),级联兜底 [SpringBoard _simulateLockButtonPress](模拟锁定键,兼锁屏+息屏)。见 dh_do_lock_main。
//   web 面板据锁屏态把按钮在「解锁/亮屏」与「锁屏」之间切换。
//
// 崩溃教训:绝不在 constructor(dyld initializer)里同步碰 SBLockScreenManager——那时 SpringBoard 未初始化完,
//   +[SBLockScreenManager _sharedInstanceCreateIfNeeded:] 内部 NSAssert 失败→SIGABRT→崩进 Safe Mode。
//   一切对 SBLockScreenManager/UIApplication 的调用都放到主队列(运行期)执行。
//
// 触发条件 = 设了「保持前台」目标(config 的 foregroundKeep 非空):两者绑定——要保持某 App 前台,锁屏就自动解开。
// 通知:
//   com.apple.springboard.lockstate  系统锁屏状态变化 → 若设了 foregroundKeep 则(延迟)自动解锁
//   com.iosdecrypthub.unlock         collector 手动解锁通知(点 web「解锁」即发,无条件解一次)
//   com.iosdecrypthub.lock           collector 手动锁屏通知(点 web「锁屏」即发,无条件锁一次)
//   com.iosdecrypthub.home           collector 手动回桌面通知(点 web「回桌面」即发,按一次 HOME;仅解锁时)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CoreFoundation/CoreFoundation.h>
#import <syslog.h>

#define UNLOCK_TAG        "[DHUnlock]"
#define DH_CFG_PATH       @"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"
#define DH_KEY_FGKEEP     @"foregroundKeep"
#define DH_LOCKSTATE_FILE @"/var/jb/tmp/dh_lockstate"   // 写 isUILocked("1"锁/"0"解),供 collector 读给 web 显示
#define DH_FRONTMOST_FILE @"/var/jb/tmp/dh_frontmost"   // 写真 frontmost App 的 bundle id(空=桌面/无),供 collector 读

static dispatch_source_t g_fg_timer;   // 前台 App 查询定时器(主队列)

static inline id dh_msg0(id obj, const char *sel) {
    return ((id (*)(id, SEL))objc_msgSend)(obj, sel_getUid(sel));
}

// 是否设了「保持前台」目标(foregroundKeep 非空)。读不到一律当未设——默认沉默,绝不擅自解锁。
static BOOL dh_fgkeep_set(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:DH_CFG_PATH];
    id v = d[DH_KEY_FGKEEP];
    return [v isKindOfClass:[NSString class]] && [v length] > 0;
}

// 【主队列】读锁屏状态写文件(SBLockScreenManager 只读,放主线程最稳)。
static void dh_write_lockstate_async(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        Class cls = objc_getClass("SBLockScreenManager");
        BOOL locked = NO;
        if (cls) {
            id mgr = dh_msg0((id)cls, "sharedInstance");
            if (mgr) locked = ((BOOL (*)(id, SEL))objc_msgSend)(mgr, sel_getUid("isUILocked"));
        }
        [(locked ? @"1" : @"0") writeToFile:DH_LOCKSTATE_FILE atomically:YES encoding:NSUTF8StringEncoding error:nil];
    });
}

// 【主队列】查真正的前台 App(SpringBoard 内部 frontmost)写文件供 collector 用。
// 为什么不让 collector 用 suspend_count 猜:VPN 等有后台执行权的 App 长期 suspend_count=0、且 App 切后台后
// iOS 有几十秒挂起宽限期 suspend_count 才变——都会误判前台(实测同时误报 InspectorVpn/Safari)。
// _accessibilityFrontMostApplication 是 SpringBoard 的真 frontmost:唯一、前后台切换即时准确。桌面/锁屏返回 nil。
static void dh_write_frontmost(void) {
    Class ua = objc_getClass("UIApplication");
    if (!ua) return;
    id app = dh_msg0((id)ua, "sharedApplication");
    if (!app) return;
    NSString *bid = @"";
    SEL sel = sel_getUid("_accessibilityFrontMostApplication");
    static int logged = 0;
    if (!logged) { syslog(LOG_NOTICE, UNLOCK_TAG " _accessibilityFrontMostApplication resp=%d", [app respondsToSelector:sel]); logged = 1; }
    if ([app respondsToSelector:sel]) {
        id sb = ((id (*)(id, SEL))objc_msgSend)(app, sel);
        if (sb) {
            id b = dh_msg0(sb, "bundleIdentifier");
            if ([b isKindOfClass:[NSString class]]) bid = b;
        }
    }
    [bid writeToFile:DH_FRONTMOST_FILE atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

// 【主队列】模拟按 HOME 键去桌面。用 SpringBoard(app 即 UIApplication 子类)的
// _simulateHomeButtonPressWithCompletion::由系统合成 HOME 事件,不依赖物理 HOME 键——无物理键(Face ID)
// 设备与新系统一样有效(设备 DSC 实证存在);前台 App 走标准 进入后台/挂起 生命周期、转场系统原生。
// 级联兜底 _returnToHomeScreenWithCompletion:(rp 原版程序化回主屏,同样通用)。两条都打 NOTICE 记走哪条;
// 两者都探不到才 LOG_ERR(fail-loud)。解锁流程与 web「回桌面」按钮共用。
static void dh_press_home_main(const char *reason) {
    Class ua = objc_getClass("UIApplication");
    if (!ua) return;
    id app = dh_msg0((id)ua, "sharedApplication");
    if (!app) return;
    SEL simHome = sel_getUid("_simulateHomeButtonPressWithCompletion:");
    SEL retHome = sel_getUid("_returnToHomeScreenWithCompletion:");
    if ([app respondsToSelector:simHome]) {
        id done = [^{} copy];
        ((void (*)(id, SEL, id))objc_msgSend)(app, simHome, done);
        syslog(LOG_NOTICE, UNLOCK_TAG " 模拟按 HOME 键(_simulateHomeButtonPressWithCompletion:,%s)", reason);
    } else if ([app respondsToSelector:retHome]) {
        id done = [^{} copy];
        ((void (*)(id, SEL, id))objc_msgSend)(app, retHome, done);
        syslog(LOG_NOTICE, UNLOCK_TAG " 回主屏(_returnToHomeScreenWithCompletion:;无 HOME 模拟,%s)", reason);
    } else {
        syslog(LOG_ERR, UNLOCK_TAG " 无 _simulateHomeButtonPressWithCompletion:/_returnToHomeScreenWithCompletion:"
                        "(respondsToSelector 均 0)——该系统需换回主屏 API,HOME(%s)未触发", reason);
    }
}

// 【主队列】真正解锁 + 按 HOME 键去桌面(解锁步骤照 rp tryUnlockDevice;去桌面本 fork 改为模拟 HOME 键)。
static void dh_do_unlock_main(const char *reason) {
    Class cls = objc_getClass("SBLockScreenManager");
    if (!cls) return;
    id mgr = dh_msg0((id)cls, "sharedInstance");
    if (!mgr) return;
    if (!((BOOL (*)(id, SEL))objc_msgSend)(mgr, sel_getUid("isUILocked"))) return;   // 已解锁不动
    ((void (*)(id, SEL, long, id))objc_msgSend)(mgr, sel_getUid("unlockUIFromSource:withOptions:"), 0, nil);
    syslog(LOG_NOTICE, UNLOCK_TAG " unlockUIFromSource:0(主线程,%s)", reason);
    // 1 秒后关自动锁屏 + 模拟按 HOME 键去桌面(只解锁不去桌面会停在锁屏下的界面)。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class ua = objc_getClass("UIApplication");
        id app = ua ? dh_msg0((id)ua, "sharedApplication") : nil;
        if (app) ((void (*)(id, SEL, BOOL))objc_msgSend)(app, sel_getUid("setIdleTimerDisabled:"), YES);
        dh_press_home_main("unlock");
    });
    dh_write_lockstate_async();   // 解锁后刷新状态文件
}

// 是否已锁(SBLockScreenManager isUILocked;拿不到 mgr 返回 -1)。
static int dh_is_ui_locked(void) {
    Class cls = objc_getClass("SBLockScreenManager");
    id mgr = cls ? dh_msg0((id)cls, "sharedInstance") : nil;
    if (!mgr) return -1;
    return ((BOOL (*)(id, SEL))objc_msgSend)(mgr, sel_getUid("isUILocked")) ? 1 : 0;
}

// 【主队列】真正锁屏。实测(设备日志)SBLockScreenManager lockUIFromSource:withOptions: 虽 respondsToSelector=YES
// 且被调用,但在 iOS 18.5 上**不触发真正锁屏**(isUILocked 仍 0),它只管锁屏 UI 内部来源标记,不锁设备。
// 故主用 [SpringBoard _simulateLockButtonPress](模拟侧边/电源键单击 → 真锁屏+息屏,任何设备都有此键;DSC 实证),
// lockUIFromSource:withOptions: 退为兜底。都 respondsToSelector 守卫;两者都无才 LOG_ERR(fail-loud)。
// 调用后 1.5s 校验 isUILocked 是否真锁上——调了却没锁也 LOG_ERR(拿样本:该方法在本系统无效,需再换 API)。
static void dh_do_lock_main(const char *reason) {
    if (dh_is_ui_locked() == 1) return;   // 已锁不动
    Class ua = objc_getClass("UIApplication");
    id app = ua ? dh_msg0((id)ua, "sharedApplication") : nil;
    Class cls = objc_getClass("SBLockScreenManager");
    id mgr = cls ? dh_msg0((id)cls, "sharedInstance") : nil;
    SEL simLock = sel_getUid("_simulateLockButtonPress");
    SEL lockSel = sel_getUid("lockUIFromSource:withOptions:");
    const char *used;
    if (app && [app respondsToSelector:simLock]) {
        ((void (*)(id, SEL))objc_msgSend)(app, simLock);
        used = "_simulateLockButtonPress";
    } else if (mgr && [mgr respondsToSelector:lockSel]) {
        ((void (*)(id, SEL, long, id))objc_msgSend)(mgr, lockSel, 0, nil);   // source 沿用解锁的 0
        used = "lockUIFromSource:0";
    } else {
        syslog(LOG_ERR, UNLOCK_TAG " 无 _simulateLockButtonPress/lockUIFromSource:withOptions:"
                        "(respondsToSelector 均 0)——该系统需换锁屏 API,锁屏本次未触发");
        return;
    }
    syslog(LOG_NOTICE, UNLOCK_TAG " 锁屏调用 %s(主线程,%s)", used, reason);
    // 1.5s 后校验是否真锁上 + 刷新状态文件。fail-loud:调了却没锁,把实况打出来好换 API。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        int locked = dh_is_ui_locked();
        dh_write_lockstate_async();
        if (locked == 1) syslog(LOG_NOTICE, UNLOCK_TAG " 锁屏成功(%s 后 isUILocked=1)", used);
        else syslog(LOG_ERR, UNLOCK_TAG " 锁屏无效:%s 调用后 isUILocked=%d(≠1)——该方法在本系统不锁设备,需换锁屏 API", used, locked);
    });
}

// 通知回调 → 延迟 1.5 秒到【主队列】(等锁屏状态稳定 + UI 必须主线程;rp 原用 3s,本 fork 收紧到 1.5s)。
static void dh_schedule_unlock(const char *reason) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        dh_do_unlock_main(reason);
    });
}

// 系统锁屏状态变化:记录状态供 web 显示;设了保持前台目标才(延迟)自动解锁。
static void lockstate_cb(CFNotificationCenterRef center, void *observer,
                         CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dh_write_lockstate_async();
    if (!dh_fgkeep_set()) return;
    dh_schedule_unlock("lockstate+fgKeep");
}
// collector 手动解锁通知:点了 web「解锁」即解,无条件解一次。
static void manual_cb(CFNotificationCenterRef center, void *observer,
                      CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dh_schedule_unlock("manual");
}
// collector 手动锁屏通知:点了 web「锁屏」即锁,无条件锁一次。锁屏不需等状态稳定,直接上主队列(UI 必须主线程)。
static void manual_lock_cb(CFNotificationCenterRef center, void *observer,
                           CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dispatch_async(dispatch_get_main_queue(), ^{ dh_do_lock_main("manual"); });
}
// collector 手动回桌面通知:点了 web「回桌面」即按一次 HOME。仅解锁时有意义(collector 侧已按锁屏态拒/隐藏)。
static void manual_home_cb(CFNotificationCenterRef center, void *observer,
                           CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dispatch_async(dispatch_get_main_queue(), ^{ dh_press_home_main("manual"); });
}

__attribute__((constructor))
static void dh_unlock_init(void) {
    // Filter 已限定只注入 SpringBoard;再确认进程名,非 SpringBoard 直接不注册(双保险)。
    const char *pn = getprogname();
    if (!pn || strcmp(pn, "SpringBoard") != 0) return;
    CFNotificationCenterRef dc = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationCenterAddObserver(dc, NULL, lockstate_cb,
        CFSTR("com.apple.springboard.lockstate"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(dc, NULL, manual_cb,
        CFSTR("com.iosdecrypthub.unlock"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(dc, NULL, manual_lock_cb,
        CFSTR("com.iosdecrypthub.lock"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(dc, NULL, manual_home_cb,
        CFSTR("com.iosdecrypthub.home"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    // 初始锁屏状态延迟到主 runloop(SpringBoard 就绪)再写;绝不在此同步碰 SBLockScreenManager。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        dh_write_lockstate_async();
    });
    // 前台 App:主队列定时(每 1s,5s 后启动等 SpringBoard 就绪)查真 frontmost 写文件。轻量(一次 msgSend+写小文件),
    // 换来准确即时(取代 collector 用 suspend_count 猜——那对 VPN 类后台常驻 App 和切后台宽限期都会误判)。
    g_fg_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(g_fg_timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                              (uint64_t)(1 * NSEC_PER_SEC), (uint64_t)(200 * NSEC_PER_MSEC));
    dispatch_source_set_event_handler(g_fg_timer, ^{ dh_write_frontmost(); });
    dispatch_resume(g_fg_timer);
    syslog(LOG_NOTICE, UNLOCK_TAG " 已装(照 rp:延迟+主线程解锁+按 HOME 键去桌面;可手动锁屏;设了 foregroundKeep 即自动解锁;前台查询已启)");
}
