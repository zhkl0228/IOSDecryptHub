// dh_unlock.m — DHUnlock.dylib:注入 SpringBoard 的自动解锁组件(照 zhkl0228 的 rp tweak 实现)
//
// 背景:无密码设备的锁屏 UI dismiss 必须在 SpringBoard 进程内调 SBLockScreenManager 的
//   unlockUIFromSource:(实测外部 daemon 的 SBSUndimScreen/uiopen/MKBUnlockDevice 都只能亮屏、进不了桌面)。
//   故本组件由 ElleKit 按 Filter Bundles=com.apple.springboard 注入 SpringBoard。
//
// 解锁流程严格照 rp.dylib 逆向(IDA:lockStateChanged→tryUnlockDevice__block_invoke),缺一步就不生效:
//   1. 通知回调收到后 dispatch_after 3 秒到【主队列】才动手——等锁屏状态稳定,且 UI 操作必须主线程
//      (曾经在通知回调线程直接裸调 unlockUIFromSource,日志显示"已执行"但 locked 仍为 1,就是没在主线程)。
//   2. 主线程:[SBLockScreenManager sharedInstance] isUILocked → unlockUIFromSource:0 withOptions:nil。
//   3. 再 dispatch_after 2 秒主队列:[UIApplication sharedApplication] setIdleTimerDisabled:YES
//      + [springBoard _returnToHomeScreenWithCompletion:] 回桌面(只解锁不回桌面会停在锁屏下的界面)。
//
// 崩溃教训:绝不在 constructor(dyld initializer)里同步碰 SBLockScreenManager——那时 SpringBoard 未初始化完,
//   +[SBLockScreenManager _sharedInstanceCreateIfNeeded:] 内部 NSAssert 失败→SIGABRT→崩进 Safe Mode。
//   一切对 SBLockScreenManager/UIApplication 的调用都放到主队列(运行期)执行。
//
// 触发条件 = 设了「保持前台」目标(config 的 foregroundKeep 非空):两者绑定——要保持某 App 前台,锁屏就自动解开。
// 通知:
//   com.apple.springboard.lockstate  系统锁屏状态变化 → 若设了 foregroundKeep 则(延迟)自动解锁
//   com.iosdecrypthub.unlock         collector 手动解锁通知(点 web「解锁」即发,无条件解一次)

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CoreFoundation/CoreFoundation.h>
#import <syslog.h>

#define UNLOCK_TAG        "[DHUnlock]"
#define DH_CFG_PATH       @"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"
#define DH_KEY_FGKEEP     @"foregroundKeep"
#define DH_LOCKSTATE_FILE @"/var/jb/tmp/dh_lockstate"   // 写 isUILocked("1"锁/"0"解),供 collector 读给 web 显示

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

// 【主队列】真正解锁 + 回桌面(照 rp tryUnlockDevice)。
static void dh_do_unlock_main(const char *reason) {
    Class cls = objc_getClass("SBLockScreenManager");
    if (!cls) return;
    id mgr = dh_msg0((id)cls, "sharedInstance");
    if (!mgr) return;
    if (!((BOOL (*)(id, SEL))objc_msgSend)(mgr, sel_getUid("isUILocked"))) return;   // 已解锁不动
    ((void (*)(id, SEL, long, id))objc_msgSend)(mgr, sel_getUid("unlockUIFromSource:withOptions:"), 0, nil);
    syslog(LOG_NOTICE, UNLOCK_TAG " unlockUIFromSource:0(主线程,%s)", reason);
    // 2 秒后回桌面 + 关自动锁屏(照 rp)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Class ua = objc_getClass("UIApplication");
        if (!ua) return;
        id app = dh_msg0((id)ua, "sharedApplication");
        if (!app) return;
        ((void (*)(id, SEL, BOOL))objc_msgSend)(app, sel_getUid("setIdleTimerDisabled:"), YES);
        if ([app respondsToSelector:sel_getUid("_returnToHomeScreenWithCompletion:")]) {
            id done = [^{} copy];
            ((void (*)(id, SEL, id))objc_msgSend)(app, sel_getUid("_returnToHomeScreenWithCompletion:"), done);
        }
        syslog(LOG_NOTICE, UNLOCK_TAG " 回桌面 + setIdleTimerDisabled:YES");
    });
    dh_write_lockstate_async();   // 解锁后刷新状态文件
}

// 通知回调 → 延迟 3 秒到【主队列】(照 rp:等锁屏稳定 + UI 必须主线程)。
static void dh_schedule_unlock(const char *reason) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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
    // 初始锁屏状态延迟到主 runloop(SpringBoard 就绪)再写;绝不在此同步碰 SBLockScreenManager。
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        dh_write_lockstate_async();
    });
    syslog(LOG_NOTICE, UNLOCK_TAG " 已装(照 rp:延迟+主线程解锁+回桌面;设了 foregroundKeep 即自动解锁)");
}
