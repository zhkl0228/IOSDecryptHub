// DHAppEnumerator.h — 已安装 App 的枚举与图标
//
// 只做两件事：列出用户 App（带显示名与 bundle 路径）、给出图标。
// 图标加载带缓存，供列表滚动时调用。

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

/// 「显示系统 App」开关：存管理器 App 自己的 NSUserDefaults，默认关。
#define DH_SHOW_SYSTEM_APPS_KEY @"dhShowSystemApps"

@interface DHAppInfo : NSObject
@property (nonatomic, copy) NSString *bundleID;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, copy, nullable) NSString *bundlePath;
@property (nonatomic, assign) BOOL isSystem;   // 系统 App（applicationType==System 或 com.apple.* 前缀）
@property (nonatomic, assign) BOOL showInAll;  // 是否出现在「全部」tab；已启用但不符合条件的系统 App 为 NO（只在「已启用」tab 显示）
@end

/// 已安装的 App（按显示名排序）：先走 LaunchServices，失败兜底扫容器目录。
/// includeSystem=NO 只列用户 App；=YES 时并入可注入的系统 App（有 UIKit、可启动的系统应用，
/// 如 App Store / Safari / 设置），但**始终**排除关键进程（见 .m 里的黑名单，如 SpringBoard）。
NSArray<DHAppInfo *> *DHInstalledApps(BOOL includeSystem);

/// 单个 App 的原始图标：先取系统图标缓存，再退回读 bundle 内的图标文件；都可能失败时返回 nil
UIImage *_Nullable DHAppIcon(NSString *bundleID, NSString *_Nullable bundlePath);

/// 列表用图标：圆角（R 角）、固定尺寸、带缓存；取不到图标时返回"首字母"默认图标，绝不空着
UIImage *DHAppListIcon(NSString *bundleID, NSString *_Nullable bundlePath, NSString *_Nullable displayName);

/// 该 App 当前是否在运行（按可执行名匹配；越狱环境下本 App 未沙盒化，可枚举进程）
BOOL DHAppProcessRunning(DHAppInfo *app);
/// 结束该 App 进程；杀掉至少一个返回 YES。rootHide 下 daemon 写不了锁文件，重启必须由本 App 自己做。
BOOL DHKillAppProcess(DHAppInfo *app);
/// 重新打开 App（LaunchServices / SpringBoardServices / uiopen）。成功返回 YES。
BOOL DHRelaunchApp(NSString *bundleID);

/// 分组用索引字母：中文按拼音首字母（如 微信 → W），非字母归到 "#"
NSString *DHAppIndexLetter(NSString *displayName);

NS_ASSUME_NONNULL_END
