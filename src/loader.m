// loader.m — IOSDecryptHub 越狱注入加载器
//
// 由 rootless 环境的 ElleKit 加载到 UIKit App（Filter: com.apple.UIKit）。
// 唯一职责：读取偏好设置 → 判断当前 App 是否启用 → dlopen 主 dylib。
// 不包含任何 hook 逻辑。hook 全部由主 dylib 的 constructor 完成。
//
// rootless 路径：
//   /var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <syslog.h>
#import <pthread.h>
#import <unistd.h>
#import <string.h>
#import "dh_bridge.h"   // struct dh_app_reg / DH_APP_REG_MAGIC(collector task_for_pid + vm_read 读)

#define LOADER_TAG      "[IOSDecryptHub]"
#define PREFS_DOMAIN    @"com.iosdecrypthub.loader"
#define PREFS_KEY       @"enabledBundles"
#define PREFS_PATH      @"/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
#define ENGINE_REL      @"usr/lib/IOSDecryptHub/decrypt_helper.dylib"
#define CONFIG_REL      @"usr/lib/IOSDecryptHub/config/enabledBundles.plist"

// 不依赖 /var/jb，也不用 access()/fileExists 探路（宿主沙盒会谎称不存在）。
// loader 实际可能在：
//   <jb>/Library/MobileSubstrate/DynamicLibraries/  （本包安装位置，向上 4 级到 jbroot）
//   <jb>/usr/lib/TweakInject/                       （ElleKit 加载位置，同样向上 4 级）
// 旧逻辑只向上 2 级再拼 IOSDecryptHub/…，仅 TweakInject 布局碰巧正确。
static void dh_add_unique(NSMutableArray<NSString *> *paths, NSString *path) {
    if (path.length && ![paths containsObject:path]) [paths addObject:path];
}

static NSArray<NSString *> *dh_paths_from_loader(NSString *relativeToJbroot) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    Dl_info info = {0};
    if (dladdr((const void *)&dh_paths_from_loader, &info) != 0 && info.dli_fname) {
        NSString *cur = [NSString stringWithUTF8String:info.dli_fname];
        for (int i = 0; i < 4 && cur.length > 1; i++) {
            cur = [cur stringByDeletingLastPathComponent];
        }
        if (cur.length > 1) {
            dh_add_unique(paths, [cur stringByAppendingPathComponent:relativeToJbroot]);
        }
        // 兼容 TweakInject：向上 2 级 = usr/lib，相对路径去掉 usr/lib/ 前缀
        NSString *loaderPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *usrLib = [[loaderPath stringByDeletingLastPathComponent]
            stringByDeletingLastPathComponent];
        if ([relativeToJbroot hasPrefix:@"usr/lib/"] && usrLib.length > 1) {
            dh_add_unique(paths, [usrLib stringByAppendingPathComponent:
                [relativeToJbroot substringFromIndex:8]]);
        }
    }
    dh_add_unique(paths, [@"/var/jb/" stringByAppendingString:relativeToJbroot]);
    return paths;
}

static NSArray<NSString *> *dh_dylib_candidates(void) {
    return dh_paths_from_loader(ENGINE_REL);
}

static NSArray<NSString *> *dh_config_candidates(void) {
    return dh_paths_from_loader(CONFIG_REL);
}

// 说明：曾短暂加过"我们自己的组件不注入"的特例（想让管理器 App 里不弹悬浮窗），
// 已撤销 —— 用户反馈里看到的悬浮窗真正原因是"开关被打开了"，不是产品行为异常。
// 开关语义保持处处一致：列在名单里的 App 就会被注入，没有例外。
// 相关：管理器 App 与设置面板同样出现在列表里，可以被显式打开（例如当服务宿主用）。

// 绝不注入的关键进程（与管理器枚举的 dh_enum_blocked 保持一致）。
// SpringBoard 是桌面进程：注入引擎会 respring 循环，且用户无法从管理器界面把它关回来。
// 这类进程即便被写进名单也一律拒绝。
static BOOL dh_is_blocked(NSString *bundleID) {
    static NSString *const blocked[] = { @"com.apple.springboard" };
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        if ([bundleID caseInsensitiveCompare:blocked[i]] == NSOrderedSame) return YES;
    }
    return NO;
}

// 读取偏好：判断当前 bundleID 是否在启用列表中
static BOOL dh_should_inject(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return NO;

    // 只挡关键进程黑名单，其余一律按名单判断。
    // 原先这里整片跳过 com.apple.*，导致系统 App 永远无法注入；为支持「设置里勾选系统 App」
    // 而放开——代价是所有 UIKit 系统进程启动时会多读一次名单 plist（开销极小）。
    if (dh_is_blocked(bundleID)) return NO;

    NSArray *enabled = nil;
    const char *source = "none";
    @try {
        // prefs 读到数组（含空数组=全关）就用。沙盒目标通常读不到这份文件，
        // 再回退 jb 配置；禁止在宿主进程里 Synchronize 此外域。
        NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
        enabled = prefs[PREFS_KEY];
        if ([enabled isKindOfClass:[NSArray class]]) {
            source = "prefs";
        } else {
            CFPropertyListRef value = CFPreferencesCopyAppValue(
                (__bridge CFStringRef)PREFS_KEY,
                (__bridge CFStringRef)PREFS_DOMAIN);
            enabled = CFBridgingRelease(value);
            if ([enabled isKindOfClass:[NSArray class]]) {
                source = "cfprefs";
            } else {
                for (NSString *configPath in dh_config_candidates()) {
                    prefs = [NSDictionary dictionaryWithContentsOfFile:configPath];
                    enabled = prefs[PREFS_KEY];
                    if ([enabled isKindOfClass:[NSArray class]]) {
                        source = "jb";
                        break;
                    }
                }
            }
        }
    } @catch (__unused NSException *exception) {
        return NO;
    }
    if (!enabled || ![enabled isKindOfClass:[NSArray class]]) return NO;
    BOOL hit = [enabled containsObject:bundleID];
    if (hit) {
        syslog(LOG_NOTICE, LOADER_TAG " 将注入 %s source=%s",
               bundleID.UTF8String, source);
    }
    return hit;
}

// App 注册信息全局(collector task_for_pid + vm_read 定位读)。App 沙盒禁 connect collector socket,故不主动
// 上报,而是把信息留在自己内存里由 collector 反读——比端口扫描完整(后台被挂起的 App 内存也可读)。
// used 属性防被优化掉;放 loader 镜像里,collector 扫 IOSDecryptHubLoader 镜像的 magic 定位。
struct dh_app_reg g_dh_app_reg __attribute__((used));

// dlopen 引擎后:等 dh_http_port() 就绪(引擎 HTTP server 异步 bind)→ 填 g_dh_app_reg(bundle/port/pid,
// 最后置 magic)。引擎版本无导出 getter,留空由 collector 用 ENGINE_VER。
static void *dh_app_reg_fill(void *arg) {
    void *handle = arg;
    int (*port_fn)(void) = (int (*)(void))dlsym(handle, "dh_http_port");
    uint32_t port = 0;
    for (int i = 0; i < 120; i++) {   // ≤12s 等 bind
        if (port_fn) port = (uint32_t)port_fn();
        if (port) break;
        usleep(100000);
    }
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    strncpy(g_dh_app_reg.bundle, bid.UTF8String ?: "", sizeof(g_dh_app_reg.bundle) - 1);
    g_dh_app_reg.port = port;
    g_dh_app_reg.pid = (uint32_t)getpid();
    __sync_synchronize();
    g_dh_app_reg.magic = DH_APP_REG_MAGIC;   // 最后置:collector 扫到 magic 时其余字段已写好
    return NULL;
}

__attribute__((constructor))
static void dh_loader_init(void) {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        // 默认不注入任何 App —— 只有用户在设置中明确开启的才注入
        if (!dh_should_inject(bundleID)) {
            return;
        }

        // 不先用 access() 探测：宿主沙盒可能拒绝路径查询，但 dyld 仍可加载由越狱
        // 注入框架授权的镜像。逐个 dlopen 才能得到真实结果。
        for (NSString *dylibPath in dh_dylib_candidates()) {
            syslog(LOG_INFO, LOADER_TAG " 注入 %s → %s",
                   bundleID.UTF8String, dylibPath.UTF8String);
            void *handle = dlopen(dylibPath.fileSystemRepresentation, RTLD_NOW);
            if (handle) {
                // 注入成功 → 起线程填 g_dh_app_reg(端口就绪后),供 collector vm_read 发现「已注入」+端口/版本。
                pthread_t th;
                if (pthread_create(&th, NULL, dh_app_reg_fill, handle) == 0) pthread_detach(th);
                return;
            }
        }
        syslog(LOG_ERR, LOADER_TAG " 主 dylib 加载失败 (%s): %s",
               bundleID.UTF8String, dlerror() ?: "unknown error");
    }
}
