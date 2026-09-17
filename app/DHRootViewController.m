// DHRootViewController.m — 主界面：管理与查看注入的 App
//
// 设计取向（按使用逻辑，不按实现）：
//   - 打开就是"我开了哪些 App"；顶部可过滤出「已启用」
//   - 全部应用按首字母分组，右侧有快速导航索引（中文按拼音首字母）
//   - 每行只有图标（R 角）+ 名称 + 开关；取不到图标时用首字母默认图标，绝不空着
//   - 提示文案只留一句真正需要用户做动作的

#import "DHRootViewController.h"
#import "DHSettingsViewController.h"
#import "DHConfigStore.h"
#import "DHAppEnumerator.h"

typedef NS_ENUM(NSInteger, DHFilter) {
    DHFilterAll = 0,
    DHFilterEnabled,
    DHFilterDaemons,   // 系统进程（daemon）
};

@interface DHRootViewController () <UISearchResultsUpdating>
@property (nonatomic, copy) NSArray<DHAppInfo *> *allApps;
@property (nonatomic, copy) NSArray<DHAppInfo *> *daemons;              // dh_daemons.h 策展的系统 daemon
@property (nonatomic, strong) NSMutableSet<NSString *> *enabled;        // enabledBundles(App)
@property (nonatomic, strong) NSMutableSet<NSString *> *enabledExecs;   // enabledExecutables(daemon)
@property (nonatomic, copy) NSArray<NSArray<DHAppInfo *> *> *sections;
@property (nonatomic, copy) NSArray<NSString *> *sectionHeaders;
@property (nonatomic, copy) NSArray<NSString *> *sectionIndexes;
@property (nonatomic, copy) NSArray<DHAppInfo *> *matched;
@property (nonatomic, strong) UISearchController *search;
@property (nonatomic, strong) UISegmentedControl *filter;
@property (nonatomic, assign) BOOL searching;
@property (nonatomic, assign) BOOL enabledOnly;
@property (nonatomic, copy, nullable) NSString *freshLatest;   // App 自己刚查到的线上版本
@property (nonatomic, strong) NSMutableArray<NSString *> *pendingRestart;   // 改了开关但还没重启的 App
@property (nonatomic, copy) NSDictionary<NSString *, NSDictionary *> *injected;  // 本机 8088 探测到的已注入 App
@property (nonatomic, strong) NSTimer *pollTimer;   // 前台时定期重扫注入状态
@property (nonatomic, copy, nullable) NSString *lanAddress;   // 本机 LAN IP,拼进「已注入 IP:端口」
@end

@implementation DHRootViewController

#pragma mark - lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    [self loadPendingRestart];
    [self refreshLatestIfStale];
    self.tableView.rowHeight = 56;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    self.tableView.sectionIndexMinimumDisplayRowCount = 12;

    self.filter = [[UISegmentedControl alloc] initWithItems:@[ @"全部", @"已启用", @"系统进程" ]];
    self.filter.selectedSegmentIndex = 0;
    [self.filter addTarget:self action:@selector(filterChanged) forControlEvents:UIControlEventValueChanged];
    self.navigationItem.titleView = self.filter;

    // 齿轮按钮（有新版时带一个小橙点，让用户不必主动去翻设置）
    UIButton *gear = [UIButton buttonWithType:UIButtonTypeSystem];
    gear.frame = CGRectMake(0, 0, 30, 30);
    [gear setImage:[UIImage systemImageNamed:@"gearshape"] forState:UIControlStateNormal];
    [gear addTarget:self action:@selector(openSettings) forControlEvents:UIControlEventTouchUpInside];
    UIView *dot = [[UIView alloc] initWithFrame:CGRectMake(24, 1, 8, 8)];
    dot.backgroundColor = [UIColor systemOrangeColor];
    dot.layer.cornerRadius = 4;
    dot.tag = 999;
    [gear addSubview:dot];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:gear];

    self.search = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.search.searchResultsUpdater = self;
    self.search.obscuresBackgroundDuringPresentation = NO;
    self.search.searchBar.placeholder = @"搜索 App";
    self.navigationItem.searchController = self.search;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reload];
    [self prunePendingRestart];
}

// 前台时定期重扫注入状态:daemon 常驻(nsurlsessiond 等),开启+重启后无需用户切走再回来
// 就能自动刷成「已注入」。第三方 App 进后台会被系统挂起、监听端口扫不到,轮询对它无效
// (这类靠打开 App 看悬浮窗确认;cell 也不再因扫不到而对 App 误报「未注入」)。
- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self.pollTimer invalidate];
    __weak typeof(self) weakSelf = self;
    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:5.0 repeats:YES block:^(__unused NSTimer *t) {
        [weakSelf refreshInjectedStatus];
    }];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self.pollTimer invalidate];
    self.pollTimer = nil;
}

// daemon 每 12 小时查一次；App 打开时若距上次检查超过 6 小时就补一次，
// 让"有新版本"这件事不必等周期、也不必用户主动去点检查更新。
// 静默进行：只更新齿轮上的橙点，不弹任何东西。
- (void)refreshLatestIfStale {
    NSTimeInterval lastCheck = [DHReadUpdaterState()[@"lastCheck"] doubleValue];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (lastCheck > 0 && now - lastCheck < 6 * 3600) return;
    DHFetchLatestRelease(^(NSDictionary *_Nullable info, __unused NSError *_Nullable error) {
        NSString *version = info[@"version"];
        if (![version isKindOfClass:[NSString class]] || version.length == 0) return;
        self.freshLatest = version;
        [self refreshUpdateDot];
    });
}

- (BOOL)hasPendingUpdate {
    if (DHPendingUpdateVersion() != nil) return YES;
    NSString *installed = DHReadEngineMeta()[@"version"];
    if (self.freshLatest.length && [installed isKindOfClass:[NSString class]] && installed.length) {
        return DHCompareVersions(installed, self.freshLatest) == NSOrderedAscending;
    }
    return NO;
}

- (void)refreshUpdateDot {
    UIView *dot = [self.navigationItem.rightBarButtonItem.customView viewWithTag:999];
    dot.hidden = ![self hasPendingUpdate];
}

- (void)openSettings {
    DHSettingsViewController *settings = [[DHSettingsViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
    [self.navigationController pushViewController:settings animated:YES];
}

- (void)filterChanged {
    self.enabledOnly = (self.filter.selectedSegmentIndex == DHFilterEnabled);
    [self rebuild];
    [self.tableView reloadData];
}

- (BOOL)isDaemonMode {
    return self.filter.selectedSegmentIndex == DHFilterDaemons;
}

// 统一「某项是否已启用」：daemon 看 enabledExecs(execName)，App 看 enabled(bundleID)
- (BOOL)isOn:(DHAppInfo *)app {
    if (app.isDaemon) return app.execName.length && [self.enabledExecs containsObject:app.execName];
    return [self.enabled containsObject:app.bundleID];
}

// pendingRestart 里用的键：daemon 用 execName，App 用 bundleID
- (NSString *)restartKeyFor:(DHAppInfo *)app {
    return app.isDaemon ? (app.execName ?: @"") : app.bundleID;
}

// 该项在本机的反代/注入端口信息：daemon 按 processName 在探测表里找，App 按 bundleID 取
- (NSDictionary *)injectedInfoFor:(DHAppInfo *)app {
    if (!app.isDaemon) return self.injected[app.bundleID];
    for (NSDictionary *info in self.injected.allValues) {
        if ([info[@"processName"] isEqualToString:app.execName]) return info;
    }
    return nil;
}

#pragma mark - 数据

- (void)reload {
    // 有新版本就在齿轮上点个橙点：用户不主动翻设置也能知道
    [self refreshUpdateDot];
    BOOL showSystem = [[NSUserDefaults standardUserDefaults] boolForKey:DH_SHOW_SYSTEM_APPS_KEY];
    self.allApps = DHInstalledApps(showSystem);
    self.daemons = DHSystemDaemons();
    self.enabled = [[DHReadEnabledBundles() mutableCopy] ?: [NSMutableSet set] mutableCopy];
    self.enabledExecs = [[DHReadEnabledExecutables() mutableCopy] ?: [NSMutableSet set] mutableCopy];
    self.lanAddress = DHLocalLANAddress();
    [self rebuild];
    [self.tableView reloadData];
    [self refreshInjectedStatus];
}

- (void)refreshInjectedStatus {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *found = DHProbeInjectedApps();
        dispatch_async(dispatch_get_main_queue(), ^{
            self.injected = found;
            [self.tableView reloadData];
        });
    });
}

- (void)updateSearchResultsForSearchController:(__unused UISearchController *)controller {
    [self rebuild];
    [self.tableView reloadData];
}

/// 按「过滤 → 搜索 → 首字母分组」重建分区
- (void)rebuild {
    NSString *query = [self.search.searchBar.text
        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    self.searching = query.length > 0;

    // 系统进程段：策展表(dh_daemons.h)平铺，数量少不分组、无首字母索引。
    if ([self isDaemonMode]) {
        NSMutableArray<DHAppInfo *> *pool = [NSMutableArray array];
        for (DHAppInfo *d in self.daemons) {
            if (query.length &&
                ![d.name localizedCaseInsensitiveContainsString:query] &&
                ![(d.execName ?: @"") localizedCaseInsensitiveContainsString:query]) continue;
            [pool addObject:d];
        }
        self.sections = @[ pool ];
        self.sectionHeaders = @[ @"" ];
        self.sectionIndexes = @[];
        return;
    }

    NSMutableArray<DHAppInfo *> *pool = [NSMutableArray array];
    for (DHAppInfo *app in self.allApps) {
        if (self.enabledOnly) {
            if (![self.enabled containsObject:app.bundleID]) continue;
        } else if (!app.showInAll) {
            // 「全部」tab 只显示合格项；已启用但不符合条件的系统 App 只在「已启用」tab 出现
            continue;
        }
        if (self.searching &&
            ![app.name localizedCaseInsensitiveContainsString:query] &&
            ![app.bundleID localizedCaseInsensitiveContainsString:query]) continue;
        [pool addObject:app];
    }

    if (self.searching) {   // 搜索结果不分组，直接平铺
        self.sections = @[ pool ];
        self.sectionHeaders = @[ @"" ];
        self.sectionIndexes = @[];
        return;
    }

    NSMutableArray<NSArray<DHAppInfo *> *> *sections = [NSMutableArray array];
    NSMutableArray<NSString *> *headers = [NSMutableArray array];
    NSMutableArray<NSString *> *indexes = [NSMutableArray array];

    // 按（首字母, 名称）排序后分组；中文名字用拼音首字母
    NSArray<DHAppInfo *> *sorted = [pool sortedArrayUsingComparator:^NSComparisonResult(DHAppInfo *l, DHAppInfo *r) {
        NSComparisonResult byLetter = [DHAppIndexLetter(l.name) compare:DHAppIndexLetter(r.name)];
        return byLetter != NSOrderedSame ? byLetter : [l.name localizedCaseInsensitiveCompare:r.name];
    }];
    NSString *current = nil;
    NSMutableArray<DHAppInfo *> *bucket = nil;
    for (DHAppInfo *app in sorted) {
        NSString *letter = DHAppIndexLetter(app.name);
        if (![letter isEqualToString:current]) {
            if (bucket) { [sections addObject:bucket]; [headers addObject:current]; [indexes addObject:current]; }
            bucket = [NSMutableArray array];
            current = letter;
        }
        [bucket addObject:app];
    }
    if (bucket) { [sections addObject:bucket]; [headers addObject:current]; [indexes addObject:current]; }

    self.sections = sections;
    self.sectionHeaders = headers;
    self.sectionIndexes = indexes;
}

#pragma mark - 表格

- (NSInteger)numberOfSectionsInTableView:(__unused UITableView *)tableView { return self.sections.count; }

- (NSInteger)tableView:(__unused UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.sections.count == 0 ? 1 : self.sections[section].count;   // 空态占一行
}

- (NSString *)tableView:(__unused UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    if (self.sections.count == 0) return nil;
    NSString *header = self.sectionHeaders[section];
    return self.searching ? @"搜索结果" : header;
}

- (NSString *)tableView:(__unused UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    // 只留一句真正需要用户做动作的话，放在"已启用"页（管理开关的地方）
    if (!self.searching && self.enabledOnly && section == 0) {
        return @"改动需要重启目标 App 才生效；点右侧 ⋯ 可重启或停止。";
    }
    if (!self.searching && [self isDaemonMode] && section == 0 &&
        self.sections.count > 0 && self.sections[0].count > 0) {
        return @"注入系统进程(daemon)可拿到 App 看不到的加解密/网络行为；开关后点 ⋯ 重启该进程才生效。";
    }
    return nil;
}

- (NSArray<NSString *> *)sectionIndexTitlesForTableView:(__unused UITableView *)tableView {
    return self.searching ? @[] : self.sectionIndexes;
}

- (NSInteger)tableView:(__unused UITableView *)tableView sectionForSectionIndexTitle:(NSString *)title atIndex:(NSInteger)index {
    return index;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (self.sections.count == 0) {   // 空态
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.numberOfLines = 0;
        cell.textLabel.textColor = [UIColor secondaryLabelColor];
        cell.textLabel.font = [UIFont systemFontOfSize:14];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        if (self.allApps.count == 0) {
            cell.textLabel.text = @"未能读取已安装应用";
        } else if (self.searching) {
            cell.textLabel.text = @"没有匹配的 App";
        } else {
            cell.textLabel.text = @"还没有启用任何 App\n在上面搜索，或从列表里打开开关";
        }
        return cell;
    }

    DHAppInfo *app = self.sections[indexPath.section][indexPath.row];
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"app"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"app"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
        cell.detailTextLabel.font = [UIFont systemFontOfSize:11];

        // 附件区：⋯ 菜单 + 开关。⋯ 是可见入口（左滑/长按用户未必发现），
        // 里面按当前状态给"重启 / 停止"或"开启注入"。
        UIView *accessory = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 92, 32)];
        UIButton *more = [UIButton buttonWithType:UIButtonTypeSystem];
        more.frame = CGRectMake(0, 1, 30, 30);
        [more setImage:[UIImage systemImageNamed:@"ellipsis.circle"] forState:UIControlStateNormal];
        more.showsMenuAsPrimaryAction = YES;          // iOS 14+
        [accessory addSubview:more];
        UISwitch *toggle = [[UISwitch alloc] init];
        toggle.frame = CGRectMake(38, 0, 51, 31);
        [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
        [accessory addSubview:toggle];
        cell.accessoryView = accessory;
    }
    UIView *accessory = cell.accessoryView;
    UIButton *more = (UIButton *)accessory.subviews.firstObject;
    UISwitch *toggle = (UISwitch *)accessory.subviews.lastObject;
    more.menu = [self menuForApp:app];               // 每次重建：菜单内容跟着状态走

    cell.textLabel.text = app.name;
    // 副标题标注来源：daemon 标进程名,系统 App 标 bundleId,第三方直接 bundleId
    NSString *base = app.isDaemon ? [@"系统进程 · " stringByAppendingString:(app.execName ?: @"")]
                   : (app.isSystem ? [@"系统 · " stringByAppendingString:app.bundleID] : app.bundleID);
    BOOL on = [self isOn:app];
    NSDictionary *injectedInfo = [self injectedInfoFor:app];
    if ([self.pendingRestart containsObject:[self restartKeyFor:app]]) {
        // 改了开关还没重启：直接标在这一行上，比横幅更贴身
        NSMutableAttributedString *subtitle = [[NSMutableAttributedString alloc]
            initWithString:base
                attributes:@{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor] }];
        [subtitle appendAttributedString:[[NSAttributedString alloc]
            initWithString:@"　需重启"
                attributes:@{ NSForegroundColorAttributeName: [UIColor systemOrangeColor] }]];
        cell.detailTextLabel.attributedText = subtitle;
    } else if (on && injectedInfo) {
        NSNumber *port = injectedInfo[@"port"];
        NSMutableAttributedString *subtitle = [[NSMutableAttributedString alloc]
            initWithString:base
                attributes:@{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor] }];
        NSNumber *pid = injectedInfo[@"pid"];
        NSString *mark;
        if (port) {
            NSString *addr = self.lanAddress.length
                ? [NSString stringWithFormat:@"%@:%@", self.lanAddress, port]   // 与悬浮窗一致,可直接访问
                : [NSString stringWithFormat:@":%@", port];
            mark = pid ? [NSString stringWithFormat:@"　已注入 %@ · PID %@", addr, pid]
                       : [NSString stringWithFormat:@"　已注入 %@", addr];
        } else {
            mark = pid ? [NSString stringWithFormat:@"　已注入 · PID %@", pid] : @"　已注入";
        }
        [subtitle appendAttributedString:[[NSAttributedString alloc]
            initWithString:mark
                attributes:@{ NSForegroundColorAttributeName: [UIColor systemGreenColor] }]];
        cell.detailTextLabel.attributedText = subtitle;
    } else if (on && app.isDaemon && DHAppProcessRunning(app)) {
        // daemon 常驻、端口一直可扫;扫不到就是真没架桥 → 提示未注入。
        NSMutableAttributedString *subtitle = [[NSMutableAttributedString alloc]
            initWithString:base
                attributes:@{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor] }];
        [subtitle appendAttributedString:[[NSAttributedString alloc]
            initWithString:@"　未注入"
                attributes:@{ NSForegroundColorAttributeName: [UIColor systemOrangeColor] }]];
        cell.detailTextLabel.attributedText = subtitle;
    } else if (on && !app.isDaemon && DHAppProcessRunning(app)) {
        // 第三方 App 在后台被系统挂起,监听端口扫不到 ≠ 未注入,不误报;打开 App 看悬浮窗为准。
        NSMutableAttributedString *subtitle = [[NSMutableAttributedString alloc]
            initWithString:base
                attributes:@{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor] }];
        [subtitle appendAttributedString:[[NSAttributedString alloc]
            initWithString:@"　运行中"
                attributes:@{ NSForegroundColorAttributeName: [UIColor secondaryLabelColor] }]];
        cell.detailTextLabel.attributedText = subtitle;
    } else {
        cell.detailTextLabel.attributedText = nil;
        cell.detailTextLabel.text = base;
    }
    cell.imageView.image = DHAppListIcon(app.bundleID, app.bundlePath, app.name);
    toggle.on = on;
    toggle.tag = indexPath.section * 10000 + indexPath.row;
    return cell;
}

#pragma mark - 开关

- (void)toggleChanged:(UISwitch *)toggle {
    NSInteger section = toggle.tag / 10000;
    NSInteger row = toggle.tag % 10000;
    if (section >= (NSInteger)self.sections.count) return;
    NSArray<DHAppInfo *> *apps = self.sections[section];
    if (row < 0 || row >= (NSInteger)apps.count) return;
    [self applyEnabled:toggle.on forApp:apps[row] revert:(void (^)(void))^{
        toggle.on = !toggle.on;
    }];
}

#pragma mark - 每行的 ⋯ 菜单（与长按菜单同一份内容）

- (UIMenu *)menuForApp:(DHAppInfo *)app {
    BOOL on = [self isOn:app];
    __weak typeof(self) weakSelf = self;
    NSMutableArray<UIMenuElement *> *items = [NSMutableArray array];
    if (on) {
        [items addObject:[UIAction actionWithTitle:@"重启" image:[UIImage systemImageNamed:@"arrow.clockwise"]
                                        identifier:nil handler:^(__unused UIAction *a) {
            [weakSelf requestRestartFor:app];
        }]];
        // daemon 由 launchd KeepAlive 守护,kill 会被立刻拉起,"停止"无意义,只给 App。
        if (!app.isDaemon) {
            [items addObject:[UIAction actionWithTitle:@"停止" image:[UIImage systemImageNamed:@"stop.circle"]
                                            identifier:nil handler:^(__unused UIAction *a) {
                [weakSelf requestStopFor:app];
            }]];
        }
    } else {
        [items addObject:[UIAction actionWithTitle:@"开启注入" image:[UIImage systemImageNamed:@"checkmark.circle"]
                                        identifier:nil handler:^(__unused UIAction *a) {
            [weakSelf applyEnabled:YES forApp:app revert:nil];
        }]];
    }
    return [UIMenu menuWithChildren:items];
}

- (UIContextMenuConfiguration *)tableView:(__unused UITableView *)tableView
    contextMenuConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath
                                        point:(__unused CGPoint)point {
    if (self.sections.count == 0 || indexPath.section >= (NSInteger)self.sections.count) return nil;
    NSArray<DHAppInfo *> *apps = self.sections[indexPath.section];
    if (indexPath.row >= (NSInteger)apps.count) return nil;
    DHAppInfo *app = apps[indexPath.row];
    return [UIContextMenuConfiguration configurationWithIdentifier:nil previewProvider:nil
        actionProvider:^(__unused NSArray<UIMenuElement *> *suggested) {
        return [self menuForApp:app];
    }];
}

- (void)requestRestartFor:(DHAppInfo *)app {
    if (app.isDaemon) { [self restartDaemon:app]; return; }
    // rootHide 上 launchd 能拉起 daemon，但签过名的二进制对引擎目录 EPERM，
    // 拿不到锁就退出，重启请求永远不会被处理。管理器与目标 App 同为 mobile，自己杀+打开。
    [self clearPendingRestart:app.bundleID];
    NSString *bundleID = app.bundleID;
    NSString *name = app.name;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL killed = DHKillAppProcess(app);
        if (killed) [NSThread sleepForTimeInterval:0.4];
        BOOL relaunched = DHRelaunchApp(bundleID);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (relaunched) {
                [self flashRestarted:name];
                return;
            }
            NSString *message = killed
                ? @"已结束它，请手动打开以让改动生效。"
                : @"无法重启该 App。";
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
                message:message preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

- (void)requestStopFor:(DHAppInfo *)app {
    [self clearPendingRestart:app.bundleID];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        DHKillAppProcess(app);
    });
}

// 系统 daemon 用 launchctl kickstart 重启(companion 随之重新注入);失败退回 SIGKILL(见 DHRestartDaemon)。
- (void)restartDaemon:(DHAppInfo *)daemon {
    [self clearPendingRestart:[self restartKeyFor:daemon]];
    NSString *name = daemon.name;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL ok = DHRestartDaemon(daemon);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                [self flashRestarted:name];
                // kickstart 后引擎要 1~2s 才注入+架桥完成；延迟重扫端口，让「已注入」自动刷新
                // （不必等用户切走再回来）。扫两次覆盖快慢。
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ [self refreshInjectedStatus]; });
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ [self refreshInjectedStatus]; });
                return;
            }
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
                message:@"无法重启该系统进程；可尝试重启设备让改动生效。"
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

#pragma mark - 开关写入

- (void)applyEnabled:(BOOL)on forApp:(DHAppInfo *)app revert:(void (^)(void))revert {
    if (app.isDaemon) { [self applyExec:on forDaemon:app revert:revert]; return; }
    NSMutableSet<NSString *> *next = [self.enabled mutableCopy];
    if (on) [next addObject:app.bundleID]; else [next removeObject:app.bundleID];
    NSError *writeErr = nil;
    if (!DHWriteEnabledBundles(next, &writeErr)) {
        if (revert) revert();
        NSString *detail = writeErr.localizedDescription.length
            ? writeErr.localizedDescription : @"请确认插件已正确安装。";
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"保存失败"
            message:[NSString stringWithFormat:@"写入启用名单失败。%@", detail]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    self.enabled = next;
    [self rebuild];
    [self.tableView reloadData];

    // 关掉/打开都只有重启目标 App 才生效。用户不知道这一点，所以由我们来判断：
    // 目标正在运行时自动重启它；没在运行时什么都不做（下次打开自然是新状态）。
    // 这样批量开关多个 App 时不会弹一堆确认框。
    // 不替用户做动作：只在列表顶部告诉他"这个改动需要重启才生效"，并给一个按钮。
    // 目标本来就没在运行的话不用提醒 —— 下次打开自然是新状态。
    NSString *selfBundle = [[NSBundle mainBundle] bundleIdentifier];
    BOOL isSelf = [app.bundleID isEqualToString:selfBundle];
    if (!isSelf && DHAppProcessRunning(app)) {
        [self markPendingRestart:app.bundleID];
    } else {
        [self clearPendingRestart:app.bundleID];
    }
}

// 系统进程注入名单(enabledExecutables)的开关写入,对称于 applyEnabled。
- (void)applyExec:(BOOL)on forDaemon:(DHAppInfo *)daemon revert:(void (^)(void))revert {
    if (daemon.execName.length == 0) { if (revert) revert(); return; }
    NSMutableSet<NSString *> *next = [self.enabledExecs mutableCopy];
    if (on) [next addObject:daemon.execName]; else [next removeObject:daemon.execName];
    NSError *writeErr = nil;
    if (!DHWriteEnabledExecutables(next, &writeErr)) {
        if (revert) revert();
        NSString *detail = writeErr.localizedDescription.length
            ? writeErr.localizedDescription : @"请确认插件已正确安装。";
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"保存失败"
            message:[NSString stringWithFormat:@"写入系统进程名单失败。%@", detail]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    self.enabledExecs = next;
    [self rebuild];
    [self.tableView reloadData];
    // 改注入名单要重启目标 daemon 才生效:在跑就标"需重启",点 ⋯ 重启(kickstart)。
    if (DHAppProcessRunning(daemon)) {
        [self markPendingRestart:daemon.execName];
    } else {
        [self clearPendingRestart:daemon.execName];
    }
}

#pragma mark - 待重启（开关改了但还没生效）

- (void)loadPendingRestart {
    NSArray *saved = [[NSUserDefaults standardUserDefaults] arrayForKey:@"dhPendingRestart"];
    self.pendingRestart = [NSMutableArray array];
    for (id item in saved) {
        if ([item isKindOfClass:[NSString class]]) [self.pendingRestart addObject:item];
    }
}

- (void)savePendingRestart {
    [[NSUserDefaults standardUserDefaults] setObject:[self.pendingRestart copy] forKey:@"dhPendingRestart"];
}

- (void)markPendingRestart:(NSString *)bundleID {
    if (bundleID.length == 0) return;
    if (![self.pendingRestart containsObject:bundleID]) {
        [self.pendingRestart addObject:bundleID];
        [self savePendingRestart];
    }
    [self.tableView reloadData];
}

- (void)clearPendingRestart:(NSString *)bundleID {
    if ([self.pendingRestart containsObject:bundleID]) {
        [self.pendingRestart removeObject:bundleID];
        [self savePendingRestart];
        [self.tableView reloadData];
    }
}

// 每次进入界面时清理：已经不在运行的 App 不用再提醒（下次打开自然是新状态）
- (void)prunePendingRestart {
    NSMutableDictionary<NSString *, DHAppInfo *> *map = [NSMutableDictionary dictionary];
    for (DHAppInfo *app in self.allApps) map[app.bundleID] = app;
    // daemon 的 pending 用 execName 作键，也要纳入，否则会被误清。
    for (DHAppInfo *d in self.daemons) if (d.execName.length) map[d.execName] = d;
    BOOL changed = NO;
    for (NSString *key in [self.pendingRestart copy]) {
        DHAppInfo *app = map[key];
        if (!app || !DHAppProcessRunning(app)) {
            [self.pendingRestart removeObject:key];
            changed = YES;
        }
    }
    if (changed) [self savePendingRestart];
}

#pragma mark - 重启结果

- (void)flashRestarted:(NSString *)name {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
        message:[NSString stringWithFormat:@"已重启 %@ 以应用改动", name]
        preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [alert dismissViewControllerAnimated:YES completion:nil]; });
}

@end
