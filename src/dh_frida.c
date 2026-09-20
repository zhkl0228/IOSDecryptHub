// dh_frida.c — IOSDecryptHubFrida:Frida 编排 daemon(C + frida-core devkit,不用 python)
//
// 背景:frida 是独立于 ElleKit(loader/companion)和引擎的第三套注入。本 daemon 连设备上已跑的
//   frida-server(REMOTE device),按 web 控制台请求「启动某 App 并注入 JS」——即 frida 主动 spawn
//   目标 App + 注入配置好的 JS 脚本。用户要的「启动时注入」。
//
// 为什么不用 spawn-gating(拦截用户点图标启动):实测 frida-server 的全局 spawn-gating 会 gate 设备上
//   所有新进程(含 SSH 会话子进程),且 spawn-added 事件不可靠传到 REMOTE device 回调 → 被 gate 的进程
//   等不到 resume 全卡死(SSH 都断)。风险太大,弃用。改主动 spawn:只影响目标进程,安全。
// 为什么 resume 后才 attach:实测本环境对 spawn 挂起态进程直接 attach 报 "connection is closed"
//   (goog-trans 也因此 resume 后 attach);故 spawn→resume→短延迟→attach→load(App 刚起来即注入)。
//
// 触发:collector 把请求(目标 bundle id)写进 REQ_FILE,本 daemon g_timeout 轮询处理;JS 从
//   JS_DIR/<bundle>.js 读。collector 只管 web + 存 JS + 写请求,frida 交互全在这。

#include "frida-core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>

#define FRIDA_TAG   "[dh-frida]"
#define REQ_FILE    "/var/jb/tmp/dh-frida-req"        // collector 写:一行 bundle id
#define JS_DIR      "/var/jb/usr/lib/IOSDecryptHub/frida"  // <bundle>.js
#define MSG_LOG     "/var/log/dh-frida.jsonl"              // script console.log/send 落这,collector 读给 web 显示
#define RESUME_DELAY_US 800000                         // spawn→resume 后等 App 起来再 attach

static GMainLoop *loop;
static FridaDevice *g_dev;

// 统一往 jsonl 落一条(json_msg 必须是合法 JSON 片段,嵌进 msg 字段)。collector /api/frida/log 读它给 web。
static void frida_jsonl(const char *bundle, const char *json_msg) {
    FILE *fp = fopen(MSG_LOG, "a");
    if (fp) {
        fprintf(fp, "{\"tsMs\":%lld,\"bundle\":\"%s\",\"msg\":%s}\n",
                (long long)time(NULL) * 1000, bundle, json_msg);
        fclose(fp);
    }
}
// 落一条错误(stage=spawn/resume/attach/create_script/load;desc 转义后放 payload)——让 web 也能看到
// 加载/编译/spawn 类错误(不只运行时 throw)。
static void frida_error(const char *bundle, const char *stage, const char *desc) {
    gchar *esc = g_strescape(desc ? desc : "", NULL);   // 转义 " \ \n,保证 JSON 合法
    gchar *json = g_strdup_printf("{\"type\":\"error\",\"stage\":\"%s\",\"payload\":\"%s\"}", stage, esc);
    frida_jsonl(bundle, json);
    syslog(LOG_ERR, FRIDA_TAG " [%s] %s 错误: %s", bundle, stage, desc ? desc : "");
    g_free(json); g_free(esc);
}
// frida script 的 console.log / send / 运行时 error(throw):落 syslog + jsonl(web 看)。
static void on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer ud) {
    const char *bundle = ud ? (const char *)ud : "";
    syslog(LOG_NOTICE, FRIDA_TAG " [%s] msg: %s", bundle, message);
    frida_jsonl(bundle, message);   // message 本身是 frida JSON({"type":"log"/"send"/"error",...})
}
// 目标进程 detach(脚本把 App 搞崩 / 主动断开):落 jsonl,web 能看到"脚本已断开(原因)"。
static void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer ud) {
    const char *bundle = ud ? (const char *)ud : "";
    gchar *rs = g_enum_to_string(FRIDA_TYPE_SESSION_DETACH_REASON, reason);
    gchar *json = g_strdup_printf("{\"type\":\"detached\",\"reason\":\"%s\",\"crash\":%s}",
                                  rs ? rs : "?", crash ? "true" : "false");
    frida_jsonl(bundle, json);
    syslog(LOG_NOTICE, FRIDA_TAG " [%s] detached reason=%s crash=%p", bundle, rs ? rs : "?", (void *)crash);
    g_free(rs); g_free(json);
}

// 读文件全部内容(调用者 free)。失败返回 NULL。
static gchar *read_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len < 0) { fclose(fp); return NULL; }
    rewind(fp);
    gchar *buf = g_malloc(len + 1);
    size_t rd = fread(buf, 1, len, fp);
    fclose(fp);
    buf[rd] = '\0';
    return buf;
}

// 主动 spawn 目标 App + 注入其 JS。session/script 不 unref(保持注入,直到目标退出)。
static void spawn_inject(const gchar *bundle) {
    GError *e = NULL;
    gchar *js_path = g_strdup_printf("%s/%s.js", JS_DIR, bundle);
    gchar *js = read_file(js_path);
    if (!js) {
        syslog(LOG_ERR, FRIDA_TAG " 无 JS 脚本 %s,跳过 %s", js_path, bundle);
        g_free(js_path);
        return;
    }
    syslog(LOG_NOTICE, FRIDA_TAG " spawn %s (JS %ld 字节)...", bundle, (long)strlen(js));

    guint pid = frida_device_spawn_sync(g_dev, bundle, NULL, NULL, &e);
    if (e) { frida_error(bundle, "spawn", e->message); goto done; }

    frida_device_resume_sync(g_dev, pid, NULL, &e);
    if (e) { frida_error(bundle, "resume", e->message); goto done; }
    g_usleep(RESUME_DELAY_US);   // 挂起 attach 本环境不通,resume 后等 App 起来再 attach

    FridaSession *sess = frida_device_attach_sync(g_dev, pid, NULL, NULL, &e);
    if (e) { frida_error(bundle, "attach", e->message); goto done; }
    g_signal_connect(sess, "detached", G_CALLBACK(on_detached), g_strdup(bundle));   // 崩溃/断开落 jsonl

    FridaScriptOptions *opt = frida_script_options_new();
    frida_script_options_set_name(opt, "dh-frida");
    frida_script_options_set_runtime(opt, FRIDA_SCRIPT_RUNTIME_QJS);
    FridaScript *scr = frida_session_create_script_sync(sess, js, opt, NULL, &e);
    g_clear_object(&opt);
    if (e) { frida_error(bundle, "create_script", e->message); goto done; }   // 语法/编译错误
    g_signal_connect(scr, "message", G_CALLBACK(on_message), g_strdup(bundle));   // ud=bundle(session 保持,不释放)
    frida_script_load_sync(scr, NULL, &e);
    if (e) { frida_error(bundle, "load", e->message); goto done; }   // 加载错误
    syslog(LOG_NOTICE, FRIDA_TAG " %s pid=%u 注入成功(script 保持)", bundle, pid);
    // 故意不 unref sess/scr:保持注入直到目标退出(detach 会 unload)。daemon 注入次数少,可接受。
done:
    g_clear_error(&e);
    g_free(js);
    g_free(js_path);
}

// 轮询请求文件:collector 写一行 bundle id → 处理 → 删。
static gboolean poll_req(gpointer ud) {
    if (access(REQ_FILE, F_OK) != 0) return TRUE;
    gchar *content = read_file(REQ_FILE);
    unlink(REQ_FILE);
    if (content) {
        gchar *bundle = g_strstrip(content);
        // 只允许 bundle id 字符集,防注入(内容来自 collector 写的文件,仍校验)
        gboolean ok = *bundle != '\0';
        for (const gchar *p = bundle; *p; p++) {
            if (!(g_ascii_isalnum(*p) || *p == '.' || *p == '-' || *p == '_')) { ok = FALSE; break; }
        }
        if (ok) spawn_inject(bundle);
        else syslog(LOG_ERR, FRIDA_TAG " 非法 bundle 请求,忽略");
        g_free(content);
    }
    return TRUE;
}

int main(void) {
    openlog("dh-frida", LOG_PID, LOG_DAEMON);
    frida_init();
    loop = g_main_loop_new(NULL, TRUE);

    GError *e = NULL;
    FridaDeviceManager *mgr = frida_device_manager_new();
    FridaDeviceList *devs = frida_device_manager_enumerate_devices_sync(mgr, NULL, &e);
    if (e) { syslog(LOG_ERR, FRIDA_TAG " enumerate_devices: %s", e->message); return 1; }
    gint n = frida_device_list_size(devs);
    for (gint i = 0; i < n; i++) {
        FridaDevice *d = frida_device_list_get(devs, i);
        if (frida_device_get_dtype(d) == FRIDA_DEVICE_TYPE_REMOTE) g_dev = g_object_ref(d);
        g_object_unref(d);
    }
    frida_unref(devs);
    if (!g_dev) { syslog(LOG_ERR, FRIDA_TAG " 无 REMOTE device(frida-server 没跑?)"); return 2; }

    unlink(REQ_FILE);   // 清残留请求
    g_timeout_add(400, poll_req, NULL);
    syslog(LOG_NOTICE, FRIDA_TAG " 就绪:轮询 %s,JS 目录 %s", REQ_FILE, JS_DIR);
    g_main_loop_run(loop);
    return 0;
}
