#include "jni_bridge.h"
#include <jni.h>
#include <android/log.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#define TAG "JNI_BRIDGE"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

JavaVM *g_jvm = NULL;
jobject g_native_engine_instance = NULL;

// 快取 MethodID 避免反覆查詢 (效能關鍵)
static jmethodID g_mid_createSocket = NULL;
static jmethodID g_mid_notifyClosed = NULL;
static jmethodID g_mid_notifyServerEvent = NULL;
static jmethodID g_mid_notifyEngineStopped = NULL;

extern int tun_socks_start(int tun_fd, const char *host, int port, const char *user, const char *pass, int udp_in_tcp, int remote_dns);
extern void tun_socks_stop(void);
extern void tun_socks_get_stats(unsigned long long *to_server, unsigned long long *from_server, int *tcp_sessions, int *udp_sessions);
extern void tun_socks_reconnect(void);
extern int tun_socks_is_running(void);

static pthread_t g_tunnel_thread;
static atomic_int g_tunnel_running = 0;

typedef struct { int fd; char host[256]; int port; char user[128]; char pass[128]; int udp_in_tcp; int remote_dns; } TunnelArgs;

static void *tunnel_thread_func(void *arg) {
    TunnelArgs *args = (TunnelArgs *)arg;
    tun_socks_start(args->fd, args->host, args->port, args->user, args->pass, args->udp_in_tcp, args->remote_dns);
    free(args);
    // 注意：不可在此清 g_tunnel_running，否則 stop 會 join 不到本線程
    return NULL;
}

// 供 Worker 線程使用：永久綁定 JVM
void jni_attach_thread() {
    if (!g_jvm) return;
    JNIEnv *env;
    (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL);
}

void jni_detach_thread() {
    if (!g_jvm) return;
    (*g_jvm)->DetachCurrentThread(g_jvm);
}

static JNIEnv *get_jni_env(int *should_detach) {
    JNIEnv *env = NULL;
    *should_detach = 0;
    if (!g_jvm) return NULL;
    int res = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) return NULL;
        *should_detach = 1;
    }
    return env;
}

// 請求 Java 層建立「已 protect（繞過 VPN）」的 socket 並取得 fd
int request_java_socket(const char *host, int port, int is_udp) {
    int should_detach = 0;
    JNIEnv *env = get_jni_env(&should_detach);
    if (!env || !g_native_engine_instance || !g_mid_createSocket) return -1;

    jstring jhost = (*env)->NewStringUTF(env, host);
    jint fd = (*env)->CallIntMethod(env, g_native_engine_instance, g_mid_createSocket, jhost, (jint)port, (jboolean)is_udp);

    // 異常防護
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        fd = -1;
    }

    (*env)->DeleteLocalRef(env, jhost);
    if (should_detach) (*g_jvm)->DetachCurrentThread(g_jvm);
    return (int)fd;
}

void release_java_socket(int fd) {
    int should_detach = 0;
    JNIEnv *env = get_jni_env(&should_detach);
    if (!env || !g_native_engine_instance || !g_mid_notifyClosed) return;

    (*env)->CallVoidMethod(env, g_native_engine_instance, g_mid_notifyClosed, (jint)fd);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    if (should_detach) (*g_jvm)->DetachCurrentThread(g_jvm);
}

// 伺服器連線事件（事件碼見 jni_bridge.h 的 enum server_event）
void notify_server_event(int code) {
    int should_detach = 0;
    JNIEnv *env = get_jni_env(&should_detach);
    if (!env || !g_native_engine_instance || !g_mid_notifyServerEvent) return;

    (*env)->CallVoidMethod(env, g_native_engine_instance, g_mid_notifyServerEvent, (jint)code);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    if (should_detach) (*g_jvm)->DetachCurrentThread(g_jvm);
}

// 引擎意外退出（非正常停止）→ 通知 Java 清除 isRunning 等狀態
void notify_engine_stopped(int unexpected) {
    int should_detach = 0;
    JNIEnv *env = get_jni_env(&should_detach);
    if (!env || !g_native_engine_instance || !g_mid_notifyEngineStopped) return;

    (*env)->CallVoidMethod(env, g_native_engine_instance, g_mid_notifyEngineStopped, (jboolean)(unexpected ? 1 : 0));
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    if (should_detach) (*g_jvm)->DetachCurrentThread(g_jvm);
}

// 流量統計 → [tx_bytes, rx_bytes, tcp_sessions, udp_sessions]
JNIEXPORT jlongArray JNICALL native_get_stats(JNIEnv *env, jobject thiz) {
    unsigned long long tx = 0, rx = 0;
    int tn = 0, un = 0;
    tun_socks_get_stats(&tx, &rx, &tn, &un);
    jlong v[4] = { (jlong)tx, (jlong)rx, (jlong)tn, (jlong)un };
    jlongArray arr = (*env)->NewLongArray(env, 4);
    if (!arr) return NULL;
    (*env)->SetLongArrayRegion(env, arr, 0, 4, v);
    return arr;
}

JNIEXPORT void JNICALL native_register_instance(JNIEnv *env, jobject thiz) {
    (*env)->GetJavaVM(env, &g_jvm);
    if (g_native_engine_instance) (*env)->DeleteGlobalRef(env, g_native_engine_instance);
    g_native_engine_instance = (*env)->NewGlobalRef(env, thiz);

    // 初始化 MethodID 快取
    jclass cls = (*env)->GetObjectClass(env, thiz);
    g_mid_createSocket = (*env)->GetMethodID(env, cls, "createSocketFromNative", "(Ljava/lang/String;IZ)I");
    if (!g_mid_createSocket) {
        LOGE("native_register_instance: GetMethodID failed for createSocketFromNative");
        g_mid_createSocket = NULL;
        g_mid_notifyClosed = NULL;
        g_mid_notifyServerEvent = NULL;
        (*env)->DeleteGlobalRef(env, g_native_engine_instance);
        g_native_engine_instance = NULL;
        return;
    }
    g_mid_notifyClosed = (*env)->GetMethodID(env, cls, "notifySocketClosed", "(I)V");
    if (!g_mid_notifyClosed) {
        LOGE("native_register_instance: GetMethodID failed for notifySocketClosed");
        g_mid_createSocket = NULL;
        g_mid_notifyClosed = NULL;
        g_mid_notifyServerEvent = NULL;
        (*env)->DeleteGlobalRef(env, g_native_engine_instance);
        g_native_engine_instance = NULL;
        return;
    }
    g_mid_notifyServerEvent = (*env)->GetMethodID(env, cls, "notifyServerEvent", "(I)V");
    if (!g_mid_notifyServerEvent) {
        LOGE("native_register_instance: GetMethodID failed for notifyServerEvent");
        g_mid_createSocket = NULL;
        g_mid_notifyClosed = NULL;
        g_mid_notifyServerEvent = NULL;
        g_mid_notifyEngineStopped = NULL;
        (*env)->DeleteGlobalRef(env, g_native_engine_instance);
        g_native_engine_instance = NULL;
        return;
    }
    g_mid_notifyEngineStopped = (*env)->GetMethodID(env, cls, "notifyEngineStopped", "(Z)V");
    if (!g_mid_notifyEngineStopped) {
        LOGE("native_register_instance: GetMethodID failed for notifyEngineStopped");
        g_mid_createSocket = NULL;
        g_mid_notifyClosed = NULL;
        g_mid_notifyServerEvent = NULL;
        g_mid_notifyEngineStopped = NULL;
        (*env)->DeleteGlobalRef(env, g_native_engine_instance);
        g_native_engine_instance = NULL;
        return;
    }
}

JNIEXPORT jstring JNICALL native_start_tunnel(JNIEnv *env, jobject thiz, jint fd, jstring host, jint port, jstring user, jstring pass, jboolean udp_in_tcp, jboolean remote_dns) {
    // g_tunnel_running 在引擎意外退出（epoll 錯誤）後可能殘留為 1；只有「引擎實際仍執行」
    // 時才拒絕，否則歸零照常啟動，避免隧道卡在假運行狀態永遠無法重啟。
    if (atomic_load(&g_tunnel_running) && tun_socks_is_running())
        return (*env)->NewStringUTF(env, "Already running");
    atomic_store(&g_tunnel_running, 0);

    TunnelArgs *args = calloc(1, sizeof(TunnelArgs));
    if (!args) return (*env)->NewStringUTF(env, "OOM");
    args->fd = (int)fd;
    args->port = (int)port;
    args->udp_in_tcp = udp_in_tcp ? 1 : 0;
    args->remote_dns = remote_dns ? 1 : 0;

    const char *chost = host ? (*env)->GetStringUTFChars(env, host, NULL) : NULL;
    const char *cuser = user ? (*env)->GetStringUTFChars(env, user, NULL) : NULL;
    const char *cpass = pass ? (*env)->GetStringUTFChars(env, pass, NULL) : NULL;
    strncpy(args->host, chost ? chost : "", sizeof(args->host) - 1);
    strncpy(args->user, cuser ? cuser : "", sizeof(args->user) - 1);
    strncpy(args->pass, cpass ? cpass : "", sizeof(args->pass) - 1);
    if (chost) (*env)->ReleaseStringUTFChars(env, host, chost);
    if (cuser) (*env)->ReleaseStringUTFChars(env, user, cuser);
    if (cpass) (*env)->ReleaseStringUTFChars(env, pass, cpass);

    atomic_store(&g_tunnel_running, 1);
    pthread_create(&g_tunnel_thread, NULL, tunnel_thread_func, args);
    return (*env)->NewStringUTF(env, "Started");
}

JNIEXPORT jstring JNICALL native_stop_tunnel(JNIEnv *env, jobject thiz) {
    // 無論啟動與否都執行停止：tun_socks_stop() 內部有 g_running 防呆。
    // 不能以 g_tunnel_running 判斷，因為啟動線程幾毫秒內就會把它清成 0，
    // 之後按停止會被誤判為「沒在跑」而直接略過 → 引擎永遠停不掉。
    tun_socks_stop();
    if (atomic_load(&g_tunnel_running)) {
        pthread_join(g_tunnel_thread, NULL);
        atomic_store(&g_tunnel_running, 0);
    }
    // 第二次：處理「按停止時啟動線程才剛 spawn 引擎」的競態（先 join 再停）
    tun_socks_stop();
    return (*env)->NewStringUTF(env, "Stopped");
}

// soft-reconnect：保留 TUN / VPN 介面，僅重置引擎連線狀態（供自動重連走軟重連路徑）
JNIEXPORT jstring JNICALL native_reconnect(JNIEnv *env, jobject thiz) {
    if (!atomic_load(&g_tunnel_running)) return (*env)->NewStringUTF(env, "Not running");
    tun_socks_reconnect();
    return NULL;
}

static const JNINativeMethod gMethods[] = {
    {"nativeRegisterInstance", "()V", (void *)native_register_instance},
    {"startTunnel", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/String;", (void *)native_start_tunnel},
    {"stopTunnel", "()Ljava/lang/String;", (void *)native_stop_tunnel},
    {"getStats", "()[J", (void *)native_get_stats},
    {"reconnect", "()Ljava/lang/String;", (void *)native_reconnect},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "com/tokyoxpa3/socksclient/NativeEngine");
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return JNI_ERR; }
    (*env)->RegisterNatives(env, cls, gMethods, sizeof(gMethods) / sizeof(gMethods[0]));
    return JNI_VERSION_1_6;
}
