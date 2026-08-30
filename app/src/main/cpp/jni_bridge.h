#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

void jni_attach_thread(void);
void jni_detach_thread(void);
int request_java_socket(const char *host, int port, int is_udp);
void release_java_socket(int fd);

// 伺服器連線事件分類碼（notify_server_event 用；Kotlin NativeEngine 有對應常數）：
//   SE_EVENT_OK            連線成功 → 重置自動重連看門狗
//   SE_EVENT_NETWORK_FAIL  網路層失敗（socket 逾時）→ 累計並觸發看門狗自動重連
//   SE_EVENT_AUTH_FAIL     認證被拒（帳號/密碼錯誤）→ 不觸發看門狗，提示使用者改正設定
//   SE_EVENT_PROTOCOL_FAIL 協定層錯誤（非 SOCKS5 / REP≠0 / 未知回應）→ 同上
//   SE_EVENT_NONE          不通知（引擎關閉中中止，非錯誤）
enum server_event {
    SE_EVENT_OK            = 0,
    SE_EVENT_NETWORK_FAIL  = 1,
    SE_EVENT_AUTH_FAIL     = 2,
    SE_EVENT_PROTOCOL_FAIL = 3,
    SE_EVENT_NONE          = -1
};

// 伺服器連線事件（事件碼見 enum server_event）→ Kotlin 自動重連看門狗 / UI 錯誤提示
void notify_server_event(int code);

// 引擎意外退出（非正常停止，例如 epoll 錯誤）→ Kotlin 清除 isRunning 等狀態，
// 避免 g_tunnel_running 卡住導致日後無法重啟
void notify_engine_stopped(int unexpected);

#endif
