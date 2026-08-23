#ifndef JNI_BRIDGE_H
#define JNI_BRIDGE_H

void jni_attach_thread(void);
void jni_detach_thread(void);
int request_java_socket(const char *host, int port, int is_udp);
void release_java_socket(int fd);

// 伺服器連線事件（ok=1 成功 / 0 網路層失敗）→ Kotlin 自動重連看門狗
void notify_server_event(int ok);

#endif
