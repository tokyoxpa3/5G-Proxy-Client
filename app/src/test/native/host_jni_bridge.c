// 主機版 jni_bridge 替身：以真實 POSIX socket 取代 JNI 語意，供 tun_engine 整合測試連結。
// request_java_socket 直接建立/連線 socket，notify_* 記錄到原子全域供測試斷言。
// 不含 <jni.h>，可在 CI Linux runner 上編譯。僅測試用，不進入 Android 正式建置。

#include "jni_bridge.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// 供測試斷言讀取的記錄（tun_engine_test.c 以 extern 引用）
atomic_int g_host_last_server_event = SE_EVENT_OK;  // 0 = OK
atomic_int g_host_engine_stopped = 0;               // 0 = 未觸發；1 = 意外退出

void jni_attach_thread(void) {}
void jni_detach_thread(void) {}

int request_java_socket(const char *host, int port, int is_udp) {
    if (is_udp) {
        // 對應 Android 端未 connect 的 DatagramSocket：僅建立並綁定本機埠，
        // 目標由引擎以 sendto(relay_addr) 指定（host/port 在此路徑不參與連線）。
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;   // 綁定本機暫時埠（自動指派）
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
            close(fd);
            return -1;
        }
        return fd;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void release_java_socket(int fd) {
    if (fd >= 0) close(fd);
}

void notify_server_event(int code) {
    atomic_store(&g_host_last_server_event, code);
}

void notify_engine_stopped(int unexpected) {
    atomic_store(&g_host_engine_stopped, unexpected ? 1 : 0);
}
