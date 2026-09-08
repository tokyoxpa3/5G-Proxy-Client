// 主機端 logging shim：把 Android NDK 的 __android_log_print 對應到 stderr，
// 使 tun_socks.c 可在無 NDK 的 CI Linux runner 上編譯執行。
// 僅供測試連結（經 Makefile 的 -I . 讓 <android/log.h> 優先解析到此檔），
// 不影響 Android 正式建置（其編譯使用 NDK 自帶的 android/log.h）。
#ifndef ANDROID_LOG_H
#define ANDROID_LOG_H

#include <stdarg.h>
#include <stdio.h>

#define ANDROID_LOG_VERBOSE 2
#define ANDROID_LOG_DEBUG 3
#define ANDROID_LOG_INFO 4
#define ANDROID_LOG_WARN 5
#define ANDROID_LOG_ERROR 6

static inline int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio;
    (void)tag;
    va_list ap;
    va_start(ap, fmt);
    int r = vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return r;
}

#endif /* ANDROID_LOG_H */
