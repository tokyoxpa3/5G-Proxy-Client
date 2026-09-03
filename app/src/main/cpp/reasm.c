// reasm.c — IP 分片重組的純演算法（抽離自 tun_socks.c 的 reasm_insert）
// 不依賴引擎全域狀態、epoll、POSIX、android/log，可於 host 端 gcc 編譯做單元測試。
#include "reasm.h"
#include <string.h>

int reasm_insert_seg(size_t *soff, size_t *slen, int *nseg, unsigned char *buf,
                     size_t offset, const unsigned char *data, size_t len, int mf,
                     size_t *total_len, int *have_last) {
    if (offset + len > REASM_MAX_SIZE) return -1;          // 超出重組上限
    if (!mf) {
        size_t t = offset + len;
        if (*have_last && *total_len != t) return -1;     // 末片長度與先前不一致
        *total_len = t;
        *have_last = 1;
    }
    if (len > 0) {
        if (*nseg >= REASM_MAX_FRAGS) return -1;          // 分片數超上限
        // 重疊檢查（RFC 5722：重疊的分片一律丟棄）
        for (int i = 0; i < *nseg; i++) {
            size_t a = soff[i], b = a + slen[i];
            if (offset < b && a < offset + len) return -1;
        }
        soff[*nseg] = offset;
        slen[*nseg] = len;
        (*nseg)++;
        memcpy(buf + offset, data, len);
    }
    if (!*have_last) return 0;
    // 依 offset 排序 segment，確認 [0, total_len) 無間隙全覆蓋
    for (int i = 0; i < *nseg - 1; i++)
        for (int j = i + 1; j < *nseg; j++)
            if (soff[j] < soff[i]) {
                size_t t1 = soff[i], t2 = slen[i];
                soff[i] = soff[j]; slen[i] = slen[j];
                soff[j] = t1; slen[j] = t2;
            }
    size_t expected = 0;
    for (int i = 0; i < *nseg; i++) {
        if (soff[i] != expected) return 0;
        expected += slen[i];
    }
    return (expected == *total_len) ? 1 : 0;
}
