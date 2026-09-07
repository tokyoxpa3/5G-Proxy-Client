#include "dns_tcp.h"

size_t dns_tcp_frame_len(const unsigned char *p) {
    return ((size_t)p[0] << 8) | p[1];
}

size_t dns_tcp_scan_frames(const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off + 2 <= len) {
        size_t mlen = dns_tcp_frame_len(buf + off);
        if (off + 2 + mlen > len) break;   // 不完整 frame：停止，等後續串流補齊
        off += 2 + mlen;
    }
    return off;
}
