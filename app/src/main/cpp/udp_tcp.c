#include "udp_tcp.h"

void udp_tcp_stream_init(udp_tcp_stream_t *st) {
    st->want = -1;
}

long udp_tcp_consume(udp_tcp_stream_t *st, const unsigned char *buf, size_t len, size_t cap,
                     udp_tcp_frame_cb cb, void *ctx) {
    size_t off = 0;
    for (;;) {
        if (st->want < 0) {
            if (off + 2 > len) break;                       // 長度欄不完整
            int L = (buf[off] << 8) | buf[off + 1];
            if (L < UDP_TCP_MIN_FRAME || (size_t)L > cap) return -1;   // 異常長度欄
            off += 2;
            st->want = L;
        }
        if ((size_t)st->want > len - off) break;            // payload 不完整
        if (cb) cb(ctx, buf + off, (size_t)st->want);
        off += (size_t)st->want;
        st->want = -1;
    }
    return (long)off;
}
