#include "tcp_buf.h"

int tcp_buf_reserve_should_compact(size_t off, size_t len) {
    return off > 0 && len > 0;
}

int tcp_buf_reserve_fits(size_t off, size_t len, size_t cap, size_t need) {
    return off + len + need <= cap;
}

int tcp_buf_should_compact_half(size_t off, size_t cap) {
    return off >= cap / 2;
}

int tcp_buf_full(size_t off, size_t len, size_t cap) {
    return off + len >= cap;
}

size_t tcp_buf_recv_want(size_t off, size_t len, size_t cap, size_t chunk_limit) {
    size_t free_space = cap - off - len;
    return free_space < chunk_limit ? free_space : chunk_limit;
}
