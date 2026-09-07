#include "tcp_state.h"

uint32_t tcp_isn_generate(uint32_t now_sec, uint32_t *counter) {
    *counter += 1u;
    return (now_sec ^ 0x5F3759DFu) + *counter * 2654435761u;
}

uint32_t tcp_win_scaled(uint16_t win_field, uint8_t wscale) {
    return ((uint32_t)win_field) << wscale;
}

int tcp_flow_window_full(uint32_t snd_next, uint32_t acked, uint32_t win) {
    return (snd_next - acked) >= win;
}

int tcp_srv_should_send_fin(int srv_eof, size_t srv_len, int srv_fin_sent) {
    return srv_eof && srv_len == 0 && !srv_fin_sent;
}

int tcp_app_can_shutdown_write(int app_fin, size_t app_len) {
    return app_fin && app_len == 0;
}

int tcp_is_idle(int state, time_t now, time_t last_active) {
    return state == 1 && now - last_active > TCP_IDLE_TIMEOUT_SEC;
}

int tcp_post_fin_send_rst(size_t payload_len) {
    return payload_len != 0;
}

int tcp_server_drained(int srv_eof, size_t srv_len) {
    return srv_eof && srv_len == 0;
}

int tcp_recv_full_should_close(size_t srv_len) {
    return srv_len == 0;
}

tcp_in_class_t tcp_classify_in(uint8_t flags, uint32_t seq_host, uint32_t app_next,
                               size_t payload_len, int srv_fin_sent) {
    if ((flags & 0x02) && !(flags & 0x10)) return TCP_IN_SYN_ONLY;   // SYN && !ACK
    if (flags & 0x04) return TCP_IN_RST;                            // RST
    if (seq_host != app_next) return TCP_IN_OUT_OF_ORDER;           // 亂序/重傳
    if (srv_fin_sent) return TCP_IN_POST_FIN;                       // 我方已送 FIN
    if (payload_len == 0 && (flags & 0x10) && !(flags & 0x01)) return TCP_IN_PURE_ACK;  // 純 ACK（排除 FIN）
    return TCP_IN_FALLTHROUGH;
}
