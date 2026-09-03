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
