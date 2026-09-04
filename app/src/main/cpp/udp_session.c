#include "udp_session.h"

int udp_should_buffer_first_pkt(size_t payload_len) {
    return payload_len <= UDP_FIRST_PKT_BUFFER_MAX;
}

int udp_is_idle(time_t now, time_t last_active) {
    return now - last_active > UDP_IDLE_TIMEOUT_SEC;
}
