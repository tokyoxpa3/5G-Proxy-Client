#ifndef UDP_SESSION_H
#define UDP_SESSION_H
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// 首包緩衝門檻：涵蓋 QUIC Initial（~1200B），超過此值不緩衝、避免等 App 重傳。
#define UDP_FIRST_PKT_BUFFER_MAX 1400
// 閒置逾時：超過此秒數未活動即回收 UDP 會話。
#define UDP_IDLE_TIMEOUT_SEC 330

// 是否緩衝 handshake 期間的首包（payload_len 不超過門檻）。
// 純函式：不碰全域/時間/socket。
int udp_should_buffer_first_pkt(size_t payload_len);

// 是否已閒置逾時（now - last_active 超過 UDP_IDLE_TIMEOUT_SEC）。
// last_active 不大於 now 的正常語意下，純比較；不碰全域。
int udp_is_idle(time_t now, time_t last_active);

#ifdef __cplusplus
}
#endif
#endif
