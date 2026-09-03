#ifndef TCP_STATE_H
#define TCP_STATE_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 產生下一個 TCP ISN（host 序）。
// now_sec 為秒級時間（引擎注入 time(NULL)）；counter 為會話計數（引擎注入 &g.isn_counter），
// 呼叫後 *counter 遞增。純函式：所有可變狀態（計數器）經指標傳入，不碰全域。
uint32_t tcp_isn_generate(uint32_t now_sec, uint32_t *counter);

// 將 App 通告的 window field 依協商的 window scale 放大成位元組。
// win_field 為 host 序 window 欄位（已 ntohs），wscale 為 SYN 協商的縮放值。
uint32_t tcp_win_scaled(uint16_t win_field, uint8_t wscale);

// 流量控制：我方已送出但尚未被 App ACK 的位元組數是否已達 App 通告 window。
// 回傳 1 = window 已滿（應暫停送出，等 App ACK 開窗）；0 = 尚有空間。
// 與引擎一致採用 32-bit 無號減法（snd_next - acked），迴繞語意由既有的
// tcp_seq_gt 保證 acked 只會前進，故此處直接相減即為在途位元組數。
int tcp_flow_window_full(uint32_t snd_next, uint32_t acked, uint32_t win);

#ifdef __cplusplus
}
#endif
#endif
