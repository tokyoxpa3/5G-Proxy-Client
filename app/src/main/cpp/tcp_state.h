#ifndef TCP_STATE_H
#define TCP_STATE_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// 閒置逾時：超過此秒數未活動即回收 TCP 會話（僅在 state==1「就緒」時套用）。
#define TCP_IDLE_TIMEOUT_SEC 300

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

// ---------- 關閉狀態機（兩方向獨立半關） ----------
//   server→App：engine 收 server EOF（recv==0）→ srv_eof=1；待 srv_buf 排空（srv_len==0）
//     才 srv_fin_sent=1 + 送 FIN 給 App（tcp_srv_should_send_fin）。
//   App→server：engine 收 App FIN → app_fin=1；待 app_buf 排空（app_len==0）才
//     shutdown(SHUT_WR) 傳播給 server（tcp_app_can_shutdown_write）。
//   不變量：srv_eof && !srv_fin_sent ⟹ srv_len>0（FIN 尚未送只因資料未排空），
//     故 App FIN 時不得在 srv_len>0 的狀態 close，否則丟棄尚未寫入 TUN 的 server 資料。
//   序：App FIN 必須在「純 ACK」分支前處理——FIN|ACK 的 payload==0 會被純 ACK 誤吞，
//     導致 app_fin 永不置位、半關無法傳播。異常：App RST→close(0)；server RST/err→close(1)；
//     已送 FIN 又收非零 payload→close(1)。

// server→App 半關傳播：已 EOF 且資料排空且尚未送 FIN → 應送 FIN。
int tcp_srv_should_send_fin(int srv_eof, size_t srv_len, int srv_fin_sent);

// App→server 半關傳播：App 已 FIN 且待送資料排空 → 可 shutdown(SHUT_WR)。
int tcp_app_can_shutdown_write(int app_fin, size_t app_len);

// 閒置逾時判定：會話就緒（state==1）且 now-last_active 超過 TCP_IDLE_TIMEOUT_SEC。
// state 由引擎以 atomic_load 載入後傳入；closed 判斷留給引擎。
int tcp_is_idle(int state, time_t now, time_t last_active);

#ifdef __cplusplus
}
#endif
#endif
