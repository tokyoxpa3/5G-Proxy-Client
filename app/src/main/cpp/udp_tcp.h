#ifndef UDP_TCP_H
#define UDP_TCP_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// UDP-in-TCP（SOCKS5 cmd=0x04 relay）的 length-prefixed frame 串流：
//   [2-byte 大端長度 L][L-byte SOCKS5 UDP datagram] 重複。
// 吃不可信的 server→client 串流，是長度欄解析的記憶體安全敏感點。
// 純邏輯：無 I/O、無全域、無記憶體配置；跨 recv 邊界的狀態經 udp_tcp_stream_t 保留。

// 單一 frame 的最小 payload：SOCKS5 UDP datagram 固定表頭（RSV+FRAG+ATYP）4 位元組。
#define UDP_TCP_MIN_FRAME 4

typedef struct {
    int want;   // -1 = 待讀 2-byte 長度欄；>=0 = 已吃掉長度欄、待讀 payload 長度
} udp_tcp_stream_t;

// 每個完整 frame 的 payload 回呼（ctx 由呼叫端透傳）。
typedef void (*udp_tcp_frame_cb)(void *ctx, const unsigned char *payload, size_t payload_len);

// 初始化：want = -1（等待 2-byte 長度欄）。
void udp_tcp_stream_init(udp_tcp_stream_t *st);

// 從 buf[0..len) 解析完整 frame，湊齊一個就呼叫 cb(ctx, payload, payload_len)。
// 回傳已消費位元組數（0 = 不足一個完整 frame）；-1 = 協定違規（長度欄 <
// UDP_TCP_MIN_FRAME 或 > cap）。cap 為串流緩衝容量，作 frame 長度上限擋異常長度欄。
// state 跨呼叫保留：長度欄已消費但 payload 未完時，下次帶入後續位元組繼續。
long udp_tcp_consume(udp_tcp_stream_t *st, const unsigned char *buf, size_t len, size_t cap,
                     udp_tcp_frame_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif
