#ifndef DNS_TCP_H
#define DNS_TCP_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// DNS-over-TCP 的 length-prefixed frame 串流（[2-byte 長度 + DNS message] 重複）。
// 吃不可信的 DNS-over-TCP 串流，是長度欄解析的記憶體安全敏感點，純邏輯、無 I/O、無狀態。

// 讀取 frame 的 2-byte 長度前綴（網路序）；回傳 DNS message 長度（0..65535）。
// 呼叫端須保證 p 之後至少有 2 位元組。
size_t dns_tcp_frame_len(const unsigned char *p);

// 掃描 buf 前綴中「完整 frame」的總長度；第一個 frame 不完整時回傳 0。
// 完整 frame = 2-byte 長度 + 該長度的 payload，且不超出 len。
size_t dns_tcp_scan_frames(const unsigned char *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif
