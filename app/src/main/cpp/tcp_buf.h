#ifndef TCP_BUF_H
#define TCP_BUF_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 待送佇列的純空間算術（TCP 引擎 app_buf / srv_buf 共用）。
// 佇列以 (off, len, cap) 表示：off = 已送出前綴位元組數、len = 待送位元組數、cap = 容量。
// 純邏輯：無 I/O、無全域、無記憶體配置、不取時間；同步由引擎持有。

// reserve 前是否需先緊縮前綴：off>0 且仍有待送資料（回收已送出前綴騰出尾部空間）。
// app_buf_reserve 的緊縮條件。
int tcp_buf_reserve_should_compact(size_t off, size_t len);

// 尾部是否可再容納 need 位元組：off+len+need <= cap（前置：off+len <= cap）。
int tcp_buf_reserve_fits(size_t off, size_t len, size_t cap, size_t need);

// 是否已達「攤銷緊縮」門檻：前綴已送出超過一半容量（off >= cap/2），
// 分攤 memmove 成本、避免逐 segment 搬移。flush_tcp_srv_buf 與 handle_tcp_event 共用。
int tcp_buf_should_compact_half(size_t off, size_t cap);

// 佇列是否已滿：off+len >= cap。
int tcp_buf_full(size_t off, size_t len, size_t cap);

// 本次 recv 建議讀取量：剩餘空間 (cap-off-len) 與 chunk 上限取小（前置：off+len <= cap）。
size_t tcp_buf_recv_want(size_t off, size_t len, size_t cap, size_t chunk_limit);

#ifdef __cplusplus
}
#endif
#endif
