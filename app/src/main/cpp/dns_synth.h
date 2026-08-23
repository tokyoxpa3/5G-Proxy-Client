#ifndef DNS_SYNTH_H
#define DNS_SYNTH_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_FAKE_TTL_SEC 60
#define DNS_FAKE_IP_BASE 0xC6120000u // 198.18.0.0

// 依 entry index 產生穩定 fake IPv6: fd00::5e<idx+1>
void dns_build_fake_ip6(int idx, unsigned char out[16]);

// 純函式 DNS reply 合成（不依賴全域 fake dns 表）
// fake_ip 為網路序，fake_ip6 為 16 bytes；always_answer 語意同 tun_socks.c dns_build_reply
// 回傳 1=成功（reply/rlen 有效），0=放行/失敗
int dns_build_reply_pure(const unsigned char *q, size_t qlen,
                         uint32_t fake_ip_n, const unsigned char fake_ip6[16],
                         int always_answer,
                         unsigned char *reply, size_t *rlen);

// 便於 golden test 的 helper：直接用已知 byte 序列對比，不經過 alloc
// 若 qtype==A/AAAA 時呼叫端需提供 fake_ip/fake_ip6，否則可傳 0/NULL
int dns_build_reply_for_test(const unsigned char *q, size_t qlen,
                             uint32_t fake_ip_n, const unsigned char fake_ip6[16],
                             int always_answer,
                             unsigned char *reply, size_t *rlen);

#ifdef __cplusplus
}
#endif
#endif
