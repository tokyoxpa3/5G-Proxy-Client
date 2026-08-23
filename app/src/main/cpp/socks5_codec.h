#ifndef SOCKS5_CODEC_H
#define SOCKS5_CODEC_H
#include <stddef.h>
#include <stdint.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ---------- SOCKS5 UDP frame ----------
// 建構 UDP ASSOCIATE 的 datagram frame（SOCKS5 頭 + payload），外層 2-byte length prefix 由呼叫端決定是否包含
// out 需至少 262+plen 空間；回傳寫入長度（不含 2-byte prefix），失敗回傳 -1
// domain != NULL 時使用 ATYP=0x03，否則依 family 選 0x01/0x04
int socks5_build_udp_datagram(const unsigned char *dst_ip, int family,
                              uint16_t dst_port_n, // 網路序
                              const char *domain, // 若非空則以網域撥號
                              const unsigned char *payload, size_t plen,
                              unsigned char *out, size_t out_cap);

// 含 2-byte length prefix 的完整 frame（for UDP-in-TCP）；回傳總長或 -1
int socks5_build_udp_frame(const unsigned char *dst_ip, int family,
                           uint16_t dst_port_n,
                           const char *domain,
                           const unsigned char *payload, size_t plen,
                           unsigned char *out, size_t out_cap);

// ---------- SOCKS5 CONNECT request ----------
int socks5_build_connect_request(const unsigned char *dst_ip, int family,
                                 uint16_t dst_port_n,
                                 const char *domain,
                                 unsigned char *out, size_t out_cap);

// ---------- SOCKS5 handshake ----------
int socks5_build_hello(const char *user, const char *pass, unsigned char *out, size_t cap);
int socks5_build_auth(const char *user, const char *pass, unsigned char *out, size_t cap);

// 解析 SOCKS5 UDP datagram 回應頭，回傳 payload offset/len，失敗 -1
int socks5_parse_udp_datagram(const unsigned char *datagram, size_t dlen,
                              unsigned char *src_ip_out, int *family_out,
                              uint16_t *src_port_n,
                              char *domain_out, size_t domain_cap,
                              const unsigned char **payload_out, size_t *payload_len_out);

#ifdef __cplusplus
}
#endif
#endif
