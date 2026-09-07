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

// greeting method-selection 回覆（2-byte）的分類。純判斷：不碰 I/O、不碰引擎狀態。
typedef enum {
    S5_GREET_NO_AUTH = 0,   // 0x00：無認證，握手完成
    S5_GREET_NEED_AUTH,     // 0x02：需 RFC 1929 認證
    S5_ERR_NOT_SOCKS5,      // 首位元組 != 0x05
    S5_ERR_NO_METHOD        // 伺服器未選用可用方法（其它 method byte）
} s5_greet_class_t;
s5_greet_class_t socks5_classify_greet_reply(const unsigned char reply[2]);

// RFC 1929 認證回覆（2-byte）是否成功（0x01 0x00）。純判斷。
int socks5_auth_reply_ok(const unsigned char reply[2]);

// BND.ADDR 需再讀取的位元組數（不含 4-byte 回覆頭）。
// 0x01→6、0x04→18；0x03 為變長（回傳 -2，呼叫端先讀 1-byte 長度再讀 len+2）；其它→-1。
int socks5_atyp_bnd_len(uint8_t atyp);

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
