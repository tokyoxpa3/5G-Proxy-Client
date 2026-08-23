#ifndef TCP_PACKET_H
#define TCP_PACKET_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#include <BaseTSD.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#include <sys/types.h>
#endif

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define TCP_MSS_IPV4 1460
#define TCP_MSS_IPV6 1440

// 建構 IPv4/IPv6 + TCP 封包（不含寫入 TUN），回傳總長或 -1
// 參數皆為 host 序 seq/ack，sport/dport 為網路序，win 為 host 序 window field
ssize_t tcp_build_segment(const unsigned char *saddr, const unsigned char *daddr, int family,
                          uint16_t sport_n, uint16_t dport_n,
                          uint32_t seq_host, uint32_t ack_host, uint8_t flags,
                          const unsigned char *payload, size_t plen,
                          uint16_t win,
                          unsigned char *out, size_t out_cap);

// 建構 SYN-ACK（MSS + WS 選項），回傳總長或 -1
ssize_t tcp_build_synack(const unsigned char *src_ip, const unsigned char *dst_ip, int family,
                         uint16_t src_port_n, uint16_t dst_port_n,
                         uint32_t isn_host, uint32_t ack_host,
                         uint16_t mss, uint8_t wscale,
                         unsigned char *out, size_t out_cap);

// 建構 UDP/IP 封包（for relay to TUN）
ssize_t udp_build_packet(const unsigned char *src_ip, const unsigned char *dst_ip, int family,
                         uint16_t src_port_n, uint16_t dst_port_n,
                         const unsigned char *payload, size_t plen,
                         unsigned char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
#endif
