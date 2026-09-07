#include "icmp_packet.h"
#include "checksum.h"
#include <string.h>

#define ICMP_TUN_MTU 4096

ssize_t icmp4_build_echo_reply(const unsigned char *req, size_t req_len, int ihl,
                               const unsigned char *src_ip4, const unsigned char *dst_ip4,
                               unsigned char *out, size_t out_cap) {
    if (ihl < 20 || (size_t)ihl + 8 > req_len) return -1;
    if (req_len > out_cap || req_len > ICMP_TUN_MTU) return -1;
    size_t t = (size_t)ihl;
    memcpy(out, req, req_len);
    // 交換 IP 來源/目的（回覆方向），重算 IP header checksum
    memcpy(out + 12, src_ip4, 4);
    memcpy(out + 16, dst_ip4, 4);
    out[8] = 64;                                   // TTL
    out[10] = 0; out[11] = 0;
    uint16_t csum = checksum16(out, t);
    out[10] = (unsigned char)(csum >> 8); out[11] = (unsigned char)(csum & 0xFF);
    // echo reply（type 8 → 0），重算 ICMP checksum
    out[t] = 0;
    out[t + 2] = 0; out[t + 3] = 0;
    uint16_t icsum = checksum16(out + t, req_len - t);
    out[t + 2] = (unsigned char)(icsum >> 8); out[t + 3] = (unsigned char)(icsum & 0xFF);
    return (ssize_t)req_len;
}

ssize_t icmp6_build_echo_reply(const unsigned char *req, size_t req_len,
                               const unsigned char *src_ip6, const unsigned char *dst_ip6,
                               unsigned char *out, size_t out_cap) {
    if (req_len < 48 || req_len > out_cap || req_len > ICMP_TUN_MTU) return -1;
    memcpy(out, req, req_len);
    // 交換 IPv6 來源/目的（回覆方向）
    memcpy(out + 8, src_ip6, 16);
    memcpy(out + 24, dst_ip6, 16);
    out[7] = 64;                                   // hop limit
    // echo reply（type 128 → 129），重算 ICMPv6 checksum（含 pseudo-header）
    out[40] = 129;
    out[42] = 0; out[43] = 0;
    uint16_t icsum = tcpudp_checksum6(src_ip6, dst_ip6, 58, out + 40, req_len - 40);
    out[42] = (unsigned char)(icsum >> 8); out[43] = (unsigned char)(icsum & 0xFF);
    return (ssize_t)req_len;
}

ssize_t icmp6_build_na(const unsigned char *target_ip6, const unsigned char *from_ip6,
                       unsigned char *out, size_t out_cap) {
    if (out_cap < 64) return -1;
    memset(out, 0, 64);
    out[0] = 0x60;
    out[4] = 0; out[5] = 24;             // payload length = 24（ICMPv6 8 + NA 16）
    out[6] = 58;                          // next header ICMPv6
    out[7] = 255;                         // hop limit
    memcpy(out + 8, target_ip6, 16);      // 來源 = 目標（宣告擁有權）
    memcpy(out + 24, from_ip6, 16);       // 目的 = NS 來源
    out[40] = 136;                        // Neighbor Advertisement
    out[44] = 0x60;                       // R=0 S=1 O=1
    memcpy(out + 48, target_ip6, 16);
    uint16_t csum = tcpudp_checksum6(out + 8, out + 24, 58, out + 40, 24);
    out[42] = (unsigned char)(csum >> 8); out[43] = (unsigned char)(csum & 0xFF);
    return 64;
}
