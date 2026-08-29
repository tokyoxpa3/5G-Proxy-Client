// ip_parse.c — 純函式 IPv4/IPv6 頭與 fragment 表頭解析
// 獨立成檔以便 host 端編譯做單元測試；不依賴 POSIX/Android API、不碰引擎狀態。
#include <string.h>
#include "ip_parse.h"

// 網路序 → host 序（可攜版，避免依賴 arpa/inet.h）
#ifndef ntohl
static inline uint32_t ip_ntohl(uint32_t x) {
    return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000);
}
#define ntohl ip_ntohl
#endif

int parse_ipv4(const unsigned char *pkt, size_t len, uint8_t *proto, ip_addr_t *saddr, ip_addr_t *daddr, int *ihl) {
    if (len < 20) return -1;
    if ((pkt[0] >> 4) != 4) return -1;
    *ihl = (pkt[0] & 0x0F) * 4;
    if (*ihl < 20 || (size_t)*ihl > len) return -1;
    *proto = pkt[9];
    saddr->family = AF_INET; memcpy(saddr->ip, pkt + 12, 4); memset(saddr->ip + 4, 0, 12);
    daddr->family = AF_INET; memcpy(daddr->ip, pkt + 16, 4); memset(daddr->ip + 4, 0, 12);
    return 0;
}

int parse_ipv6(const unsigned char *pkt, size_t len, uint8_t *proto, ip_addr_t *saddr, ip_addr_t *daddr, size_t *l4off) {
    if (len < 40) return -1;
    if ((pkt[0] >> 4) != 6) return -1;
    saddr->family = AF_INET6; memcpy(saddr->ip, pkt + 8, 16);
    daddr->family = AF_INET6; memcpy(daddr->ip, pkt + 24, 16);

    size_t off = 40;
    uint8_t nh = pkt[6];
    for (int hops = 0; hops < 8; hops++) {
        if (nh == 17 || nh == 6 || nh == 58) { *proto = nh; *l4off = off; return 0; }
        if (nh == 44) return -1;                   // Fragment：無法重組，直接丟棄
        if (off + 8 > len) return -1;
        size_t hlen;
        if (nh == 51)                              hlen = ((size_t)pkt[off + 1] + 2) * 4;   // AH
        else if (nh == 0 || nh == 43 || nh == 60)  hlen = ((size_t)pkt[off + 1] + 1) * 8;   // Hop-by-Hop / Routing / Destination
        else return -1;                                                                      // 不認識的 ext header
        if (hlen < 8 || off + hlen > len) return -1;
        nh = pkt[off];
        off += hlen;
    }
    return -1;                                      // 超過層數上限
}

int ipv6_first_frag(const unsigned char *pkt, size_t len,
                    uint8_t *next_hdr, size_t *frag_off, int *mf, uint32_t *id) {
    if (len < 48) return 0;
    if (pkt[6] != 44) return 0;
    uint16_t ff = (uint16_t)((pkt[42] << 8) | pkt[43]);
    *next_hdr = pkt[40];
    // Fragment Offset 佔 16-bit 欄位的高 13 位（RFC 8200 §4.5），低 3 位為 Res(2)+M(1)
    *frag_off = (size_t)((ff >> 3) & 0x1FFF) * 8;
    *mf = (ff & 0x0001) != 0;
    uint32_t idn;
    memcpy(&idn, pkt + 44, 4);
    *id = ntohl(idn);
    return 1;
}