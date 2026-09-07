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

int ip_addr_eq(const ip_addr_t *a, const ip_addr_t *b) {
    return a->family == b->family && memcmp(a->ip, b->ip, 16) == 0;
}

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

int ipv6_find_fragment(const unsigned char *pkt, size_t len,
                       uint8_t *next_hdr, size_t *frag_off, int *mf, uint32_t *id,
                       size_t *frag_data_off, size_t *pre_frag_len, size_t *patch_off) {
    if (len < 40) return -1;
    if ((pkt[0] >> 4) != 6) return -1;

    size_t off = 40;
    size_t prev_next_off = 6;   // base header 的 next-header 欄位偏移
    uint8_t nh = pkt[6];
    for (int hops = 0; hops < 8; hops++) {
        if (nh == 6 || nh == 17 || nh == 58) return 0;   // 已達 L4，無 fragment
        if (nh == 44) {                                  // 找到 Fragment header（任意巢狀位置）
            if (off + 8 > len) return -1;
            uint16_t ff = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
            if (next_hdr) *next_hdr = pkt[off];          // Fragment 的 next-header = L4
            if (frag_off) *frag_off = (size_t)((ff >> 3) & 0x1FFF) * 8;
            if (mf) *mf = (ff & 0x0001) != 0;
            if (id) {
                uint32_t idn;
                memcpy(&idn, pkt + off + 4, 4);
                *id = ntohl(idn);
            }
            if (frag_data_off) *frag_data_off = off + 8;  // 緊接 Fragment header 之後
            if (pre_frag_len) *pre_frag_len = off;        // Fragment 之前的表頭鏈長度
            if (patch_off) *patch_off = prev_next_off;    // 前一 header 的 next-header 欄位
            return 1;
        }
        if (off + 8 > len) return -1;
        size_t hlen;
        if (nh == 51)                              hlen = ((size_t)pkt[off + 1] + 2) * 4;   // AH
        else if (nh == 0 || nh == 43 || nh == 60)  hlen = ((size_t)pkt[off + 1] + 1) * 8;   // Hop-by-Hop / Routing / Destination
        else return -1;                                                                      // 不認識的 ext header
        if (hlen < 8 || off + hlen > len) return -1;
        prev_next_off = off;                        // 此 header 的 next-header 欄位偏移
        nh = pkt[off];
        off += hlen;
    }
    return -1;                                      // 超過層數上限
}

int ip6_reasm_rebuild(const unsigned char *pre_frag_hdr, size_t pre_frag_len,
                      size_t patch_off, uint8_t next_hdr,
                      const unsigned char *payload, size_t plen,
                      unsigned char *out, size_t out_cap) {
    if (pre_frag_len < 40) return -1;
    if (patch_off >= pre_frag_len) return -1;
    // base header 的 payload 長度 = 移除 Fragment 後剩下的 ext header + 重組後 L4
    size_t payload_len = (pre_frag_len - 40) + plen;
    if (payload_len > 0xFFFF) return -1;
    size_t total = pre_frag_len + plen;
    if (total > out_cap) return -1;
    memcpy(out, pre_frag_hdr, pre_frag_len);
    out[4] = (unsigned char)(payload_len >> 8);
    out[5] = (unsigned char)(payload_len & 0xFF);
    out[patch_off] = next_hdr;                       // 44 → L4 協定
    memcpy(out + pre_frag_len, payload, plen);
    return (int)total;
}
