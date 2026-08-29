#ifndef IP_PARSE_H
#define IP_PARSE_H
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

// 位址抽象（v4 / v6 共用 session 結構）；v4 僅使用前 4 bytes，其餘填 0
typedef struct {
    int family;             // AF_INET / AF_INET6
    unsigned char ip[16];   // 網路序位址（v4 存前 4 bytes）
} ip_addr_t;

// 解析 IPv4 頭：回傳 0 成功 / -1 失敗；輸出 proto、來源/目的位址、ihl（位元組）
int parse_ipv4(const unsigned char *pkt, size_t len, uint8_t *proto,
               ip_addr_t *saddr, ip_addr_t *daddr, int *ihl);

// 沿 IPv6 extension header 鏈走到真正的 L4 協定，輸出傳輸層偏移 l4off。
// 支援 Hop-by-Hop(0)/Routing(43)/Destination(60)/AH(51)；Fragment(44) 需重組，直接丟棄。
int parse_ipv6(const unsigned char *pkt, size_t len, uint8_t *proto,
               ip_addr_t *saddr, ip_addr_t *daddr, size_t *l4off);

// IPv6：檢查首個 extension header 是否為 Fragment（最常見情況）。
// 回傳 1 = 是 fragment（輸出 next_hdr/frag_off/mf/id）；0 = 不是。
int ipv6_first_frag(const unsigned char *pkt, size_t len,
                    uint8_t *next_hdr, size_t *frag_off, int *mf, uint32_t *id);

#ifdef __cplusplus
}
#endif
#endif