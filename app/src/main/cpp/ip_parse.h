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

// IPv6：沿 extension header 鏈找到「任意位置」的 Fragment header（巢狀分片）。
// 回傳 1 = 找到（輸出各欄位）；0 = 無 fragment（已達 L4，可正常解析）；-1 = 畸形/超限。
//
// 輸出欄位：
//   next_hdr        Fragment header 的 next-header（= 重組後的 L4 協定）
//   frag_off        分片 payload 的位元組偏移（已 ×8）
//   mf              更多分片旗標（M）
//   id              分片 ID（host 序）
//   frag_data_off   分片 payload 在封包中的偏移（緊接 Fragment header 之後）
//   pre_frag_len    Fragment 之前的表頭鏈長度（base 40 + 所有前置 ext header）
//   patch_off       需從 44 改寫為 next_hdr 的「next header 欄位」位元組偏移
int ipv6_find_fragment(const unsigned char *pkt, size_t len,
                       uint8_t *next_hdr, size_t *frag_off, int *mf, uint32_t *id,
                       size_t *frag_data_off, size_t *pre_frag_len, size_t *patch_off);

// 重建重組完成的 IPv6 封包：移除 Fragment header、把前一 header 的 next-header
// 改為 L4 協定、設定 base header 的 payload 長度、接上重組後的 payload。
// pre_frag_hdr 指向 base + Fragment 之前的 ext header（pre_frag_len 位元組），
// patch_off 為其中需改寫的 next-header 欄位位元組；payload/plen 為重組後 L4 資料。
// 回傳總長，或 -1（參數非法或 out_cap 不足）。
int ip6_reasm_rebuild(const unsigned char *pre_frag_hdr, size_t pre_frag_len,
                      size_t patch_off, uint8_t next_hdr,
                      const unsigned char *payload, size_t plen,
                      unsigned char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
#endif