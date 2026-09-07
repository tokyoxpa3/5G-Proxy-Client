#ifndef FAKE_DNS_H
#define FAKE_DNS_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "ip_parse.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FAKE_DNS_ENTRIES 512
#define FAKE_DNS_IDLE_SEC 300

// 單一 fake IP ↔ 網域映射項
typedef struct {
    uint32_t fake_ip;            // 網路序（v4 fake）
    unsigned char fake_ip6[16];  // 對應的 fake IPv6（AAAA 回覆用）
    char domain[256];
    time_t last_used;
    int in_use;
} fake_dns_entry_t;

// fake DNS 狀態表：可整體重置、由引擎持有。
// 引擎單執行緒與 handshake 執行緒皆會存取，同步由呼叫端（引擎的 mutex）負責；
// 此模組為純邏輯、不取時間、不加鎖，now 由呼叫端注入以便 deterministic 測試。
typedef struct {
    fake_dns_entry_t entries[FAKE_DNS_ENTRIES];
    unsigned next;   // round-robin 分配游標（下一個起始索引）
} fake_dns_table_t;

// 全表清空（in_use=0，游標歸零）
void fake_dns_reset(fake_dns_table_t *t);

// 分配（或重用）網域的 fake IP；回傳網路序 IP（0=失敗），ip6_out 帶出對應 fake IPv6（可為 NULL）。
uint32_t fake_dns_alloc(fake_dns_table_t *t, const char *domain, time_t now,
                        unsigned char ip6_out[16]);

// fake IP → 網域；回傳 1=找到（domain 帶出），0=無映射
int fake_dns_lookup(fake_dns_table_t *t, uint32_t fake_ip, time_t now,
                    char *domain, size_t dn);

// 網域 → fake IP（大小寫不敏感；找不到回傳 0）
uint32_t fake_dns_find_domain(fake_dns_table_t *t, const char *domain, time_t now);

// fake IPv6 → 網域；回傳 1=找到（domain 帶出），0=無映射
int fake_dns_lookup6(fake_dns_table_t *t, const unsigned char ip6[16], time_t now,
                     char *domain, size_t dn);

// fake IP 的 32-bit 查表鍵（v4 位址前 4 bytes 原樣重解讀；非 v4 回傳 0）
uint32_t fake_dns_key(const ip_addr_t *ip);

#ifdef __cplusplus
}
#endif
#endif
