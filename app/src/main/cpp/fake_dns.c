#include "fake_dns.h"
#include "dns_synth.h"
#include <string.h>
#include <strings.h>   // strcasecmp

// portable htonl（不依賴 arpa/winsock，同 dns_synth.c 手法）
#ifndef htonl
static inline uint32_t fd_htonl(uint32_t x) {
    return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) |
           ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000);
}
#define htonl fd_htonl
#endif

void fake_dns_reset(fake_dns_table_t *t) {
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) t->entries[i].in_use = 0;
    t->next = 0;
}

uint32_t fake_dns_alloc(fake_dns_table_t *t, const char *domain, time_t now,
                        unsigned char ip6_out[16]) {
    // 1. 同網域已有映射 → 直接回傳（刷新 last_used）
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &t->entries[i];
        if (e->in_use && strcmp(e->domain, domain) == 0) {
            e->last_used = now;
            if (ip6_out) memcpy(ip6_out, e->fake_ip6, 16);
            return e->fake_ip;
        }
    }
    // 2. 依序尋找空位或已閒置逾時的項目
    for (int round = 0; round < FAKE_DNS_ENTRIES; round++) {
        unsigned idx = (t->next + (unsigned)round) % FAKE_DNS_ENTRIES;
        fake_dns_entry_t *e = &t->entries[idx];
        if (!e->in_use || now - e->last_used > FAKE_DNS_IDLE_SEC) {
            e->in_use = 1;
            e->fake_ip = htonl(DNS_FAKE_IP_BASE + idx + 1);
            strncpy(e->domain, domain, sizeof(e->domain) - 1);
            e->domain[sizeof(e->domain) - 1] = '\0';
            e->last_used = now;
            t->next = (idx + 1) % FAKE_DNS_ENTRIES;
            dns_build_fake_ip6((int)idx, e->fake_ip6);
            if (ip6_out) memcpy(ip6_out, e->fake_ip6, 16);
            return e->fake_ip;
        }
    }
    // 3. 全滿且皆未逾時 → LRU 淘汰最舊者
    unsigned oldest = 0;
    for (int i = 1; i < FAKE_DNS_ENTRIES; i++)
        if (t->entries[i].last_used < t->entries[oldest].last_used)
            oldest = (unsigned)i;
    fake_dns_entry_t *e = &t->entries[oldest];
    e->in_use = 1;
    e->fake_ip = htonl(DNS_FAKE_IP_BASE + oldest + 1);
    strncpy(e->domain, domain, sizeof(e->domain) - 1);
    e->domain[sizeof(e->domain) - 1] = '\0';
    e->last_used = now;
    t->next = (oldest + 1) % FAKE_DNS_ENTRIES;
    dns_build_fake_ip6((int)oldest, e->fake_ip6);
    if (ip6_out) memcpy(ip6_out, e->fake_ip6, 16);
    return e->fake_ip;
}

int fake_dns_lookup(fake_dns_table_t *t, uint32_t fake_ip, time_t now,
                    char *domain, size_t dn) {
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &t->entries[i];
        if (e->in_use && e->fake_ip == fake_ip) {
            e->last_used = now;
            strncpy(domain, e->domain, dn - 1);
            domain[dn - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

uint32_t fake_dns_find_domain(fake_dns_table_t *t, const char *domain, time_t now) {
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &t->entries[i];
        if (e->in_use && strcasecmp(e->domain, domain) == 0) {
            e->last_used = now;
            return e->fake_ip;
        }
    }
    return 0;
}

int fake_dns_lookup6(fake_dns_table_t *t, const unsigned char ip6[16], time_t now,
                     char *domain, size_t dn) {
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &t->entries[i];
        if (e->in_use && memcmp(e->fake_ip6, ip6, 16) == 0) {
            e->last_used = now;
            strncpy(domain, e->domain, dn - 1);
            domain[dn - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

uint32_t fake_dns_key(const ip_addr_t *ip) {
    if (ip->family != AF_INET) return 0;
    uint32_t k;
    memcpy(&k, ip->ip, 4);
    return k;
}
