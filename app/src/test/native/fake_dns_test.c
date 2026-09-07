// fake_dns_test.c — fake DNS 分配／查表狀態機 golden test
// 驗證 fake_dns_alloc 的決定性分配、網域↔IP 雙向查表（v4/v6）、大小寫、
// 閒置重用、LRU 淘汰與 reset。now 由測試注入以確保完全 deterministic。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "fake_dns.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

// 網路序 fake_ip → 是否等於四段十進位（讀取儲存於 uint32_t 的 on-wire bytes，endian 無關）
static int ip_is(uint32_t fake_ip_n, unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
    unsigned char wire[4];
    memcpy(wire, &fake_ip_n, 4);
    return wire[0] == a && wire[1] == b && wire[2] == c && wire[3] == d;
}

static ip_addr_t mk4(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
    ip_addr_t r;
    memset(&r, 0, sizeof r);
    r.family = AF_INET;
    r.ip[0] = a; r.ip[1] = b; r.ip[2] = c; r.ip[3] = d;
    return r;
}

// 填滿整張表（dom0..domN-1），方便測試閒置重用／LRU
static void fill(fake_dns_table_t *t, time_t now) {
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        char d[64];
        snprintf(d, sizeof d, "dom%d.example", i);
        fake_dns_alloc(t, d, now, NULL);
    }
}

int main(void) {
    // 1. 決定性分配：idx 0/1/2 → 198.18.0.1 / .2 / .3（網路序 bytes）
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        uint32_t a = fake_dns_alloc(&t, "a.com", 1000, NULL);
        uint32_t b = fake_dns_alloc(&t, "b.com", 1000, NULL);
        uint32_t c = fake_dns_alloc(&t, "c.com", 1000, NULL);
        CHECK("alloc a.com == 198.18.0.1", ip_is(a, 0xC6, 0x12, 0x00, 0x01));
        CHECK("alloc b.com == 198.18.0.2", ip_is(b, 0xC6, 0x12, 0x00, 0x02));
        CHECK("alloc c.com == 198.18.0.3", ip_is(c, 0xC6, 0x12, 0x00, 0x03));
        CHECK("alloc 不同網域不回撞", a != b && b != c && a != c);
    }

    // 2. fake IPv6 golden：fd00::5e00:xxxx（idx 決定尾 16-bit）
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        unsigned char ip6[16];
        static const unsigned char exp0[16] = {0xFD,0,0,0,0,0,0,0,0,0,0,0,0,0x5E,0x00,0x01};
        fake_dns_alloc(&t, "a.com", 1000, ip6);
        CHECK("ip6 idx0 == fd00::5e00:0001", memcmp(ip6, exp0, 16) == 0);
        static const unsigned char exp1[16] = {0xFD,0,0,0,0,0,0,0,0,0,0,0,0,0x5E,0x00,0x02};
        fake_dns_alloc(&t, "b.com", 1000, ip6);
        CHECK("ip6 idx1 == fd00::5e00:0002", memcmp(ip6, exp1, 16) == 0);
    }

    // 3. 同網域冪等：回傳相同 fake IP、不新增槽位
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        uint32_t a1 = fake_dns_alloc(&t, "example.com", 1000, NULL);
        uint32_t a2 = fake_dns_alloc(&t, "example.com", 2000, NULL);
        CHECK("同網域冪等", a1 == a2);
        // 下一個新網域應拿到 idx1（.2），證明沒有重複占槽
        uint32_t b = fake_dns_alloc(&t, "other.com", 1000, NULL);
        CHECK("冪等後新域用 idx1", ip_is(b, 0xC6, 0x12, 0x00, 0x02));
    }

    // 4. 網域 ↔ IP 雙向查表（v4 鍵、v6 鍵、大小寫不敏感）
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        unsigned char ip6[16];
        uint32_t fake = fake_dns_alloc(&t, "Example.COM", 1000, ip6);
        char dom[256];
        CHECK("lookup fake_ip", fake_dns_lookup(&t, fake, 1500, dom, sizeof dom) == 1
              && strcmp(dom, "Example.COM") == 0);
        CHECK("lookup6 fake_ip6", fake_dns_lookup6(&t, ip6, 1500, dom, sizeof dom) == 1
              && strcmp(dom, "Example.COM") == 0);
        CHECK("find_domain 大小寫不敏感",
              fake_dns_find_domain(&t, "example.com", 1500) == fake
              && fake_dns_find_domain(&t, "EXAMPLE.COM", 1500) == fake);
        // 未映射查詢
        char d2[256];
        CHECK("lookup 未映射回 0", fake_dns_lookup(&t, 0xFFFFFFFFu, 1000, d2, sizeof d2) == 0);
        CHECK("find 未映射回 0", fake_dns_find_domain(&t, "nope.com", 1000) == 0);
        unsigned char no6[16];
        memset(no6, 0xFF, 16);
        CHECK("lookup6 未映射回 0", fake_dns_lookup6(&t, no6, 1000, d2, sizeof d2) == 0);
    }

    // 5. 閒置重用：填滿後 now 跨過 FAKE_DNS_IDLE_SEC，新域重用 idx0 槽位
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        fill(&t, 1000);
        // 下一個 round-robin 游標已回到 0；idx0 已 idle（400s > 300s）
        uint32_t reuse = fake_dns_alloc(&t, "reuse.com", 1400, NULL);
        CHECK("閒置重用取 idx0 槽", ip_is(reuse, 0xC6, 0x12, 0x00, 0x01));
        CHECK("閒置重用踢掉舊網域", fake_dns_find_domain(&t, "dom0.example", 1400) == 0);
        char dom[256];
        CHECK("閒置重用後可查新網域",
              fake_dns_lookup(&t, reuse, 1400, dom, sizeof dom) == 1
              && strcmp(dom, "reuse.com") == 0);
    }

    // 6. LRU 淘汰：填滿且皆未逾時，新域淘汰 last_used 最舊者（idx0）
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        fill(&t, 1000);
        uint32_t overflow = fake_dns_alloc(&t, "overflow.com", 1001, NULL);
        CHECK("LRU 淘汰取 idx0 槽", ip_is(overflow, 0xC6, 0x12, 0x00, 0x01));
        CHECK("LRU 淘汰舊網域", fake_dns_find_domain(&t, "dom0.example", 1001) == 0);
        char dom[256];
        CHECK("LRU 淘汰後可查新網域",
              fake_dns_lookup(&t, overflow, 1001, dom, sizeof dom) == 1
              && strcmp(dom, "overflow.com") == 0);
        CHECK("LRU 未誤踢其他網域", fake_dns_find_domain(&t, "dom1.example", 1001) != 0);
    }

    // 7. reset 清空整表：reset 後原網域不可查、重新從 idx0 開始分配
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        uint32_t old = fake_dns_alloc(&t, "gone.com", 1000, NULL);
        fake_dns_reset(&t);
        CHECK("reset 後舊網域不可查", fake_dns_find_domain(&t, "gone.com", 1000) == 0);
        char dom[256];
        // 舊 fake_ip 在空表上不可查（此時尚未重新分配占用同槽位）
        CHECK("reset 後舊 fake_ip 不可查", fake_dns_lookup(&t, old, 1000, dom, sizeof dom) == 0);
        uint32_t fresh = fake_dns_alloc(&t, "fresh.com", 1000, NULL);
        CHECK("reset 後重新由 idx0 分配", ip_is(fresh, 0xC6, 0x12, 0x00, 0x01));
    }

    // 8. fake_dns_key：v4 位址前 4 bytes 原樣重解讀；非 v4 回 0
    {
        ip_addr_t v4 = mk4(198, 18, 0, 1);
        // 前 4 bytes {198,18,0,1} 於主機 endian 重解讀後 memcpy 回去應得原 bytes
        uint32_t k = fake_dns_key(&v4);
        unsigned char back[4];
        memcpy(back, &k, 4);
        CHECK("fake_dns_key v4 bytes", back[0] == 198 && back[1] == 18 && back[2] == 0 && back[3] == 1);
        ip_addr_t v6;
        memset(&v6, 0, sizeof v6);
        v6.family = AF_INET6;
        CHECK("fake_dns_key 非 v4 回 0", fake_dns_key(&v6) == 0);
    }

    // 9. 超長網域：截斷至 255 字元、不越界、可回查
    {
        fake_dns_table_t t;
        memset(&t, 0, sizeof t);
        char longdom[320];
        memset(longdom, 'x', sizeof longdom - 1);
        longdom[sizeof longdom - 1] = '\0';
        uint32_t fake = fake_dns_alloc(&t, longdom, 1000, NULL);
        char dom[256];
        CHECK("超長網域可分配且回查", fake_dns_lookup(&t, fake, 1000, dom, sizeof dom) == 1
              && strlen(dom) == 255);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
