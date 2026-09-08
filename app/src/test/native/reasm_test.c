// reasm_test.c — IP 分片重組純演算法 golden test
// 驗證 reasm_insert_seg：循序/亂序重組、重疊丟棄、末片不一致、間隙、超上限、分片數上限、零長度末片。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "reasm.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

// 與 tun_socks.c 的 reasm_entry_t 對應的可變狀態（純函式所需子集）
typedef struct {
    size_t soff[REASM_MAX_FRAGS];
    size_t slen[REASM_MAX_FRAGS];
    int nseg;
    unsigned char buf[REASM_MAX_SIZE];
    size_t total_len;
    int have_last;
} reasm_state;

static reasm_state g_s;
static void state_init(void) { memset(&g_s, 0, sizeof(g_s)); }

static int ins(size_t offset, const unsigned char *data, size_t len, int mf) {
    return reasm_insert_seg(g_s.soff, g_s.slen, &g_s.nseg, g_s.buf,
                            offset, data, len, mf,
                            &g_s.total_len, &g_s.have_last);
}

// ---- reasm_table_insert（stateful 重組表）測試用回呼：捕捉重組完成封包 ----
static unsigned char g_cap[1024];
static size_t g_cap_len = 0;
static int g_cap_count = 0;
static void emit_capture(const unsigned char *out, size_t outlen, void *ctx) {
    (void)ctx;
    if (outlen <= sizeof g_cap) { memcpy(g_cap, out, outlen); g_cap_len = outlen; }
    g_cap_count++;
}

int main(void) {
    // 1. 循序到達
    state_init();
    CHECK("inorder frag1", ins(0, (const unsigned char*)"ABC", 3, 1) == 0);
    CHECK("inorder frag2", ins(3, (const unsigned char*)"DEF", 3, 0) == 1);
    CHECK("inorder total_len", g_s.total_len == 6);
    CHECK("inorder bytes", memcmp(g_s.buf, "ABCDEF", 6) == 0);

    // 2. 亂序到達（末片 offset 3 + mf=0 先到，首片 offset 0 + mf=1 後到）
    state_init();
    CHECK("outorder frag-last-first", ins(3, (const unsigned char*)"DEF", 3, 0) == 0);
    CHECK("outorder frag0-last", ins(0, (const unsigned char*)"ABC", 3, 1) == 1);
    CHECK("outorder bytes", memcmp(g_s.buf, "ABCDEF", 6) == 0);

    // 3. 重疊（RFC 5722 一律丟棄）
    state_init();
    CHECK("overlap frag1", ins(0, (const unsigned char*)"ABCD", 4, 1) == 0);
    CHECK("overlap frag2 dropped", ins(2, (const unsigned char*)"XX", 2, 1) == -1);

    // 4. 末片長度不一致
    state_init();
    CHECK("inconsistent frag1", ins(0, (const unsigned char*)"ABC", 3, 1) == 0);
    CHECK("inconsistent last", ins(3, (const unsigned char*)"DEF", 3, 0) == 1);
    CHECK("inconsistent extra last", ins(6, (const unsigned char*)"G", 1, 0) == -1);

    // 5. 中間有間隙（末片已到但缺口未補 → 未完成）
    state_init();
    CHECK("gap frag1", ins(0, (const unsigned char*)"AB", 2, 1) == 0);
    CHECK("gap last", ins(5, (const unsigned char*)"CD", 2, 0) == 0);

    // 6. 超出重組上限
    state_init();
    CHECK("overflow dropped", ins(REASM_MAX_SIZE - 1, (const unsigned char*)"12345", 5, 1) == -1);

    // 7. 分片數達上限（16 片後第 17 片丟棄）
    state_init();
    int over_nseg = 0;
    unsigned char one = 0xAA;
    for (int i = 0; i < REASM_MAX_FRAGS; i++) {
        int r = ins((size_t)i, &one, 1, 1);
        if (r != 0) { over_nseg = 1; break; }
    }
    CHECK("nseg 16 accepted", !over_nseg && g_s.nseg == REASM_MAX_FRAGS);
    CHECK("nseg 17 dropped", ins((size_t)REASM_MAX_FRAGS, &one, 1, 1) == -1);

    // 8. 零長度末片（offset = 已收長度，正常完成）
    state_init();
    CHECK("zero-len frag1", ins(0, (const unsigned char*)"AB", 2, 1) == 0);
    CHECK("zero-len last", ins(2, (const unsigned char*)"", 0, 0) == 1);
    CHECK("zero-len bytes", g_s.total_len == 2 && memcmp(g_s.buf, "AB", 2) == 0);

    // 9. 相鄰不重疊（邊界：offset == 前片末端）
    state_init();
    CHECK("adjacent frag1", ins(0, (const unsigned char*)"AB", 2, 1) == 0);
    CHECK("adjacent frag2", ins(2, (const unsigned char*)"CD", 2, 0) == 1);

    // 10. reasm_table v4 兩片重組端到端
    {
        reasm_table_t t;
        reasm_table_init(&t);
        ip_addr_t src = { AF_INET, {10,0,0,1} };
        ip_addr_t dst = { AF_INET, {8,8,8,8} };
        unsigned char hdr[20] = {0};
        hdr[0] = 0x45; hdr[9] = 17;
        memcpy(hdr + 12, src.ip, 4); memcpy(hdr + 16, dst.ip, 4);
        unsigned char d0[8] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7};
        unsigned char d1[4] = {0xB0,0xB1,0xB2,0xB3};

        g_cap_len = 0; g_cap_count = 0;
        reasm_table_insert(&t, AF_INET, &src, &dst, 17, 0x1234, 0, d0, 8, 1, hdr, 20, 0, 100, emit_capture, NULL);
        CHECK("tbl v4 frag0 no emit", g_cap_count == 0);
        reasm_table_insert(&t, AF_INET, &src, &dst, 17, 0x1234, 8, d1, 4, 0, hdr, 20, 0, 101, emit_capture, NULL);
        CHECK("tbl v4 frag1 emit once", g_cap_count == 1);
        CHECK("tbl v4 len=32", g_cap_len == 32);
        CHECK("tbl v4 total_len=32", g_cap[2] == 0 && g_cap[3] == 32);
        CHECK("tbl v4 payload order", memcmp(g_cap + 20, d0, 8) == 0 && memcmp(g_cap + 28, d1, 4) == 0);
        reasm_table_clear(&t);
    }

    // 11. reasm_table v6 兩片重組端到端（Fragment 為首個 ext header）
    {
        reasm_table_t t;
        reasm_table_init(&t);
        ip_addr_t src = { AF_INET6, {0} }; src.ip[15] = 1;                       // ::1
        ip_addr_t dst = { AF_INET6, {0x20,0x01,0x0d,0xb8} }; dst.ip[15] = 1;      // 2001:db8::1

        unsigned char f0[56] = {0};
        f0[0] = 0x60; f0[6] = 44;              // Fragment
        f0[40] = 17;                            // Fragment.next = UDP
        f0[42] = 0x00; f0[43] = 0x01;           // offset=0, M=1
        f0[44]=0x12; f0[45]=0x34; f0[46]=0x56; f0[47]=0x78;
        unsigned char d0[8] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7};
        memcpy(f0 + 48, d0, 8);

        unsigned char f1[52] = {0};
        f1[0] = 0x60; f1[6] = 44;
        f1[40] = 17;
        f1[42] = 0x00; f1[43] = 0x08;           // offset=8, M=0
        f1[44]=0x12; f1[45]=0x34; f1[46]=0x56; f1[47]=0x78;
        unsigned char d1[4] = {0xB0,0xB1,0xB2,0xB3};
        memcpy(f1 + 48, d1, 4);

        uint8_t nh; size_t fo; int mf; uint32_t id; size_t fdo, pre, po;
        ipv6_find_fragment(f0, 56, &nh, &fo, &mf, &id, &fdo, &pre, &po);
        g_cap_len = 0; g_cap_count = 0;
        reasm_table_insert(&t, AF_INET6, &src, &dst, nh, id, fo, f0 + fdo, 8, mf, f0, pre, po, 100, emit_capture, NULL);
        CHECK("tbl v6 frag0 no emit", g_cap_count == 0);

        ipv6_find_fragment(f1, 52, &nh, &fo, &mf, &id, &fdo, &pre, &po);
        reasm_table_insert(&t, AF_INET6, &src, &dst, nh, id, fo, f1 + fdo, 4, mf, f1, pre, po, 101, emit_capture, NULL);
        CHECK("tbl v6 frag1 emit once", g_cap_count == 1);
        CHECK("tbl v6 len=52", g_cap_len == 52);
        CHECK("tbl v6 next=UDP", g_cap[6] == 17);
        CHECK("tbl v6 payload", memcmp(g_cap + 40, d0, 8) == 0 && memcmp(g_cap + 48, d1, 4) == 0);
        reasm_table_clear(&t);
    }

    // 12. reasm_table GC：逾時 entry 被回收
    {
        reasm_table_t t;
        reasm_table_init(&t);
        ip_addr_t src = { AF_INET, {10,0,0,1} };
        ip_addr_t dst = { AF_INET, {8,8,8,8} };
        unsigned char hdr[20] = {0};
        hdr[0] = 0x45; hdr[9] = 17;
        unsigned char one = 0xAA;
        g_cap_count = 0;
        reasm_table_insert(&t, AF_INET, &src, &dst, 17, 1, 0, &one, 1, 1, hdr, 20, 0, 100, emit_capture, NULL);
        CHECK("tbl gc entry in use", t.entries[0].in_use == 1);
        reasm_table_gc(&t, 100 + REASM_TIMEOUT_SEC + 1);
        CHECK("tbl gc cleared", t.entries[0].in_use == 0);
        reasm_table_clear(&t);
    }

    // 13. reasm_table LRU：滿表時淘汰最舊
    {
        reasm_table_t t;
        reasm_table_init(&t);
        ip_addr_t src = { AF_INET, {10,0,0,1} };
        ip_addr_t dst = { AF_INET, {8,8,8,8} };
        unsigned char hdr[20] = {0};
        hdr[0] = 0x45; hdr[9] = 17;
        unsigned char one = 0xAA;

        // 填滿 16 個 entry（相異 id、相同時間）
        for (uint32_t i = 0; i < REASM_MAX_ENTRIES; i++) {
            reasm_table_insert(&t, AF_INET, &src, &dst, 17, i, 0, &one, 1, 1, hdr, 20, 0, 1000, emit_capture, NULL);
        }
        // 第 17 筆觸發 LRU：淘汰 last_active 最舊者（id 0）
        reasm_table_insert(&t, AF_INET, &src, &dst, 17, 0xFFFF, 0, &one, 1, 1, hdr, 20, 0, 1001, emit_capture, NULL);

        int id0_alive = 0, id_new_alive = 0, n_in_use = 0;
        for (int i = 0; i < REASM_MAX_ENTRIES; i++) {
            if (t.entries[i].in_use) {
                n_in_use++;
                if (t.entries[i].id == 0) id0_alive = 1;
                if (t.entries[i].id == 0xFFFF) id_new_alive = 1;
            }
        }
        CHECK("tbl lru evicted oldest", id0_alive == 0 && id_new_alive == 1);
        CHECK("tbl lru count stays 16", n_in_use == REASM_MAX_ENTRIES);
        reasm_table_clear(&t);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}