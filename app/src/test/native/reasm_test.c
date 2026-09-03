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

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}