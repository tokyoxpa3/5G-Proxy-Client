// tcp_buf_test.c — 待送佇列純空間算術 golden / 邊界 / 差分測試
// 驗證：reserve 緊縮條件、reserve 容量判定、攤銷緊縮門檻、滿佇列判定、recv 建議讀取量。
#include <stdio.h>
#include <stdint.h>
#include "tcp_buf.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

// 決定性 PRNG（xorshift32），供差分測試產生可重現的隨機輸入
static uint32_t xs_state = 0x12345678u;
static uint32_t xs_rand(void) {
    uint32_t x = xs_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xs_state = x;
    return x;
}

int main(void) {
    // 1. reserve 緊縮：僅 off>0 且 len>0 才緊縮
    CHECK("compact off=0 len=0 -> 0", tcp_buf_reserve_should_compact(0, 0) == 0);
    CHECK("compact off=0 len>0 -> 0", tcp_buf_reserve_should_compact(0, 10) == 0);
    CHECK("compact off>0 len=0 -> 0", tcp_buf_reserve_should_compact(10, 0) == 0);
    CHECK("compact off>0 len>0 -> 1", tcp_buf_reserve_should_compact(1, 1) == 1);

    // 2. reserve fits：off+len+need <= cap
    CHECK("fits exact boundary", tcp_buf_reserve_fits(0, 100, 100, 0) == 1);
    CHECK("fits one under", tcp_buf_reserve_fits(0, 100, 101, 0) == 1);
    CHECK("fits overflow by 1", tcp_buf_reserve_fits(0, 100, 100, 1) == 0);
    CHECK("fits off+len == cap", tcp_buf_reserve_fits(10, 90, 100, 0) == 1);
    CHECK("fits need fills cap", tcp_buf_reserve_fits(0, 0, 100, 100) == 1);
    CHECK("fits need over cap", tcp_buf_reserve_fits(0, 0, 100, 101) == 0);

    // 3. 攤銷緊縮門檻：off >= cap/2
    CHECK("half under -> 0", tcp_buf_should_compact_half(100, 1000) == 0);
    CHECK("half boundary -> 1", tcp_buf_should_compact_half(500, 1000) == 1);
    CHECK("half over -> 1", tcp_buf_should_compact_half(501, 1000) == 1);
    CHECK("half zero -> 0", tcp_buf_should_compact_half(0, 1000) == 0);
    // 引擎常數：TCP_SRV_BUF_CAP/2 = 524288
    CHECK("half engine constant", tcp_buf_should_compact_half(524288, 1048576) == 1);
    CHECK("half engine constant -1", tcp_buf_should_compact_half(524287, 1048576) == 0);

    // 4. 滿佇列：off+len >= cap
    CHECK("full under -> 0", tcp_buf_full(0, 99, 100) == 0);
    CHECK("full boundary -> 1", tcp_buf_full(0, 100, 100) == 1);
    CHECK("full off+len == cap", tcp_buf_full(50, 50, 100) == 1);
    CHECK("full over -> 1", tcp_buf_full(50, 51, 100) == 1);

    // 5. recv 建議讀取量：min(cap-off-len, chunk)
    CHECK("want all free", tcp_buf_recv_want(0, 0, 1000, 100) == 100);
    CHECK("want not clipped", tcp_buf_recv_want(0, 900, 1000, 100) == 100);
    CHECK("want clipped by free", tcp_buf_recv_want(0, 990, 1000, 100) == 10);
    CHECK("want zero free", tcp_buf_recv_want(0, 1000, 1000, 100) == 0);

    // ---------- 差分：隨機對照內聯公式，鎖死抽離前後逐位等價 ----------
    {
        int ok = 1;
        for (int i = 0; i < 200000 && ok; i++) {
            size_t cap = 1 + (xs_rand() % 1000000);

            size_t o1 = xs_rand() % 1000000, l1 = xs_rand() % 1000000;
            if (tcp_buf_reserve_should_compact(o1, l1) != ((o1 > 0 && l1 > 0) ? 1 : 0)) ok = 0;

            size_t o2 = xs_rand() % (cap + 1);
            size_t l2 = xs_rand() % (cap - o2 + 1);
            size_t need2 = xs_rand() % 1000000;
            if (tcp_buf_reserve_fits(o2, l2, cap, need2) != ((o2 + l2 + need2 <= cap) ? 1 : 0)) ok = 0;

            size_t o3 = xs_rand() % (cap + 1);
            if (tcp_buf_should_compact_half(o3, cap) != ((o3 >= cap / 2) ? 1 : 0)) ok = 0;

            size_t o4 = xs_rand() % (cap + 1);
            size_t l4 = xs_rand() % (cap + 1);
            if (tcp_buf_full(o4, l4, cap) != ((o4 + l4 >= cap) ? 1 : 0)) ok = 0;

            size_t o5 = xs_rand() % (cap + 1);
            size_t l5 = xs_rand() % (cap - o5 + 1);
            size_t chunk5 = 1 + (xs_rand() % 1000000);
            size_t free5 = cap - o5 - l5;
            size_t want5 = free5 < chunk5 ? free5 : chunk5;
            if (tcp_buf_recv_want(o5, l5, cap, chunk5) != want5) ok = 0;
        }
        CHECK("tcp_buf 隨機對照內聯公式 200k", ok);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
