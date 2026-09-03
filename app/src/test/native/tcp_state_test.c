// tcp_state_test.c — TCP 狀態機純決策 golden test
// 驗證：ISN 生成（計數器注入/迴繞）、window scale 放大、流量控制 window 是否滿。
#include <stdio.h>
#include <stdint.h>
#include "tcp_state.h"

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
    // 1. ISN 生成（金值由獨立 Python 實作算得）
    {
        uint32_t ctr = 0;
        CHECK("isn now=0 ctr0->1", tcp_isn_generate(0u, &ctr) == 0xFD6ED390u);
        CHECK("isn ctr increments to 1", ctr == 1u);
    }
    {
        uint32_t ctr = 0;
        CHECK("isn now=0x12345678 ctr0->1", tcp_isn_generate(0x12345678u, &ctr) == 0xEB3A8958u);
        CHECK("isn now=0x12345678 ctr1->2", tcp_isn_generate(0x12345678u, &ctr) == 0x89720309u);
        CHECK("isn ctr increments to 2", ctr == 2u);
    }
    {
        uint32_t ctr = 0xFFFFFFFFu;
        CHECK("isn counter wraparound", tcp_isn_generate(0u, &ctr) == 0x5F3759DFu);
        CHECK("isn ctr wrapped to 0", ctr == 0u);
    }

    // 2. window scale 放大（((uint32_t)win) << ws）
    CHECK("win ws=0 unchanged", tcp_win_scaled(0xFFFF, 0) == 0x0000FFFFu);
    CHECK("win ws=10", tcp_win_scaled(0xFFFF, 10) == 0x03FFFC00u);
    CHECK("win ws=14 max", tcp_win_scaled(0xFFFF, 14) == 0x3FFFC000u);
    CHECK("win ws=16", tcp_win_scaled(0xFFFF, 16) == 0xFFFF0000u);
    CHECK("win small ws=10", tcp_win_scaled(1, 10) == 1024u);

    // 3. 流量控制：在途位元組 >= App window 即滿
    CHECK("flow not full", tcp_flow_window_full(1000, 1000, 100) == 0);
    CHECK("flow boundary full", tcp_flow_window_full(1100, 1000, 100) == 1);
    CHECK("flow just under", tcp_flow_window_full(1099, 1000, 100) == 0);
    CHECK("flow acked>next wraps to full", tcp_flow_window_full(500, 1000, 100) == 1);
    CHECK("flow zero window full", tcp_flow_window_full(1000, 1000, 0) == 1);

    // ---------- 差分/覆蓋：對照舊公式，鎖死抽離前後逐位等價 ----------
    {
        // window scale 全空間窮舉 ws ∈ [0,31]（>=32 為移位未定義，原引擎同樣如此，不納入）
        int ok = 1;
        for (uint32_t ws = 0; ws <= 31 && ok; ws++)
            for (uint32_t win = 0; win <= 0xFFFF; win++)
                if (tcp_win_scaled((uint16_t)win, (uint8_t)ws) != (((uint32_t)win) << ws)) { ok = 0; break; }
        CHECK("win scaled 全空間窮舉 ws0..31", ok);
    }
    {
        // ISN 隨機對照舊 next_tcp_isn 內聯公式
        int ok = 1;
        for (int i = 0; i < 200000 && ok; i++) {
            uint32_t now = xs_rand(), ctr = xs_rand();
            uint32_t inc = ctr + 1u;
            uint32_t expect = (now ^ 0x5F3759DFu) + inc * 2654435761u;
            if (tcp_isn_generate(now, &ctr) != expect || ctr != inc) ok = 0;
        }
        CHECK("isn 隨機對照舊公式 200k", ok);
    }
    {
        // 流控隨機對照舊 srv_next - app_acked >= app_win
        int ok = 1;
        for (int i = 0; i < 200000 && ok; i++) {
            uint32_t a = xs_rand(), b = xs_rand(), w = xs_rand();
            if (tcp_flow_window_full(a, b, w) != (((a - b) >= w) ? 1 : 0)) ok = 0;
        }
        CHECK("flow window 隨機對照舊公式 200k", ok);
    }

    // 半關傳播判定：tcp_srv_should_send_fin（真值表）
    CHECK("srv_fin eof+drained+unsent -> 1", tcp_srv_should_send_fin(1, 0, 0) == 1);
    CHECK("srv_fin not eof -> 0", tcp_srv_should_send_fin(0, 0, 0) == 0);
    CHECK("srv_fin data pending -> 0", tcp_srv_should_send_fin(1, 100, 0) == 0);
    CHECK("srv_fin already sent -> 0", tcp_srv_should_send_fin(1, 0, 1) == 0);

    // 半關傳播判定：tcp_app_can_shutdown_write（真值表）
    CHECK("app_shutdown fin+drained -> 1", tcp_app_can_shutdown_write(1, 0) == 1);
    CHECK("app_shutdown no fin -> 0", tcp_app_can_shutdown_write(0, 0) == 0);
    CHECK("app_shutdown data pending -> 0", tcp_app_can_shutdown_write(1, 100) == 0);
    CHECK("app_shutdown neither -> 0", tcp_app_can_shutdown_write(0, 100) == 0);

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
