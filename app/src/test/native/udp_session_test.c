// udp_session_test.c — UDP Fullcone 會話純決策 golden test
// 驗證：首包緩衝門檻（1400）、閒置逾時判定（330 秒）。
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "udp_session.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

int main(void) {
    // 1. 首包緩衝門檻：<= 1400 才緩衝
    CHECK("buffer 0", udp_should_buffer_first_pkt(0) == 1);
    CHECK("buffer 1399", udp_should_buffer_first_pkt(1399) == 1);
    CHECK("buffer 1400 boundary", udp_should_buffer_first_pkt(1400) == 1);
    CHECK("buffer 1401", udp_should_buffer_first_pkt(1401) == 0);
    CHECK("buffer big", udp_should_buffer_first_pkt(65535) == 0);

    // 2. 閒置逾時：now - last_active > 330 才逾時
    CHECK("idle 329 below", udp_is_idle(329, 0) == 0);
    CHECK("idle 330 boundary not exceed", udp_is_idle(330, 0) == 0);
    CHECK("idle 331 exceed", udp_is_idle(331, 0) == 1);
    CHECK("idle big gap", udp_is_idle(100000, 0) == 1);
    // last_active 較大（時鐘倒退/異常）→ 差為負，不逾時
    CHECK("idle last_active > now", udp_is_idle(0, 5) == 0);
    CHECK("idle equal", udp_is_idle(100, 100) == 0);

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
