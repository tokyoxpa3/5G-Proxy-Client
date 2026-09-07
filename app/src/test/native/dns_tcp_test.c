// dns_tcp_test.c — DNS-over-TCP length-prefixed frame 掃描 golden test
// 驗證 dns_tcp_scan_frames 的長度解析與邊界檢查（完整/不完整/空/零長度/最大長度），
// 以及 dns_tcp_frame_len 的 2-byte 網路序長度讀取。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "dns_tcp.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

int main(void) {
    // 1. 空 / 單一位元組（不足 2-byte 長度前綴）
    CHECK("len=0", dns_tcp_scan_frames((const unsigned char*)"", 0) == 0);
    CHECK("len=1 不足前綴", dns_tcp_scan_frames((const unsigned char*)"\x00", 1) == 0);

    // 2. 單一完整 frame：2-byte 長度=4 + 4 bytes payload
    {
        unsigned char b[] = {0x00, 0x04, 'a', 'b', 'c', 'd'};
        CHECK("單一完整 frame", dns_tcp_scan_frames(b, 6) == 6);
    }
    // 3. 兩個完整 frame：(2+4) + (2+3) = 11
    {
        unsigned char b[] = {0x00, 0x02, 'x', 'x', 0x00, 0x03, 'y', 'y', 'y'};
        CHECK("兩個完整 frame", dns_tcp_scan_frames(b, 9) == 9);
    }
    // 4. 第一個 frame 不完整（宣告 5 但僅 1 byte payload）
    {
        unsigned char b[] = {0x00, 0x05, 'x'};
        CHECK("第一個 frame 不完整", dns_tcp_scan_frames(b, 3) == 0);
    }
    // 5. 第二個 frame 不完整：僅回報第一個 frame 的 4 bytes
    {
        unsigned char b[] = {0x00, 0x02, 'x', 'x', 0x00, 0x05, 'y'};
        CHECK("第二個 frame 不完整", dns_tcp_scan_frames(b, 7) == 4);
    }
    // 6. 零長度 frame：每 frame 僅 2-byte 前綴（mlen=0）
    {
        unsigned char b[] = {0x00, 0x00, 0x00, 0x00};
        CHECK("兩個零長度 frame", dns_tcp_scan_frames(b, 4) == 4);
    }
    // 7. 邊界：len=2 且 mlen=0 → 一個剛好填滿的零長度 frame
    {
        unsigned char b[] = {0x00, 0x00};
        CHECK("單一零長度 frame 剛好填滿", dns_tcp_scan_frames(b, 2) == 2);
    }

    // 8. frame_len：2-byte 網路序長度讀取
    {
        unsigned char b[] = {0x00, 0x04};
        CHECK("frame_len 4", dns_tcp_frame_len(b) == 4);
        unsigned char m[] = {0xFF, 0xFF};
        CHECK("frame_len 65535", dns_tcp_frame_len(m) == 65535);
        unsigned char h[] = {0x01, 0x00};
        CHECK("frame_len 256", dns_tcp_frame_len(h) == 256);
    }

    // 9. 最大長度 frame：0xFFFF + 65535 bytes payload = 65537（完整）
    {
        size_t cap = 2 + 65535;
        unsigned char *b = (unsigned char *)malloc(cap);
        b[0] = 0xFF; b[1] = 0xFF;
        for (size_t i = 2; i < cap; i++) b[i] = (unsigned char)(i & 0xFF);
        CHECK("最大長度 frame 完整", dns_tcp_scan_frames(b, cap) == cap);
        // 少 1 byte payload → 不完整，回 0
        CHECK("最大長度差 1 byte 不完整", dns_tcp_scan_frames(b, cap - 1) == 0);
        free(b);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
