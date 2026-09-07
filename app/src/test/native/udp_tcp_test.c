// udp_tcp_test.c — UDP-in-TCP length-prefixed frame 串流 parser golden test
// 驗證 udp_tcp_consume 的長度解析、邊界檢查與跨 recv 邊界的狀態保留。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "udp_tcp.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

// 回呼記錄：記下最後一個 frame 的 payload 與長度、以及 frame 總數
static const unsigned char *g_last;
static size_t g_last_len;
static int g_count;

static void rec_cb(void *ctx, const unsigned char *payload, size_t payload_len) {
    (void)ctx;
    g_last = payload; g_last_len = payload_len; g_count++;
}

static void reset(void) { g_last = NULL; g_last_len = 0; g_count = 0; }

int main(void) {
    udp_tcp_stream_t st;

    // 1. 空 / 不足 2-byte 長度前綴
    udp_tcp_stream_init(&st); reset();
    CHECK("len=0", udp_tcp_consume(&st, (const unsigned char*)"", 0, 8192, rec_cb, NULL) == 0);
    CHECK("len=0 無 frame", g_count == 0);
    udp_tcp_stream_init(&st); reset();
    CHECK("len=1 不足前綴", udp_tcp_consume(&st, (const unsigned char*)"\x00", 1, 8192, rec_cb, NULL) == 0);

    // 2. 單一完整 frame：長度 4 + 4 bytes payload
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x04, 'a', 'b', 'c', 'd'};
        CHECK("單一完整 frame 消費 6", udp_tcp_consume(&st, b, 6, 8192, rec_cb, NULL) == 6);
        CHECK("單一 frame 呼叫 1 次且 payload 正確",
              g_count == 1 && g_last_len == 4 && memcmp(g_last, "abcd", 4) == 0);
    }

    // 3. 兩個完整 frame 於同一緩衝
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x04, 'a', 'b', 'c', 'd', 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
        CHECK("兩個完整 frame 消費 13", udp_tcp_consume(&st, b, 13, 8192, rec_cb, NULL) == 13);
        CHECK("兩個 frame 呼叫 2 次且末 frame 正確",
              g_count == 2 && g_last_len == 5 && memcmp(g_last, "hello", 5) == 0);
    }

    // 4. 第一個 frame 不完整（宣告 5 僅 1 byte payload）：僅消費 2-byte 長度欄
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x05, 'x'};
        CHECK("第一個 frame 不完整消費 2", udp_tcp_consume(&st, b, 3, 8192, rec_cb, NULL) == 2);
        CHECK("不完整無 frame 呼叫", g_count == 0);
    }

    // 5. 第二個 frame 不完整：第一個 frame 完整回報，第二 frame 的 2-byte 長度欄也被消費
    // （狀態機語意：長度欄完整即消費、payload 未完則停，等後續位元組補齊）
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x04, 'a', 'b', 'c', 'd', 0x00, 0x09, 'x'};
        CHECK("第二個 frame 不完整消費 8", udp_tcp_consume(&st, b, 9, 8192, rec_cb, NULL) == 8);
        CHECK("僅第一個 frame 呼叫", g_count == 1 && g_last_len == 4);
    }

    // 6. 跨 recv 邊界：先吃長度欄、再補 payload
    udp_tcp_stream_init(&st); reset();
    {
        CHECK("跨邊界: 長度欄消費 2", udp_tcp_consume(&st, (const unsigned char*)"\x00\x04", 2, 8192, rec_cb, NULL) == 2);
        CHECK("跨邊界: 長度欄後尚無 frame", g_count == 0);
        CHECK("跨邊界: payload 消費 4", udp_tcp_consume(&st, (const unsigned char*)"abcd", 4, 8192, rec_cb, NULL) == 4);
        CHECK("跨邊界: frame 呼叫 1 次且 payload 正確",
              g_count == 1 && g_last_len == 4 && memcmp(g_last, "abcd", 4) == 0);
    }

    // 7. 長度欄過小（<4）→ 協定違規
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x03, 'a', 'b', 'c'};
        CHECK("長度欄 3 違規", udp_tcp_consume(&st, b, 5, 8192, rec_cb, NULL) == -1);
    }

    // 8. 零長度 frame → 違規（UDP-in-TCP 拒絕 L=0）
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x00};
        CHECK("零長度 frame 違規", udp_tcp_consume(&st, b, 2, 8192, rec_cb, NULL) == -1);
    }

    // 9. 長度欄超過 cap → 違規；等於 cap → 合法
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char b[] = {0x00, 0x09, 'x'};
        CHECK("長度欄 9 超過 cap=8 違規", udp_tcp_consume(&st, b, 3, 8, rec_cb, NULL) == -1);
    }
    udp_tcp_stream_init(&st); reset();
    {
        unsigned char ok[] = {0x00, 0x08, 'a','b','c','d','e','f','g','h'};
        CHECK("長度欄等於 cap=8 合法", udp_tcp_consume(&st, ok, 10, 8, rec_cb, NULL) == 10);
        CHECK("等於 cap 呼叫 1 次且長度 8", g_count == 1 && g_last_len == 8);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}