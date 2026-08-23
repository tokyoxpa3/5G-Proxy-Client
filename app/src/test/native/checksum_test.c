// checksum_test.c — host 端單元測試（gcc/clang 直接編譯執行，不需 Android）
// 建置：gcc -std=c11 -Wall -Wextra checksum_test.c checksum.c -o checksum_test
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "checksum.h"

static int g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("PASS  %s\n", name); } \
    else { printf("FAIL  %s\n", name); g_fail = 1; } \
} while (0)

int main(void) {
    // 1. checksum16：RFC 1071 經典範例（IP header，checksum 欄位為 0）
    //    45 00 00 73 00 00 40 00 40 11 00 00 0a 00 00 01 14 03 0a 0c → 0x126b
    {
        const unsigned char hdr[20] = {
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
            0x14, 0x03, 0x0a, 0x0c
        };
        uint16_t c = checksum16(hdr, sizeof hdr);
        printf("  checksum16(RFC1071 header) = 0x%04x (expect 0x126b)\n", c);
        CHECK("checksum16 RFC1071 example", c == 0x126b);
    }

    // 2. checksum16 空資料 = 0xffff（一補數零）
    {
        uint16_t c = checksum16((const unsigned char *)"", 0);
        printf("  checksum16(empty) = 0x%04x (expect 0xffff)\n", c);
        CHECK("checksum16 empty -> 0xffff", c == 0xffff);
    }

    // 3. checksum16 奇數長度（1 byte 0x01 → sum=0x0100 → ~0xfeff → swap 0xfeff）
    {
        const unsigned char d = 0x01;
        uint16_t c = checksum16(&d, 1);
        printf("  checksum16([0x01]) = 0x%04x (expect 0xfeff)\n", c);
        CHECK("checksum16 single byte", c == 0xfeff);
    }

    // 4. UDP/IPv4 偽表頭 checksum（參考值由獨立 Python 實作驗證）：
    //    src 10.0.0.1, dst 14.3.0.12, proto 17, UDP datagram len=9
    //    datagram: 12 34 56 78 00 09 00 00 01 → 0x7e20
    {
        const unsigned char saddr[4] = {10, 0, 0, 1};
        const unsigned char daddr[4] = {14, 3, 0, 12};
        const unsigned char datagram[9] = {
            0x12, 0x34, 0x56, 0x78, 0x00, 0x09, 0x00, 0x00, 0x01
        };
        uint16_t c = tcpudp_checksum4(saddr, daddr, 17, datagram, sizeof datagram);
        printf("  udp_checksum4 = 0x%04x (expect 0x7e20)\n", c);
        CHECK("tcpudp_checksum4 verified", c == 0x7e20);
    }

    // 5. IPv6 UDP 偽表頭（參考值 0x6875）：::1 -> 2001:db8::1, proto 17, len 9
    {
        const unsigned char saddr6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        const unsigned char daddr6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        const unsigned char datagram[9] = {
            0x12, 0x34, 0x56, 0x78, 0x00, 0x09, 0x00, 0x00, 0x01
        };
        uint16_t c = tcpudp_checksum6(saddr6, daddr6, 17, datagram, sizeof datagram);
        printf("  udp_checksum6 = 0x%04x (expect 0x6875)\n", c);
        CHECK("tcpudp_checksum6 verified", c == 0x6875);
    }

    // 6. transport_checksum 依 family 分派
    {
        const unsigned char saddr4[4] = {1,2,3,4};
        const unsigned char daddr4[4] = {5,6,7,8};
        const unsigned char d = 0x00;
        uint16_t c4 = transport_checksum(AF_INET, saddr4, daddr4, 6, &d, 1);
        uint16_t c46 = tcpudp_checksum4(saddr4, daddr4, 6, &d, 1);
        CHECK("transport_checksum(AF_INET) == tcpudp_checksum4", c4 == c46);

        const unsigned char saddr6[16] = {0};
        const unsigned char daddr6[16] = {0};
        uint16_t c6 = transport_checksum(AF_INET6, saddr6, daddr6, 6, &d, 1);
        uint16_t c66 = tcpudp_checksum6(saddr6, daddr6, 6, &d, 1);
        CHECK("transport_checksum(AF_INET6) == tcpudp_checksum6", c6 == c66);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
