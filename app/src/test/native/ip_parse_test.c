// ip_parse_test.c — IPv4/IPv6 頭與 fragment 表頭解析 golden test
// 建置：gcc -std=c11 -Wall -Wextra -I app/src/main/cpp ip_parse_test.c ip_parse.c -o ip_parse_test
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ip_parse.h"

static int g_fail = 0;

#define CHECK(name, cond) do { \
    if (cond) { printf("PASS  %s\n", name); } \
    else { printf("FAIL  %s\n", name); g_fail = 1; } \
} while (0)

int main(void) {
    uint8_t proto;
    ip_addr_t saddr, daddr;
    int ihl;

    // 1. parse_ipv4：基本 20-byte 頭（proto=UDP）
    {
        unsigned char pkt[20] = {0};
        pkt[0] = 0x45;   // ver 4, IHL 5
        pkt[9] = 17;     // proto UDP
        pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;   // src 10.0.0.1
        pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 1; // dst 192.168.1.1
        int r = parse_ipv4(pkt, 20, &proto, &saddr, &daddr, &ihl);
        CHECK("parse_ipv4 returns 0", r == 0);
        CHECK("parse_ipv4 proto", proto == 17);
        CHECK("parse_ipv4 ihl", ihl == 20);
        CHECK("parse_ipv4 src family", saddr.family == AF_INET);
        CHECK("parse_ipv4 src ip", memcmp(saddr.ip, "\x0a\x00\x00\x01", 4) == 0);
        CHECK("parse_ipv4 src ip zero pad", memcmp(saddr.ip + 4, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) == 0);
        CHECK("parse_ipv4 dst ip", memcmp(daddr.ip, "\xc0\xa8\x01\x01", 4) == 0);
    }

    // 2. parse_ipv4：長度不足
    {
        unsigned char pkt[10] = {0};
        CHECK("parse_ipv4 short len", parse_ipv4(pkt, 10, &proto, &saddr, &daddr, &ihl) == -1);
    }

    // 3. parse_ipv4：版本非 4
    {
        unsigned char pkt[20] = {0};
        pkt[0] = 0x60;   // ver 6
        CHECK("parse_ipv4 wrong version", parse_ipv4(pkt, 20, &proto, &saddr, &daddr, &ihl) == -1);
    }

    // 4. parse_ipv4：IHL 展開大於實際長度
    {
        unsigned char pkt[20] = {0};
        pkt[0] = 0x4F;   // IHL 15 -> 60 bytes > 20
        CHECK("parse_ipv4 ihl overflow", parse_ipv4(pkt, 20, &proto, &saddr, &daddr, &ihl) == -1);
    }

    // 5. parse_ipv6：基本 40-byte 頭（無 ext header）
    {
        unsigned char pkt[40] = {0};
        pkt[0] = 0x60;   // ver 6
        pkt[6] = 17;     // next header UDP
        pkt[23] = 1;     // src ::1
        pkt[24] = 0x20; pkt[25] = 0x01; pkt[26] = 0x0d; pkt[27] = 0xb8; // dst 2001:db8::1
        pkt[39] = 1;
        size_t l4off = 0;
        int r = parse_ipv6(pkt, 40, &proto, &saddr, &daddr, &l4off);
        CHECK("parse_ipv6 returns 0", r == 0);
        CHECK("parse_ipv6 proto", proto == 17);
        CHECK("parse_ipv6 l4off", l4off == 40);
        CHECK("parse_ipv6 src family", saddr.family == AF_INET6);
        CHECK("parse_ipv6 src ip ::1", saddr.ip[15] == 1 && saddr.ip[0] == 0);
        CHECK("parse_ipv6 dst ip 2001:db8::1", daddr.ip[0] == 0x20 && daddr.ip[1] == 0x01 && daddr.ip[15] == 1);
    }

    // 6. parse_ipv6：Hop-by-Hop ext header 鏈（8 bytes）→ UDP
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 0;      // Hop-by-Hop
        pkt[40] = 17;    // ext header 內的 next header = UDP
        pkt[41] = 0;     // hdr ext len = (0+1)*8 = 8
        size_t l4off = 0;
        int r = parse_ipv6(pkt, 48, &proto, &saddr, &daddr, &l4off);
        CHECK("parse_ipv6 hop-by-hop returns 0", r == 0);
        CHECK("parse_ipv6 hop-by-hop proto", proto == 17);
        CHECK("parse_ipv6 hop-by-hop l4off", l4off == 48);
    }

    // 7. parse_ipv6：Fragment header（需重組 → 丟棄）
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 44;     // Fragment
        size_t l4off = 0;
        CHECK("parse_ipv6 fragment drop", parse_ipv6(pkt, 48, &proto, &saddr, &daddr, &l4off) == -1);
    }

    // 8. ipv6_first_frag：首片（offset=0、M=1）
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 44;          // Fragment
        pkt[40] = 17;         // fragment 之後的 next header = UDP
        pkt[42] = 0x00; pkt[43] = 0x01;   // ff = 0x0001 → offset=0, M=1
        pkt[44] = 0x12; pkt[45] = 0x34; pkt[46] = 0x56; pkt[47] = 0x78; // id
        uint8_t next_hdr; size_t frag_off; int mf; uint32_t id;
        int r = ipv6_first_frag(pkt, 48, &next_hdr, &frag_off, &mf, &id);
        CHECK("ipv6_first_frag returns 1", r == 1);
        CHECK("ipv6_first_frag next_hdr", next_hdr == 17);
        CHECK("ipv6_first_frag frag_off first=0", frag_off == 0);
        CHECK("ipv6_first_frag mf", mf == 1);
        CHECK("ipv6_first_frag id", id == 0x12345678);
    }

    // 9. ipv6_first_frag：offset=1（ff=0x0008 → 高 13 位 = 1 → frag_off=8）
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 44;
        pkt[42] = 0x00; pkt[43] = 0x08;   // offset=1, M=0
        uint8_t next_hdr; size_t frag_off; int mf; uint32_t id;
        CHECK("ipv6_first_frag offset=1", (ipv6_first_frag(pkt, 48, &next_hdr, &frag_off, &mf, &id) == 1 && frag_off == 8 && mf == 0));
    }

    // 9b. ipv6_first_frag：高位 offset（ff=0x8000 → offset=0x1000 → frag_off=0x8000）
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 44;
        pkt[42] = 0x80; pkt[43] = 0x00;   // offset=0x1000, M=0
        uint8_t next_hdr; size_t frag_off; int mf; uint32_t id;
        CHECK("ipv6_first_frag high offset", (ipv6_first_frag(pkt, 48, &next_hdr, &frag_off, &mf, &id) == 1 && frag_off == 0x1000u * 8 && mf == 0));
    }

    // 10. ipv6_first_frag：非 fragment（pkt[6] != 44）
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 17;   // UDP
        uint8_t next_hdr; size_t frag_off; int mf; uint32_t id;
        CHECK("ipv6_first_frag not fragment", ipv6_first_frag(pkt, 48, &next_hdr, &frag_off, &mf, &id) == 0);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
