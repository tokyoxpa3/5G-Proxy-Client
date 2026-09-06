// ip_parse_test.c — IPv4/IPv6 頭與 fragment 表頭解析 golden test
// 建置：gcc -std=c11 -Wall -Wextra -I app/src/main/cpp ip_parse_test.c ip_parse.c reasm.c -o ip_parse_test
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ip_parse.h"
#include "reasm.h"

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

    // 12. ipv6_find_fragment：Fragment 為首個 ext header
    {
        unsigned char pkt[48] = {0};
        pkt[0] = 0x60;
        pkt[6] = 44;          // Fragment（首個 ext header）
        pkt[40] = 17;         // Fragment 的 next header = UDP
        pkt[42] = 0x00; pkt[43] = 0x01;   // offset=0, M=1
        pkt[44] = 0x12; pkt[45] = 0x34; pkt[46] = 0x56; pkt[47] = 0x78;
        uint8_t nh; size_t fo; int m; uint32_t id;
        size_t fdo, pre, po;
        int r = ipv6_find_fragment(pkt, 48, &nh, &fo, &m, &id, &fdo, &pre, &po);
        CHECK("find_frag first returns 1", r == 1);
        CHECK("find_frag first nh=UDP", nh == 17);
        CHECK("find_frag first frag_data_off=48", fdo == 48);
        CHECK("find_frag first pre_frag_len=40", pre == 40);
        CHECK("find_frag first patch_off=6", po == 6);
        CHECK("find_frag first id", id == 0x12345678);
        CHECK("find_frag first mf/off", m == 1 && fo == 0);
    }

    // 13. ipv6_find_fragment：Fragment 巢狀於 Hop-by-Hop 之後
    {
        unsigned char pkt[64] = {0};
        pkt[0] = 0x60;
        pkt[6] = 0;            // Hop-by-Hop
        pkt[40] = 44;          // Hop-by-Hop 的 next header = Fragment
        pkt[41] = 0;           // hdr ext len = (0+1)*8 = 8
        pkt[48] = 17;          // Fragment 的 next header = UDP
        pkt[50] = 0x00; pkt[51] = 0x08;   // offset=1, M=0
        pkt[52] = 0xAA; pkt[53] = 0xBB; pkt[54] = 0xCC; pkt[55] = 0xDD;
        uint8_t nh; size_t fo; int m; uint32_t id;
        size_t fdo, pre, po;
        int r = ipv6_find_fragment(pkt, 64, &nh, &fo, &m, &id, &fdo, &pre, &po);
        CHECK("find_frag nested returns 1", r == 1);
        CHECK("find_frag nested nh=UDP", nh == 17);
        CHECK("find_frag nested frag_off=8", fo == 8);
        CHECK("find_frag nested mf=0", m == 0);
        CHECK("find_frag nested id", id == 0xAABBCCDD);
        CHECK("find_frag nested frag_data_off=56", fdo == 56);
        CHECK("find_frag nested pre_frag_len=48", pre == 48);
        CHECK("find_frag nested patch_off=40", po == 40);
    }

    // 14. ipv6_find_fragment：無 fragment（L4 直達）
    {
        unsigned char pkt[40] = {0};
        pkt[0] = 0x60;
        pkt[6] = 17;           // UDP
        uint8_t nh; size_t fo; int m; uint32_t id;
        size_t fdo, pre, po;
        CHECK("find_frag none returns 0", ipv6_find_fragment(pkt, 40, &nh, &fo, &m, &id, &fdo, &pre, &po) == 0);
    }

    // 15. ip6_reasm_rebuild：首片（Fragment 為首個 ext header）
    {
        unsigned char hdr[40] = {0};
        hdr[0] = 0x60;
        hdr[6] = 44;           // base next header = Fragment（待移除）
        unsigned char payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
        unsigned char out[64];
        int n = ip6_reasm_rebuild(hdr, 40, 6, 17, payload, 4, out, sizeof out);
        CHECK("rebuild first len=44", n == 44);
        CHECK("rebuild first next_hdr=UDP", out[6] == 17);
        CHECK("rebuild first payload_len=4", out[4] == 0 && out[5] == 4);
        CHECK("rebuild first payload", memcmp(out + 40, payload, 4) == 0);
    }

    // 16. ip6_reasm_rebuild：巢狀（Fragment 在 Hop-by-Hop 之後）
    {
        unsigned char hdr[48] = {0};
        hdr[0] = 0x60;
        hdr[6] = 0;            // Hop-by-Hop
        hdr[40] = 44;          // Hop-by-Hop 的 next header = Fragment（待移除）
        hdr[41] = 0;
        unsigned char payload[] = {0x01, 0x02};
        unsigned char out[64];
        int n = ip6_reasm_rebuild(hdr, 48, 40, 17, payload, 2, out, sizeof out);
        CHECK("rebuild nested len=50", n == 50);
        CHECK("rebuild nested next_hdr patched", out[40] == 17);
        CHECK("rebuild nested base next_hdr=Hop-by-Hop", out[6] == 0);
        CHECK("rebuild nested payload_len=10", out[4] == 0 && out[5] == 10);
        CHECK("rebuild nested payload", memcmp(out + 48, payload, 2) == 0);
    }

    // 17. 端到端多分片重組：Fragment 為首個 ext header
    //（frag0 offset=0/M=1 + frag1 offset=8/M=0 → reasm_insert_seg 完成 → ip6_reasm_rebuild）
    {
        unsigned char f0[56] = {0};
        f0[0] = 0x60; f0[6] = 44;          // Fragment
        f0[40] = 17;                        // Fragment.next = UDP
        f0[42] = 0x00; f0[43] = 0x01;       // offset=0, M=1
        f0[44] = 0x12; f0[45] = 0x34; f0[46] = 0x56; f0[47] = 0x78;
        unsigned char d0[8] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7};
        memcpy(f0 + 48, d0, 8);

        unsigned char f1[52] = {0};
        f1[0] = 0x60; f1[6] = 44;
        f1[40] = 17;
        f1[42] = 0x00; f1[43] = 0x08;       // offset=1(×8)=8, M=0
        f1[44] = 0x12; f1[45] = 0x34; f1[46] = 0x56; f1[47] = 0x78;
        unsigned char d1[4] = {0xB0,0xB1,0xB2,0xB3};
        memcpy(f1 + 48, d1, 4);

        size_t soff[REASM_MAX_FRAGS], slen[REASM_MAX_FRAGS];
        int nseg = 0;
        unsigned char rbuf[64];
        size_t total_len = 0; int have_last = 0;
        unsigned char pre_hdr[40]; size_t pre_len = 0, patch_off = 0, fdo; uint8_t proto = 0;

        uint8_t nh0; uint32_t id0; size_t fo0; int mf0;
        int r0 = ipv6_find_fragment(f0, 56, &nh0, &fo0, &mf0, &id0, &fdo, &pre_len, &patch_off);
        CHECK("e2e frag0 parse", r0 == 1 && nh0 == 17 && fo0 == 0 && mf0 == 1 && pre_len == 40 && patch_off == 6);
        memcpy(pre_hdr, f0, pre_len);
        proto = nh0;
        CHECK("e2e frag0 insert not done", reasm_insert_seg(soff, slen, &nseg, rbuf, fo0, f0 + fdo, 8, mf0, &total_len, &have_last) == 0);

        uint8_t nh1; uint32_t id1; size_t fo1; int mf1;
        int r1 = ipv6_find_fragment(f1, 52, &nh1, &fo1, &mf1, &id1, &fdo, &pre_len, &patch_off);
        CHECK("e2e frag1 parse", r1 == 1 && fo1 == 8 && mf1 == 0);
        CHECK("e2e frag1 insert done", reasm_insert_seg(soff, slen, &nseg, rbuf, fo1, f1 + fdo, 4, mf1, &total_len, &have_last) == 1);
        CHECK("e2e total_len=12", total_len == 12);

        unsigned char out[64];
        int n = ip6_reasm_rebuild(pre_hdr, 40, 6, proto, rbuf, total_len, out, sizeof out);
        CHECK("e2e rebuild len=52", n == 52);
        CHECK("e2e rebuild next=UDP", out[6] == 17);
        CHECK("e2e rebuild payload_len=12", out[4] == 0 && out[5] == 12);
        CHECK("e2e rebuild payload order", memcmp(out + 40, d0, 8) == 0 && memcmp(out + 48, d1, 4) == 0);
    }

    // 18. 端到端多分片重組：Fragment 巢狀於 Hop-by-Hop 之後
    {
        unsigned char f0[64] = {0};
        f0[0] = 0x60; f0[6] = 0;            // Hop-by-Hop
        f0[40] = 44; f0[41] = 0;            // Hop-by-Hop.next=Fragment, hdr ext len=8
        f0[48] = 17;                        // Fragment.next = UDP
        f0[50] = 0x00; f0[51] = 0x01;       // offset=0, M=1
        f0[52]=0x12; f0[53]=0x34; f0[54]=0x56; f0[55]=0x78;
        unsigned char d0[8] = {0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7};
        memcpy(f0 + 56, d0, 8);

        unsigned char f1[60] = {0};
        f1[0] = 0x60; f1[6] = 0;
        f1[40] = 44; f1[41] = 0;
        f1[48] = 17;
        f1[50] = 0x00; f1[51] = 0x08;       // offset=8, M=0
        f1[52]=0x12; f1[53]=0x34; f1[54]=0x56; f1[55]=0x78;
        unsigned char d1[4] = {0xD0,0xD1,0xD2,0xD3};
        memcpy(f1 + 56, d1, 4);

        size_t soff[REASM_MAX_FRAGS], slen[REASM_MAX_FRAGS];
        int nseg = 0;
        unsigned char rbuf[64];
        size_t total_len = 0; int have_last = 0;
        unsigned char pre_hdr[48]; size_t pre_len, patch_off, fdo; uint8_t proto;

        uint8_t nh0; uint32_t id0; size_t fo0; int mf0;
        int r0 = ipv6_find_fragment(f0, 64, &nh0, &fo0, &mf0, &id0, &fdo, &pre_len, &patch_off);
        CHECK("e2e nested frag0 parse", r0 == 1 && nh0 == 17 && fo0 == 0 && mf0 == 1 && pre_len == 48 && patch_off == 40);
        memcpy(pre_hdr, f0, pre_len);
        proto = nh0;
        CHECK("e2e nested frag0 insert", reasm_insert_seg(soff, slen, &nseg, rbuf, fo0, f0 + fdo, 8, mf0, &total_len, &have_last) == 0);

        uint8_t nh1; uint32_t id1; size_t fo1; int mf1;
        int r1 = ipv6_find_fragment(f1, 60, &nh1, &fo1, &mf1, &id1, &fdo, &pre_len, &patch_off);
        CHECK("e2e nested frag1 parse", r1 == 1 && fo1 == 8 && mf1 == 0);
        CHECK("e2e nested frag1 insert done", reasm_insert_seg(soff, slen, &nseg, rbuf, fo1, f1 + fdo, 4, mf1, &total_len, &have_last) == 1);
        CHECK("e2e nested total_len=12", total_len == 12);

        unsigned char out[64];
        int n = ip6_reasm_rebuild(pre_hdr, 48, 40, proto, rbuf, total_len, out, sizeof out);
        CHECK("e2e nested rebuild len=60", n == 60);
        CHECK("e2e nested base next=Hop-by-Hop", out[6] == 0);
        CHECK("e2e nested patched=UDP", out[40] == 17);
        CHECK("e2e nested payload_len=20", out[4] == 0 && out[5] == 20);
        CHECK("e2e nested payload", memcmp(out + 48, d0, 8) == 0 && memcmp(out + 56, d1, 4) == 0);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
