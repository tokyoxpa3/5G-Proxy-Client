// icmp_packet_test.c — ICMP/ICMPv6 回覆建構 golden test
// 驗證 icmp4/icmp6 echo reply 與 NA 的欄位（type/位址交換/TTL/payload copy）與 checksum 正確性。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "icmp_packet.h"
#include "checksum.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

int main(void) {
    // 1. IPv4 echo reply
    {
        // IPv4 header (20B) + ICMP(8B) + payload "HELLO"(5B)
        unsigned char req[64]; memset(req, 0, sizeof req);
        req[0] = 0x45;                         // version 4, IHL 5
        req[1] = 0;
        req[2] = 0; req[3] = 33;               // total len 33
        req[4] = 0x12; req[5] = 0x34;          // id
        req[6] = 0; req[7] = 0;
        req[8] = 64; req[9] = 1;               // TTL, proto=ICMP
        // src 10.0.0.1
        req[12]=10; req[13]=0; req[14]=0; req[15]=1;
        // dst 8.8.8.8
        req[16]=8; req[17]=8; req[18]=8; req[19]=8;
        // IP checksum 0（建構時會重算）
        req[20] = 8; req[21] = 0;              // ICMP type=8 code=0
        req[22] = 0; req[23] = 0;              // ICMP checksum
        req[24] = 0x12; req[25] = 0x34;        // id
        req[26] = 0; req[27] = 1;              // seq
        memcpy(req + 28, "HELLO", 5);

        unsigned char src[4] = {8,8,8,8}, dst[4] = {10,0,0,1};  // 回覆方向：src=原始 dst
        unsigned char out[128];
        ssize_t n = icmp4_build_echo_reply(req, 33, 20, src, dst, out, sizeof out);
        CHECK("icmp4 reply len", n == 33);
        CHECK("icmp4 type echo reply", out[20] == 0);
        CHECK("icmp4 src swapped", memcmp(out+12, src, 4) == 0);
        CHECK("icmp4 dst swapped", memcmp(out+16, dst, 4) == 0);
        CHECK("icmp4 ttl 64", out[8] == 64);
        CHECK("icmp4 payload preserved", memcmp(out+28, "HELLO", 5) == 0);

        // IP header checksum roundtrip
        unsigned char iph[20]; memcpy(iph, out, 20); iph[10]=0; iph[11]=0;
        uint16_t ip_stored = (out[10] << 8) | out[11];
        CHECK("icmp4 ip checksum", ip_stored == checksum16(iph, 20));
        // ICMP checksum roundtrip
        unsigned char icmp[13]; memcpy(icmp, out+20, 13); icmp[2]=0; icmp[3]=0;
        uint16_t icmp_stored = (out[22] << 8) | out[23];
        CHECK("icmp4 icmp checksum", icmp_stored == checksum16(icmp, 13));
    }
    // 2. IPv6 echo reply
    {
        unsigned char req[64]; memset(req, 0, sizeof req);
        req[0] = 0x60;                         // version 6
        req[4] = 0; req[5] = 13;               // payload len = 8+5
        req[6] = 58; req[7] = 64;              // next=ICMPv6, hop=64
        // src fd00::1
        req[8]=0xfd; req[23]=1;
        // dst 2001:db8::1
        req[24]=0x20; req[25]=0x01; req[26]=0x0d; req[27]=0xb8; req[39]=1;
        req[40] = 128; req[41] = 0;            // ICMPv6 echo request
        req[42] = 0; req[43] = 0;              // checksum
        req[44] = 0x12; req[45] = 0x34; req[46] = 0; req[47] = 1;
        memcpy(req + 48, "HELLO", 5);

        unsigned char src[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        unsigned char dst[16] = {0xfd,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        unsigned char out[128];
        ssize_t n = icmp6_build_echo_reply(req, 53, src, dst, out, sizeof out);
        CHECK("icmp6 reply len", n == 53);
        CHECK("icmp6 type echo reply", out[40] == 129);
        CHECK("icmp6 src swapped", memcmp(out+8, src, 16) == 0);
        CHECK("icmp6 dst swapped", memcmp(out+24, dst, 16) == 0);
        CHECK("icmp6 hop 64", out[7] == 64);
        CHECK("icmp6 payload preserved", memcmp(out+48, "HELLO", 5) == 0);

        // ICMPv6 checksum roundtrip（含 pseudo-header）
        unsigned char icmp6[13]; memcpy(icmp6, out+40, 13); icmp6[2]=0; icmp6[3]=0;
        uint16_t icmp6_stored = (out[42] << 8) | out[43];
        CHECK("icmp6 checksum", icmp6_stored == tcpudp_checksum6(src, dst, 58, icmp6, 13));
    }
    // 3. Neighbor Advertisement
    {
        unsigned char target[16] = {0xfd,0,0,0,0,0,0,0,0,0,0,0,0,0x5e,0,1};
        unsigned char from[16]   = {0xfd,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
        unsigned char out[64];
        ssize_t n = icmp6_build_na(target, from, out, sizeof out);
        CHECK("na len 64", n == 64);
        CHECK("na ipv6 version", out[0] == 0x60);
        CHECK("na next header icmpv6", out[6] == 58);
        CHECK("na type 136", out[40] == 136);
        CHECK("na flags R0 S1 O1", out[44] == 0x60);
        CHECK("na src = target", memcmp(out+8, target, 16) == 0);
        CHECK("na dst = from", memcmp(out+24, from, 16) == 0);
        CHECK("na target field", memcmp(out+48, target, 16) == 0);

        // NA ICMPv6 checksum roundtrip
        unsigned char na[24]; memcpy(na, out+40, 24); na[2]=0; na[3]=0;
        uint16_t na_stored = (out[42] << 8) | out[43];
        CHECK("na checksum", na_stored == tcpudp_checksum6(target, from, 58, na, 24));
    }
    // 4. 邊界：out_cap 不足 / ihl 非法 回 -1
    {
        unsigned char req[64], out[16];
        unsigned char ip[4] = {1,2,3,4};
        CHECK("icmp4 cap too small", icmp4_build_echo_reply(req, 33, 20, ip, ip, out, 16) == -1);
        CHECK("icmp4 ihl too small", icmp4_build_echo_reply(req, 33, 4, ip, ip, out, sizeof out) == -1);
        CHECK("icmp6 too short", icmp6_build_echo_reply(req, 40, ip, ip, out, sizeof out) == -1);
        CHECK("na cap too small", icmp6_build_na(ip, ip, out, 63) == -1);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
