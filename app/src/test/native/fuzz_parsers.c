// fuzz_parsers.c — 封包解析器的模糊測試 harness（deterministic mutation fuzzer）
//
// 以固定種子的 xorshift64* PRNG 產生隨機封包，餵給所有「吃不可信輸入」的純解析函式。
// 在 ASan/UBSan 下編譯執行，任何越界/未定義行為會中止（非零 exit），由 CI 判定失敗。
//
// 建置（host 端 gcc + sanitizer）：
//   gcc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
//       -I app/src/main/cpp -o fuzz_parsers \
//       fuzz_parsers.c ip_parse.c reasm.c dns_synth.c socks5_codec.c tcp_packet.c checksum.c
// 執行：./fuzz_parsers [iterations]
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ip_parse.h"
#include "reasm.h"
#include "dns_query.h"
#include "dns_synth.h"
#include "dns_tcp.h"
#include "socks5_codec.h"
#include "tcp_packet.h"
#include "checksum.h"

// xorshift64*：deterministic、快速、足夠好的 fuzz PRNG
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}
static uint32_t rnd_range(uint32_t n) { return n ? (uint32_t)(rng_next() % n) : 0; }

#define MAX_IN 512
#define OUT_CAP 2048
#define DNS_CAP 512
#define REASM_BUF (REASM_MAX_SIZE + 1)

static unsigned char in[MAX_IN];      // 主要隨機輸入（呼叫 strlen 前以 in[MAX_IN-1]=0 保證 NUL 終止）
static unsigned char out[OUT_CAP];
static unsigned char dnsout[DNS_CAP];
static unsigned char rbuf[REASM_BUF];
static unsigned char pre[64];

static void fill_random(void) {
    for (int i = 0; i < MAX_IN; i++) in[i] = (unsigned char)rng_next();
    // 保證 null-terminated，使 socks5_build_hello/auth 的 strlen 不會越界
    //（strlen 最壞掃到 in[511]，仍在緩衝內）
    in[MAX_IN - 1] = 0;
    // 偏向 valid header 的結構化輸入，讓 fuzz 深入版本判斷後的分支
    uint32_t mode = rnd_range(4);
    if (mode == 0) { in[0] = 0x45; in[9] = (unsigned char)(1 + rnd_range(16)); }   // IPv4-ish
    else if (mode == 1) { in[0] = 0x60; in[6] = (unsigned char)rnd_range(64); }    // IPv6-ish
}

static void fuzz_parse(void) {
    uint8_t proto; int ihl;
    ip_addr_t sa, da; size_t l4off, fdo, prelen, po, fo; int mf; uint32_t id;
    fill_random();
    size_t len = rnd_range(MAX_IN + 1);

    (void)parse_ipv4(in, len, &proto, &sa, &da, &ihl);
    (void)parse_ipv6(in, len, &proto, &sa, &da, &l4off);
    (void)ipv6_find_fragment(in, len, &proto, &fo, &mf, &id, &fdo, &prelen, &po);
    // 重建：pre 取隨機輸入的前 64 bytes（含可能的 base header），長度受限
    memcpy(pre, in, sizeof pre);
    (void)ip6_reasm_rebuild(pre, rnd_range(sizeof pre), rnd_range(sizeof pre),
                            proto, in, rnd_range(MAX_IN), out, sizeof out);
}

static void fuzz_reasm(void) {
    size_t soff[REASM_MAX_FRAGS], slen[REASM_MAX_FRAGS];
    int nseg = 0, have_last = 0; size_t total = 0;
    fill_random();
    for (int i = 0; i < 4; i++) {
        size_t off = rnd_range(REASM_MAX_SIZE);
        size_t dlen = rnd_range(MAX_IN + 1);
        int mf = (int)rnd_range(2);
        (void)reasm_insert_seg(soff, slen, &nseg, rbuf, off, in, dlen, mf, &total, &have_last);
    }
}

static void fuzz_dns(void) {
    unsigned char fake6[16]; size_t rlen;
    char name[256]; uint16_t qtype, qclass; int supported; size_t qend;
    fill_random();
    dns_build_fake_ip6((int)rnd_range(1000), fake6);
    (void)dns_build_reply_pure(in, rnd_range(MAX_IN + 1),
                               (uint32_t)rng_next(), fake6, (int)rnd_range(2), dnsout, &rlen);
    (void)dns_query_parse(in, rnd_range(MAX_IN + 1), name, sizeof name,
                          &qtype, &qclass, &supported, &qend);
}

static void fuzz_dns_tcp(void) {
    fill_random();
    (void)dns_tcp_scan_frames(in, rnd_range(MAX_IN + 1));
    // 直接以安全偏移呼叫 frame_len（in 至少 2 位元組餘量，涵蓋長度讀取本身）
    (void)dns_tcp_frame_len(in + rnd_range(MAX_IN - 1));
}

static void fuzz_socks5(void) {
    unsigned char src[16]; int fam; uint16_t port; char domain[256];
    const unsigned char *pld; size_t plen;
    fill_random();
    (void)socks5_build_udp_datagram(in, AF_INET, (uint16_t)rng_next(), NULL,
                                    in, rnd_range(MAX_IN), out, sizeof out);
    (void)socks5_build_udp_frame(in, AF_INET6, (uint16_t)rng_next(), NULL,
                                 in, rnd_range(MAX_IN), out, sizeof out);
    (void)socks5_build_connect_request(in, AF_INET, (uint16_t)rng_next(), "example.com", out, sizeof out);
    (void)socks5_build_hello((const char *)in, (const char *)in, out, sizeof out);
    (void)socks5_build_auth((const char *)in, (const char *)in, out, sizeof out);
    (void)socks5_parse_udp_datagram(in, rnd_range(MAX_IN + 1),
                                    src, &fam, &port, domain, sizeof domain, &pld, &plen);
}

static void fuzz_tcp(void) {
    fill_random();
    (void)tcp_build_segment(in, in, AF_INET, (uint16_t)rng_next(), (uint16_t)rng_next(),
                            (uint32_t)rng_next(), (uint32_t)rng_next(), (uint8_t)rng_next(),
                            in, rnd_range(MAX_IN), (uint16_t)rng_next(), out, sizeof out);
    (void)tcp_build_segment(in, in, AF_INET6, (uint16_t)rng_next(), (uint16_t)rng_next(),
                            (uint32_t)rng_next(), (uint32_t)rng_next(), (uint8_t)rng_next(),
                            in, rnd_range(MAX_IN), (uint16_t)rng_next(), out, sizeof out);
    (void)tcp_build_synack(in, in, AF_INET, (uint16_t)rng_next(), (uint16_t)rng_next(),
                           (uint32_t)rng_next(), (uint32_t)rng_next(),
                           (uint16_t)rng_next(), (uint16_t)rng_next(), (uint8_t)rng_next(),
                           out, sizeof out);
    (void)udp_build_packet(in, in, AF_INET, (uint16_t)rng_next(), (uint16_t)rng_next(),
                           in, rnd_range(MAX_IN), out, sizeof out);
    (void)tcp_parse_window_scale(in, rnd_range(MAX_IN));
    (void)tcp_seq_gt((uint32_t)rng_next(), (uint32_t)rng_next());
    (void)tcp_win_field_pure(rnd_range(MAX_IN), rnd_range(MAX_IN) + 1);
}

static void fuzz_checksum(void) {
    fill_random();
    (void)checksum16(in, rnd_range(MAX_IN + 1));
    (void)tcpudp_checksum4(in, in, (uint8_t)rng_next(), in, rnd_range(MAX_IN + 1));
    (void)tcpudp_checksum6(in, in, (uint8_t)rng_next(), in, rnd_range(MAX_IN + 1));
    (void)transport_checksum(AF_INET, in, in, (uint8_t)rng_next(), in, rnd_range(MAX_IN + 1));
    (void)transport_checksum(AF_INET6, in, in, (uint8_t)rng_next(), in, rnd_range(MAX_IN + 1));
}

int main(int argc, char **argv) {
    unsigned long iters = 200000;
    if (argc > 1) iters = strtoul(argv[1], NULL, 10);
    fprintf(stderr, "fuzz_parsers: %lu iterations, seed=0x%016llx\n",
            iters, (unsigned long long)rng_state);
    for (unsigned long i = 0; i < iters; i++) {
        fuzz_parse();
        fuzz_reasm();
        fuzz_dns();
        fuzz_dns_tcp();
        fuzz_socks5();
        fuzz_tcp();
        fuzz_checksum();
    }
    fprintf(stderr, "fuzz_parsers: PASS (%lu iterations)\n", iters);
    return 0;
}
