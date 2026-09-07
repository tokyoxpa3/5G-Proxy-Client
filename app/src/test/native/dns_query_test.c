// dns_query_test.c — DNS query 解析器 golden test
// 驗證 dns_query_parse 對合法 A/AAAA/HTTPS 的解析（name/qtype/qclass/supported/qend），
// 以及所有非法路徑（截斷/QR/opcode/qdcount/壓縮指標/label 超長/非法字元/名長度/qclass/段落越界）。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "dns_query.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

// 同 dns_synth_test.c：建構單一 question 的 DNS query（ID=0x1234, RD=1）
static size_t build_query(const char *domain, uint16_t qtype, unsigned char *out) {
    size_t o = 0;
    out[o++] = 0x12; out[o++] = 0x34; // ID
    out[o++] = 0x01; out[o++] = 0x00; // RD=1
    out[o++] = 0x00; out[o++] = 0x01; // QDCOUNT 1
    out[o++] = 0x00; out[o++] = 0x00; // AN
    out[o++] = 0x00; out[o++] = 0x00; // NS
    out[o++] = 0x00; out[o++] = 0x00; // AR
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        out[o++] = (unsigned char)l;
        memcpy(out + o, p, l); o += l;
        if (!dot) break;
        p = dot + 1;
    }
    out[o++] = 0;
    out[o++] = (qtype >> 8) & 0xFF; out[o++] = qtype & 0xFF;
    out[o++] = 0x00; out[o++] = 0x01;
    return o;
}

int main(void) {
    char name[256]; uint16_t qtype, qclass; int supported; size_t qend;

    // 1. 合法 A 查詢
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        int ok = dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend);
        CHECK("A query parse ok", ok == 1);
        CHECK("A query name", strcmp(name, "example.com") == 0);
        CHECK("A query qtype/qclass/supported", qtype == 1 && qclass == 1 && supported == 1);
        CHECK("A query qend", qend == qlen);
    }
    // 2. 合法 AAAA（多 label）
    {
        unsigned char q[512]; size_t qlen = build_query("a.b.example.com", 28, q);
        int ok = dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend);
        CHECK("AAAA query", ok == 1 && qtype == 28 && supported == 1 && strcmp(name, "a.b.example.com") == 0);
    }
    // 3. 合法 HTTPS (65)
    {
        unsigned char q[512]; size_t qlen = build_query("x.com", 65, q);
        int ok = dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend);
        CHECK("HTTPS query", ok == 1 && qtype == 65 && supported == 1);
    }
    // 4. 未知型別（MX 15）：解析成功但 supported=0
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 15, q);
        int ok = dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend);
        CHECK("unknown type parse", ok == 1 && qtype == 15 && supported == 0);
    }
    // 5. 截斷（qlen < 17）
    {
        unsigned char q[512]; build_query("example.com", 1, q);
        CHECK("truncated header", dns_query_parse(q, 16, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 6. QR 已設（不是查詢）
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        q[2] |= 0x80;
        CHECK("QR set rejected", dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 7. opcode 非 0
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        q[2] |= 0x08; // opcode=1
        CHECK("opcode rejected", dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 8. qdcount != 1
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        q[5] = 2;
        CHECK("qdcount rejected", dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 9. 壓縮指標（0xC0）
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        q[12] = 0xC0;
        CHECK("compression ptr rejected", dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 10. label 超長（>63）
    {
        unsigned char q[512]; size_t o = 0;
        q[o++] = 0x12; q[o++] = 0x34; q[o++] = 0x01; q[o++] = 0x00;
        q[o++] = 0x00; q[o++] = 0x01; q[o++] = 0x00; q[o++] = 0x00;
        q[o++] = 0x00; q[o++] = 0x00; q[o++] = 0x00; q[o++] = 0x00;
        q[o++] = 64; // label length 64
        for (int i = 0; i < 64; i++) q[o++] = 'a';
        q[o++] = 0; q[o++] = 0; q[o++] = 1; q[o++] = 0; q[o++] = 1;
        CHECK("label >63 rejected", dns_query_parse(q, o, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 11. label 越界（宣告 5 bytes，但剩餘不足）
    {
        unsigned char q[512]; size_t o = 0;
        q[o++] = 0x12; q[o++] = 0x34; q[o++] = 0x01; q[o++] = 0x00;
        q[o++] = 0x00; q[o++] = 0x01; q[o++] = 0x00; q[o++] = 0x00;
        q[o++] = 0x00; q[o++] = 0x00; q[o++] = 0x00; q[o++] = 0x00; // 12 bytes header
        q[o++] = 0x05; // QNAME 首 label 宣告 5
        q[o++] = 'a'; q[o++] = 'b'; q[o++] = 'c'; q[o++] = 'd'; // 僅 4 bytes
        CHECK("label overflow rejected", dns_query_parse(q, o, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 12. 非法字元
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        q[13] = '!'; // 'e' -> '!'（非白名單字元）
        CHECK("invalid char rejected", dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 13. qclass 非 IN
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        q[qlen - 1] = 0x03; // qclass 低 byte 由 0x01 改為 0x03（CH）
        CHECK("qclass non-IN rejected", dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 14. 空名（QNAME 直接為 0x00）
    {
        unsigned char q[512]; size_t o = 0;
        q[o++] = 0x12; q[o++] = 0x34; q[o++] = 0x01; q[o++] = 0x00;
        q[o++] = 0x00; q[o++] = 0x01; q[o++] = 0x00; q[o++] = 0x00;
        q[o++] = 0x00; q[o++] = 0x00; q[o++] = 0x00; q[o++] = 0x00;
        q[o++] = 0x00; // QNAME = 空
        q[o++] = 0x00; q[o++] = 0x01; q[o++] = 0x00; q[o++] = 0x01;
        CHECK("empty name rejected", dns_query_parse(q, o, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }
    // 15. question 段落越界（有 name 但缺 qtype/qclass）
    {
        unsigned char q[512]; size_t qlen = build_query("example.com", 1, q);
        CHECK("question overflow rejected", dns_query_parse(q, qlen - 4, name, sizeof(name), &qtype, &qclass, &supported, &qend) == 0);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
