// ip_hash_test.c — 位址 FNV-1a 32-bit 會話鍵雜湊 golden test
// 驗證 ip_hash32：v4/v6 位址的位元精確雜湊、family 區分、全零位址。
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ip_hash.h"

static int g_fail = 0;
#define CHECK(name, cond) do { if (cond) printf("PASS  %s\n", name); else { printf("FAIL  %s\n", name); g_fail = 1; } } while (0)

// 以 4 個位元組建立 v4 位址（其餘 ip[] 填 0）
static ip_addr_t mk4(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
    ip_addr_t r;
    memset(&r, 0, sizeof r);
    r.family = AF_INET;
    r.ip[0] = a; r.ip[1] = b; r.ip[2] = c; r.ip[3] = d;
    return r;
}

int main(void) {
    // 1. v4 位址 golden（Python 獨立 FNV-1a 實作預先算出的期望值）
    {
        ip_addr_t a = mk4(1, 2, 3, 4);
        CHECK("ipv4 1.2.3.4 golden", ip_hash32(&a) == 0xE626EFEFu);
    }
    {
        ip_addr_t a = mk4(10, 0, 0, 1);
        CHECK("ipv4 10.0.0.1 golden", ip_hash32(&a) == 0x3DE7926Eu);
    }
    {
        ip_addr_t a = mk4(0, 0, 0, 0);
        CHECK("ipv4 0.0.0.0 golden", ip_hash32(&a) == 0x69691907u);
    }

    // 2. v6 位址 golden（2001:db8::1 與 ::1）
    {
        ip_addr_t a;
        memset(&a, 0, sizeof a);
        a.family = AF_INET6;
        unsigned char raw[16] = {0x20,0x01,0x0d,0xb8, 0,0,0,0,0,0,0,0,0,0,0,0x01};
        memcpy(a.ip, raw, 16);
        CHECK("ipv6 2001:db8::1 golden", ip_hash32(&a) == 0x6E5B04FEu);
    }
    {
        ip_addr_t a;
        memset(&a, 0, sizeof a);
        a.family = AF_INET6;
        unsigned char raw[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
        memcpy(a.ip, raw, 16);
        CHECK("ipv6 ::1 golden", ip_hash32(&a) == 0x68691778u);
    }

    // 3. 相同位址位元組 + 不同 family → 雜湊必須不同（family 影響 bucket 分配）
    {
        ip_addr_t v4 = mk4(1, 2, 3, 4);       // family=2
        ip_addr_t v6;
        memset(&v6, 0, sizeof v6);
        v6.family = AF_INET6;                 // family=10
        memcpy(v6.ip, v4.ip, 16);             // 相同 16 位元組
        CHECK("family 區分", ip_hash32(&v4) != ip_hash32(&v6));
    }

    // 4. 決定性：同一位址重複雜湊一致
    {
        ip_addr_t a = mk4(192, 168, 1, 1);
        CHECK("deterministic", ip_hash32(&a) == ip_hash32(&a));
    }

    // 5. ip_hash_bucket：golden（(ip_hash32 ^ port) % 256，獨立 Python 算得）
    {
        ip_addr_t a = mk4(1, 2, 3, 4);
        CHECK("bucket v4 p0",   ip_hash_bucket(&a, 0, 256) == 239);
        CHECK("bucket v4 p443", ip_hash_bucket(&a, 443, 256) == 84);
        CHECK("bucket v4 p12345", ip_hash_bucket(&a, 12345, 256) == 214);
    }
    {
        ip_addr_t a;
        memset(&a, 0, sizeof a);
        a.family = AF_INET6;
        unsigned char raw[16] = {0x20,0x01,0x0d,0xb8, 0,0,0,0,0,0,0,0,0,0,0,0x01};
        memcpy(a.ip, raw, 16);
        CHECK("bucket v6 p0", ip_hash_bucket(&a, 0, 256) == 254);
        CHECK("bucket v6 p53", ip_hash_bucket(&a, 53, 256) == 203);
    }

    // 6. ip_hash_bucket 差分：隨機對照舊公式 (ip_hash32 ^ port) % nbuckets
    {
        int ok = 1;
        uint32_t xs = 0x9E3779B9u;
        for (int i = 0; i < 200000 && ok; i++) {
            xs = xs * 1664525u + 1013904223u;
            ip_addr_t a;
            memset(&a, 0, sizeof a);
            a.family = (xs & 1) ? AF_INET6 : AF_INET;
            for (int j = 0; j < 16; j++) a.ip[j] = (unsigned char)(xs >> (j & 3));
            uint16_t port = (uint16_t)(xs >> 16);
            uint32_t nb = 1u + (xs % 512);   // 避免 nb==0 除零
            uint32_t expect = (ip_hash32(&a) ^ (uint32_t)port) % nb;
            if (ip_hash_bucket(&a, port, nb) != expect) { ok = 0; break; }
        }
        CHECK("bucket 隨機對照舊公式 200k", ok);
    }

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
