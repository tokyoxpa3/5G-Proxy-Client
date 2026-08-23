#include "dns_synth.h"
#include <string.h>
// portable htonl without arpa/winsock (avoid AF mismatch on Windows)
#ifndef htonl
static inline uint32_t dns_htonl(uint32_t x){ return ((x>>24)&0xFF)|((x>>8)&0xFF00)|((x<<8)&0xFF0000)|((x<<24)&0xFF000000); }
#define htonl dns_htonl
#endif

void dns_build_fake_ip6(int idx, unsigned char out[16]) {
    memset(out, 0, 16);
    out[0] = 0xFD;
    out[13] = 0x5E;
    out[14] = (unsigned char)(((idx + 1) >> 8) & 0xFF);
    out[15] = (unsigned char)((idx + 1) & 0xFF);
}

int dns_build_reply_pure(const unsigned char *q, size_t qlen,
                         uint32_t fake_ip_n, const unsigned char fake_ip6[16],
                         int always_answer,
                         unsigned char *reply, size_t *rlen) {
    if (qlen < 17) return 0;
    uint16_t flags = (uint16_t)((q[2] << 8) | q[3]);
    if (flags & 0x8000) return 0;
    if ((flags & 0x7800) != 0) return 0;
    if (((q[4] << 8) | q[5]) != 1) return 0;
    size_t off = 12;
    char name[256];
    size_t nlen = 0;
    for (;;) {
        if (off >= qlen) return 0;
        uint8_t l = q[off];
        if (l == 0) { off++; break; }
        if ((l & 0xC0) == 0xC0) return 0;
        if (l > 63 || off + 1 + l > qlen) return 0;
        if (nlen) {
            if (nlen + 1 >= sizeof(name)) return 0;
            name[nlen++] = '.';
        }
        for (int i = 0; i < l; i++) {
            char c = (char)q[off + 1 + i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
            if (nlen + 1 >= sizeof(name)) return 0;
            name[nlen++] = c;
        }
        off += 1u + l;
    }
    if (nlen == 0 || nlen > 253) return 0;
    if (off + 4 > qlen) return 0;
    uint16_t qtype = (uint16_t)((q[off] << 8) | q[off + 1]);
    uint16_t qclass = (uint16_t)((q[off + 2] << 8) | q[off + 3]);
    if (qclass != 1) return 0;
    int supported = (qtype == 1 || qtype == 28 || qtype == 65);
    if (!supported && !always_answer) return 0;
    name[nlen] = '\0';
    size_t qend = off + 4;

    // 若是 A/AAAA，需要 fake
    if ((qtype == 1 || qtype == 28) && fake_ip_n == 0) return 0;

    unsigned char r[512];
    size_t rl = 0;
    memcpy(r, q, 12);
    r[2] = (unsigned char)(0x80 | (q[2] & 0x01));
    r[3] = 0x80;
    r[6] = 0; r[7] = 0;
    r[8] = 0; r[9] = 0;
    r[10] = 0; r[11] = 0;
    rl = 12;
    memcpy(r + rl, q + 12, qend - 12);
    rl += qend - 12;
    if (qtype == 1) {
        r[6] = 0; r[7] = 1;
        r[rl++] = 0xC0; r[rl++] = 0x0C;
        r[rl++] = 0; r[rl++] = 1;
        r[rl++] = 0; r[rl++] = 1;
        uint32_t ttl = htonl(DNS_FAKE_TTL_SEC);
        memcpy(r + rl, &ttl, 4); rl += 4;
        r[rl++] = 0; r[rl++] = 4;
        memcpy(r + rl, &fake_ip_n, 4); rl += 4;
    } else if (qtype == 28) {
        r[6] = 0; r[7] = 1;
        r[rl++] = 0xC0; r[rl++] = 0x0C;
        r[rl++] = 0; r[rl++] = 28;
        r[rl++] = 0; r[rl++] = 1;
        uint32_t ttl = htonl(DNS_FAKE_TTL_SEC);
        memcpy(r + rl, &ttl, 4); rl += 4;
        r[rl++] = 0; r[rl++] = 16;
        if (!fake_ip6) return 0;
        memcpy(r + rl, fake_ip6, 16); rl += 16;
    }
    memcpy(reply, r, rl);
    *rlen = rl;
    return 1;
}

int dns_build_reply_for_test(const unsigned char *q, size_t qlen,
                             uint32_t fake_ip_n, const unsigned char fake_ip6[16],
                             int always_answer,
                             unsigned char *reply, size_t *rlen) {
    return dns_build_reply_pure(q, qlen, fake_ip_n, fake_ip6, always_answer, reply, rlen);
}
