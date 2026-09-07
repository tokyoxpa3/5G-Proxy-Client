#include "dns_synth.h"
#include "dns_query.h"
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
    char name[256];
    uint16_t qtype, qclass;
    int supported;
    size_t qend;
    if (!dns_query_parse(q, qlen, name, sizeof(name), &qtype, &qclass, &supported, &qend))
        return 0;
    if (!supported && !always_answer) return 0;

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
