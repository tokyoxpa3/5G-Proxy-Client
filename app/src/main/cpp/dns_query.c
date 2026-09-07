#include "dns_query.h"

int dns_query_parse(const unsigned char *q, size_t qlen,
                    char *name_out, size_t name_cap,
                    uint16_t *qtype_out, uint16_t *qclass_out,
                    int *supported_out, size_t *qend_out) {
    if (qlen < 17) return 0;
    uint16_t flags = (uint16_t)((q[2] << 8) | q[3]);
    if (flags & 0x8000) return 0;                 // 不是查詢（QR=1）
    if ((flags & 0x7800) != 0) return 0;          // 僅支援 QUERY (opcode=0)
    if (((q[4] << 8) | q[5]) != 1) return 0;      // 僅單一 question

    size_t off = 12;
    size_t nlen = 0;
    for (;;) {
        if (off >= qlen) return 0;
        uint8_t l = q[off];
        if (l == 0) { off++; break; }
        if ((l & 0xC0) == 0xC0) return 0;         // 壓縮指標不處理
        if (l > 63 || off + 1 + l > qlen) return 0;
        if (nlen) {
            if (nlen + 1 >= name_cap) return 0;
            name_out[nlen++] = '.';
        }
        for (int i = 0; i < l; i++) {
            char c = (char)q[off + 1 + i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
            if (nlen + 1 >= name_cap) return 0;
            name_out[nlen++] = c;
        }
        off += 1u + l;
    }
    if (nlen == 0 || nlen > 253) return 0;
    if (off + 4 > qlen) return 0;
    uint16_t qtype = (uint16_t)((q[off] << 8) | q[off + 1]);
    uint16_t qclass = (uint16_t)((q[off + 2] << 8) | q[off + 3]);
    if (qclass != 1) return 0;                    // 僅 IN
    name_out[nlen] = '\0';
    if (qtype_out) *qtype_out = qtype;
    if (qclass_out) *qclass_out = qclass;
    if (supported_out) *supported_out = (qtype == 1 || qtype == 28 || qtype == 65);
    if (qend_out) *qend_out = off + 4;
    return 1;
}
