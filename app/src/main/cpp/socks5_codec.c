#include "socks5_codec.h"
#include <string.h>

int socks5_build_udp_datagram(const unsigned char *dst_ip, int family,
                              uint16_t dst_port_n,
                              const char *domain,
                              const unsigned char *payload, size_t plen,
                              unsigned char *out, size_t out_cap) {
    size_t off = 0;
    if (out_cap < 4) return -1;
    out[0] = 0; out[1] = 0; out[2] = 0; // RSV + FRAG
    off = 3;
    if (domain && domain[0]) {
        size_t dl = strlen(domain);
        if (dl > 255) return -1;
        if (off + 1 + 1 + dl + 2 + plen > out_cap) return -1;
        out[off++] = 0x03;
        out[off++] = (unsigned char)dl;
        memcpy(out + off, domain, dl);
        off += dl;
        memcpy(out + off, &dst_port_n, 2);
        off += 2;
    } else if (family == AF_INET6) {
        if (off + 1 + 16 + 2 + plen > out_cap) return -1;
        out[off++] = 0x04;
        memcpy(out + off, dst_ip, 16);
        off += 16;
        memcpy(out + off, &dst_port_n, 2);
        off += 2;
    } else {
        if (off + 1 + 4 + 2 + plen > out_cap) return -1;
        out[off++] = 0x01;
        if (dst_ip) memcpy(out + off, dst_ip, 4);
        else memset(out + off, 0, 4);
        off += 4;
        memcpy(out + off, &dst_port_n, 2);
        off += 2;
    }
    if (plen) {
        if (off + plen > out_cap) return -1;
        memcpy(out + off, payload, plen);
        off += plen;
    }
    return (int)off;
}

int socks5_build_udp_frame(const unsigned char *dst_ip, int family,
                           uint16_t dst_port_n,
                           const char *domain,
                           const unsigned char *payload, size_t plen,
                           unsigned char *out, size_t out_cap) {
    if (out_cap < 2) return -1;
    int dlen = socks5_build_udp_datagram(dst_ip, family, dst_port_n, domain, payload, plen, out + 2, out_cap - 2);
    if (dlen < 0) return -1;
    out[0] = (unsigned char)(dlen >> 8);
    out[1] = (unsigned char)(dlen & 0xFF);
    return dlen + 2;
}

int socks5_build_connect_request(const unsigned char *dst_ip, int family,
                                 uint16_t dst_port_n,
                                 const char *domain,
                                 unsigned char *out, size_t out_cap) {
    if (out_cap < 3) return -1;
    out[0] = 0x05; out[1] = 0x01; out[2] = 0x00;
    size_t off = 3;
    if (domain && domain[0]) {
        size_t dl = strlen(domain);
        if (dl > 255) return -1;
        if (off + 1 + 1 + dl + 2 > out_cap) return -1;
        out[off++] = 0x03;
        out[off++] = (unsigned char)dl;
        memcpy(out + off, domain, dl);
        off += dl;
        memcpy(out + off, &dst_port_n, 2);
        off += 2;
    } else if (family == AF_INET6) {
        if (off + 1 + 16 + 2 > out_cap) return -1;
        out[off++] = 0x04;
        memcpy(out + off, dst_ip, 16);
        off += 16;
        memcpy(out + off, &dst_port_n, 2);
        off += 2;
    } else {
        if (off + 1 + 4 + 2 > out_cap) return -1;
        out[off++] = 0x01;
        if (dst_ip) memcpy(out + off, dst_ip, 4);
        else memset(out + off, 0, 4);
        off += 4;
        memcpy(out + off, &dst_port_n, 2);
        off += 2;
    }
    return (int)off;
}

int socks5_build_hello(const char *user, const char *pass, unsigned char *out, size_t cap) {
    int auth = (user && user[0]) || (pass && pass[0]);
    if (cap < 3) return -1;
    out[0] = 0x05; out[1] = 0x01; out[2] = auth ? 0x02 : 0x00;
    return 3;
}

int socks5_build_auth(const char *user, const char *pass, unsigned char *out, size_t cap) {
    size_t ul = user ? strlen(user) : 0;
    size_t pl = pass ? strlen(pass) : 0;
    if (ul > 255 || pl > 255) return -1;
    if (3 + ul + pl > cap) return -1;
    out[0] = 0x01; out[1] = (unsigned char)ul;
    if (ul) memcpy(out + 2, user, ul);
    out[2 + ul] = (unsigned char)pl;
    if (pl) memcpy(out + 3 + ul, pass, pl);
    return (int)(3 + ul + pl);
}

int socks5_parse_udp_datagram(const unsigned char *dg, size_t dlen,
                              unsigned char *src_ip_out, int *family_out,
                              uint16_t *src_port_n,
                              char *domain_out, size_t domain_cap,
                              const unsigned char **payload_out, size_t *payload_len_out) {
    if (dlen < 4) return -1;
    int atyp = dg[3];
    size_t off = 0;
    if (atyp == 0x01) {
        if (dlen < 10) return -1;
        if (family_out) *family_out = AF_INET;
        if (src_ip_out) memcpy(src_ip_out, dg + 4, 4);
        if (src_port_n) memcpy(src_port_n, dg + 8, 2);
        off = 10;
    } else if (atyp == 0x04) {
        if (dlen < 22) return -1;
        if (family_out) *family_out = AF_INET6;
        if (src_ip_out) memcpy(src_ip_out, dg + 4, 16);
        if (src_port_n) memcpy(src_port_n, dg + 20, 2);
        off = 22;
    } else if (atyp == 0x03) {
        if (dlen < 7) return -1;
        uint8_t dl = dg[4];
        if (dlen < (size_t)7 + dl) return -1;
        if (domain_out && domain_cap > 0) {
            size_t n = dl < domain_cap - 1 ? dl : domain_cap - 1;
            memcpy(domain_out, dg + 5, n);
            domain_out[n] = '\0';
        }
        if (family_out) *family_out = -1; // domain
        if (src_port_n) memcpy(src_port_n, dg + 5 + dl, 2);
        off = 7 + dl;
        if (src_ip_out) memset(src_ip_out, 0, 16);
    } else return -1;
    if (payload_out) *payload_out = dg + off;
    if (payload_len_out) *payload_len_out = dlen - off;
    return 0;
}
