#include "tcp_packet.h"
#include "checksum.h"
#include <string.h>
#ifndef htonl
static inline uint32_t tp_htonl(uint32_t x){ return ((x>>24)&0xFF)|((x>>8)&0xFF00)|((x<<8)&0xFF0000)|((x<<24)&0xFF000000); }
static inline uint16_t tp_htons(uint16_t x){ return (uint16_t)((x>>8)|(x<<8)); }
#define htonl tp_htonl
#define htons tp_htons
#define ntohl tp_htonl
#define ntohs tp_htons
#endif

#define TUN_MTU 4096

ssize_t tcp_build_segment(const unsigned char *saddr, const unsigned char *daddr, int family,
                          uint16_t sport_n, uint16_t dport_n,
                          uint32_t seq_host, uint32_t ack_host, uint8_t flags,
                          const unsigned char *payload, size_t plen,
                          uint16_t win,
                          unsigned char *out, size_t out_cap) {
    int is6 = (family == AF_INET6);
    size_t ip_hlen = is6 ? 40 : 20;
    if (ip_hlen + 20 + plen > out_cap) return -1;
    if (ip_hlen + 20 + plen > TUN_MTU) return -1;
    size_t total = ip_hlen + 20 + plen;
    if (is6) {
        out[0] = 0x60; out[1]=0;out[2]=0;out[3]=0;
        size_t pl = 20 + plen;
        out[4] = (pl>>8)&0xFF; out[5]=pl&0xFF;
        out[6]=6; out[7]=64;
        memcpy(out+8, saddr, 16);
        memcpy(out+24, daddr, 16);
    } else {
        out[0]=0x45; out[1]=0;
        out[2]=(total>>8)&0xFF; out[3]=total&0xFF;
        out[4]=0;out[5]=0;out[6]=0;out[7]=0;
        out[8]=64; out[9]=6;
        memcpy(out+12, saddr, 4);
        memcpy(out+16, daddr, 4);
        out[10]=0;out[11]=0;
        uint16_t csum = checksum16(out,20);
        out[10]=csum>>8; out[11]=csum&0xFF;
    }
    size_t u = ip_hlen;
    memcpy(out+u, &sport_n,2);
    memcpy(out+u+2,&dport_n,2);
    uint32_t seq_n=htonl(seq_host), ack_n=htonl(ack_host);
    memcpy(out+u+4,&seq_n,4);
    memcpy(out+u+8,&ack_n,4);
    out[u+12]=0x50;
    out[u+13]=flags;
    out[u+14]=win>>8; out[u+15]=win&0xFF;
    out[u+16]=0;out[u+17]=0;
    out[u+18]=0;out[u+19]=0;
    if (plen) memcpy(out+u+20,payload,plen);
    uint16_t tcsum = transport_checksum(family, saddr, daddr,6, out+u, 20+plen);
    out[u+16]=tcsum>>8; out[u+17]=tcsum&0xFF;
    return (ssize_t)total;
}

ssize_t tcp_build_synack(const unsigned char *src_ip, const unsigned char *dst_ip, int family,
                         uint16_t src_port_n, uint16_t dst_port_n,
                         uint32_t isn_host, uint32_t ack_host,
                         uint16_t win, uint16_t mss, uint8_t wscale,
                         unsigned char *out, size_t out_cap) {
    int is6 = (family == AF_INET6);
    size_t ip_hlen = is6 ? 40:20;
    size_t total = ip_hlen + 32;
    if (total > out_cap) return -1;
    if (is6) {
        out[0]=0x60;out[1]=0;out[2]=0;out[3]=0;
        out[4]=0;out[5]=32;out[6]=6;out[7]=64;
        memcpy(out+8, src_ip,16);
        memcpy(out+24,dst_ip,16);
    } else {
        out[0]=0x45;out[1]=0;
        out[2]=(total>>8)&0xFF;out[3]=total&0xFF;
        out[4]=0;out[5]=0;out[6]=0;out[7]=0;
        out[8]=64;out[9]=6;
        memcpy(out+12,src_ip,4);
        memcpy(out+16,dst_ip,4);
        out[10]=0;out[11]=0;
        uint16_t csum=checksum16(out,20);
        out[10]=csum>>8;out[11]=csum&0xFF;
    }
    size_t u=ip_hlen;
    memcpy(out+u,&src_port_n,2);
    memcpy(out+u+2,&dst_port_n,2);
    uint32_t isn_n=htonl(isn_host), ack_n=htonl(ack_host);
    memcpy(out+u+4,&isn_n,4);
    memcpy(out+u+8,&ack_n,4);
    out[u+12]=0x80;
    out[u+13]=0x12;
    // window: 呼叫端傳入（引擎 = TCP_APP_BUF_CAP >> 10）
    out[u+14]=(uint8_t)(win>>8); out[u+15]=(uint8_t)(win&0xFF);
    out[u+16]=0;out[u+17]=0;
    out[u+18]=0;out[u+19]=0;
    out[u+20]=0x02;out[u+21]=0x04;
    uint16_t mss_n=htons(mss);
    memcpy(out+u+22,&mss_n,2);
    out[u+24]=0x01;out[u+25]=0x01;
    out[u+26]=0x03;out[u+27]=0x03;out[u+28]=wscale;
    out[u+29]=0;out[u+30]=0;out[u+31]=0;
    uint16_t tcsum=transport_checksum(family, src_ip,dst_ip,6,out+u,32);
    out[u+16]=tcsum>>8;out[u+17]=tcsum&0xFF;
    return (ssize_t)total;
}

ssize_t udp_build_packet(const unsigned char *src_ip, const unsigned char *dst_ip, int family,
                         uint16_t src_port_n, uint16_t dst_port_n,
                         const unsigned char *payload, size_t plen,
                         unsigned char *out, size_t out_cap) {
    int is6 = (family==AF_INET6);
    size_t ip_hlen=is6?40:20;
    if (plen > TUN_MTU - ip_hlen -8) return -1;
    size_t total=ip_hlen+8+plen;
    if (total>out_cap) return -1;
    if (is6) {
        out[0]=0x60;out[1]=0;out[2]=0;out[3]=0;
        out[4]=(8+plen)>>8;out[5]=(8+plen)&0xFF;
        out[6]=17;out[7]=64;
        memcpy(out+8,src_ip,16);
        memcpy(out+24,dst_ip,16);
    } else {
        out[0]=0x45;out[1]=0;
        out[2]=(total>>8)&0xFF;out[3]=total&0xFF;
        out[4]=0;out[5]=0;out[6]=0;out[7]=0;
        out[8]=64;out[9]=17;
        memcpy(out+12,src_ip,4);
        memcpy(out+16,dst_ip,4);
        out[10]=0;out[11]=0;
        uint16_t csum=checksum16(out,20);
        out[10]=csum>>8;out[11]=csum&0xFF;
    }
    size_t u=ip_hlen;
    memcpy(out+u,&src_port_n,2);
    memcpy(out+u+2,&dst_port_n,2);
    uint16_t ulen=8+plen;
    out[u+4]=ulen>>8;out[u+5]=ulen&0xFF;
    out[u+6]=0;out[u+7]=0;
    if (plen) memcpy(out+u+8,payload,plen);
    uint16_t ucsum = (family==AF_INET6)? tcpudp_checksum6(src_ip,dst_ip,17,out+u,8+plen) : tcpudp_checksum4(src_ip,dst_ip,17,out+u,8+plen);
    out[u+6]=ucsum>>8; out[u+7]=ucsum&0xFF;
    return (ssize_t)total;
}

int tcp_seq_gt(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

uint16_t tcp_win_field_pure(size_t occ, size_t cap) {
    size_t free = (occ >= cap) ? 0 : (cap - occ);
    uint16_t w = (uint16_t)(free >> 10);
    return (w > 0) ? w : 1;
}

uint8_t tcp_parse_window_scale(const unsigned char *opts, size_t optlen) {
    uint8_t ws = 0;
    size_t o = 0;
    while (o + 2 <= optlen) {
        uint8_t k = opts[o];
        if (k == 0) break;                              // EOL
        if (k == 1) { o += 1; continue; }               // NOP
        if (k == 3 && o + 3 <= optlen) ws = opts[o + 2];  // Window Scale
        // RFC 793：非 EOL/NOP 的選項長度須 >= 2；畸形長度（0/1）直接終止，
        // 否則 o 不前進會在惡意 SYN 上無限迴圈（引擎執行緒 DoS）。
        uint8_t alen = opts[o + 1];
        if (alen < 2) break;
        o += alen;
    }
    return ws;
}
