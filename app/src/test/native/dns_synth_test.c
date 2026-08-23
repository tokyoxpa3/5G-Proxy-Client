// dns_synth_test.c — DNS 合成回覆 golden test
// 驗證：dns_build_reply_pure 的 r[] 建構（含 A/AAAA/HTTPS）與 fakedns fake IPv6 映射
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static inline uint32_t dt_htonl(uint32_t x){ return ((x>>24)&0xFF)|((x>>8)&0xFF00)|((x<<8)&0xFF0000)|((x<<24)&0xFF000000); }
#define htonl dt_htonl
#include "dns_synth.h"

static int g_fail=0;
#define CHECK(name,cond) do{if(cond)printf("PASS  %s\n",name); else{printf("FAIL  %s\n",name);g_fail=1;}}while(0)
static void hexdump(const unsigned char *b,size_t n){for(size_t i=0;i<n;i++)printf("%02x ",b[i]); printf("\n");}

// helper: build minimal DNS query for QNAME=example.com, QTYPE, QCLASS=1
static size_t build_query(const char *domain, uint16_t qtype, unsigned char *out){
    size_t o=0;
    out[o++]=0x12; out[o++]=0x34; // ID
    out[o++]=0x01; out[o++]=0x00; // RD=1
    out[o++]=0x00; out[o++]=0x01; // QDCOUNT 1
    out[o++]=0x00; out[o++]=0x00; // AN
    out[o++]=0x00; out[o++]=0x00; // NS
    out[o++]=0x00; out[o++]=0x00; // AR
    // QNAME
    const char *p=domain;
    while(*p){
        const char *dot=strchr(p,'.');
        size_t l= dot? (size_t)(dot-p): strlen(p);
        out[o++]=(unsigned char)l;
        memcpy(out+o,p,l); o+=l;
        if(!dot) break;
        p=dot+1;
    }
    out[o++]=0;
    out[o++]=(qtype>>8)&0xFF; out[o++]=qtype&0xFF;
    out[o++]=0x00; out[o++]=0x01;
    return o;
}

int main(void){
    // 1. fake IPv6 building golden: idx 0 => fd00::5e:1 => last bytes 00 01 + 5E at 13
    {
        unsigned char ip6[16];
        dns_build_fake_ip6(0, ip6);
        unsigned char exp[16]={0xFD,0,0,0,0,0,0,0,0,0,0,0,0,0x5E,0x00,0x01};
        CHECK("fake ip6 idx0", memcmp(ip6,exp,16)==0);
        dns_build_fake_ip6(511, ip6);
        unsigned char exp2[16]={0xFD,0,0,0,0,0,0,0,0,0,0,0,0,0x5E,0x02,0x00};
        CHECK("fake ip6 idx511", memcmp(ip6,exp2,16)==0);
    }
    // 2. A query golden: example.com -> fake 198.18.0.1 (C6120001)
    {
        unsigned char q[512]; size_t qlen=build_query("example.com",1,q);
        uint32_t fake=htonl(DNS_FAKE_IP_BASE+1); // 198.18.0.1
        unsigned char fake6[16]; dns_build_fake_ip6(0,fake6);
        unsigned char reply[512]; size_t rlen=0;
        int ok=dns_build_reply_pure(q,qlen,fake,fake6,0,reply,&rlen);
        // expected reply = id 12 34, flags 81 80, QD1 AN1, question + answer
        // answer: C00C 0001 0001 0000003C 0004 C6120001
        unsigned char exp[512];
        size_t eo=0;
        exp[eo++]=0x12; exp[eo++]=0x34;
        exp[eo++]=0x81; exp[eo++]=0x80; // QR=1 RD preserved, RA
        exp[eo++]=0x00; exp[eo++]=0x01;
        exp[eo++]=0x00; exp[eo++]=0x01; // ANCOUNT 1
        exp[eo++]=0x00; exp[eo++]=0x00;
        exp[eo++]=0x00; exp[eo++]=0x00;
        // question
        memcpy(exp+eo,q+12,qlen-12); eo+=qlen-12;
        // answer
        exp[eo++]=0xC0; exp[eo++]=0x0C;
        exp[eo++]=0x00; exp[eo++]=0x01;
        exp[eo++]=0x00; exp[eo++]=0x01;
        exp[eo++]=0x00; exp[eo++]=0x00; exp[eo++]=0x00; exp[eo++]=0x3C;
        exp[eo++]=0x00; exp[eo++]=0x04;
        exp[eo++]=0xC6; exp[eo++]=0x12; exp[eo++]=0x00; exp[eo++]=0x01;
        CHECK("dns A reply golden", ok==1 && rlen==eo && memcmp(reply,exp,eo)==0);
        if(!(ok==1 && rlen==eo && memcmp(reply,exp,eo)==0)){
            printf(" got rlen %zu exp %zu\n",rlen,eo);
            printf(" got "); hexdump(reply,rlen);
            printf(" exp "); hexdump(exp,eo);
        }
    }
    // 3. AAAA query golden
    {
        unsigned char q[512]; size_t qlen=build_query("example.com",28,q);
        uint32_t fake=htonl(DNS_FAKE_IP_BASE+1);
        unsigned char fake6[16]; dns_build_fake_ip6(0,fake6);
        unsigned char reply[512]; size_t rlen=0;
        int ok=dns_build_reply_pure(q,qlen,fake,fake6,0,reply,&rlen);
        unsigned char exp[512]; size_t eo=0;
        exp[eo++]=0x12; exp[eo++]=0x34;
        exp[eo++]=0x81; exp[eo++]=0x80;
        exp[eo++]=0x00; exp[eo++]=0x01;
        exp[eo++]=0x00; exp[eo++]=0x01;
        exp[eo++]=0x00; exp[eo++]=0x00;
        exp[eo++]=0x00; exp[eo++]=0x00;
        memcpy(exp+eo,q+12,qlen-12); eo+=qlen-12;
        exp[eo++]=0xC0; exp[eo++]=0x0C;
        exp[eo++]=0x00; exp[eo++]=0x1C;
        exp[eo++]=0x00; exp[eo++]=0x01;
        exp[eo++]=0x00; exp[eo++]=0x00; exp[eo++]=0x00; exp[eo++]=0x3C;
        exp[eo++]=0x00; exp[eo++]=0x10;
        memcpy(exp+eo,fake6,16); eo+=16;
        CHECK("dns AAAA reply golden", ok==1 && rlen==eo && memcmp(reply,exp,eo)==0);
        if(!(ok==1 && rlen==eo && memcmp(reply,exp,eo)==0)){
            printf(" got "); hexdump(reply,rlen);
            printf(" exp "); hexdump(exp,eo);
        }
    }
    // 4. HTTPS (65) query -> empty answer (NOERROR)
    {
        unsigned char q[512]; size_t qlen=build_query("example.com",65,q);
        uint32_t fake=htonl(DNS_FAKE_IP_BASE+1);
        unsigned char fake6[16]; dns_build_fake_ip6(0,fake6);
        unsigned char reply[512]; size_t rlen=0;
        int ok=dns_build_reply_pure(q,qlen,fake,fake6,0,reply,&rlen);
        // expect ANCOUNT 0, no answer, length = 12 + question
        size_t eo=12 + (qlen-12);
        CHECK("dns HTTPS empty answer", ok==1 && rlen==eo && reply[6]==0 && reply[7]==0);
    }
    // 5. always_answer=0 for unknown type (e.g., MX 15) -> should return 0 (放行)
    {
        unsigned char q[512]; size_t qlen=build_query("example.com",15,q);
        uint32_t fake=htonl(DNS_FAKE_IP_BASE+1);
        unsigned char fake6[16]; dns_build_fake_ip6(0,fake6);
        unsigned char reply[512]; size_t rlen=0;
        int ok=dns_build_reply_pure(q,qlen,fake,fake6,0,reply,&rlen);
        CHECK("dns unknown type not intercepted UDP", ok==0);
        int ok2=dns_build_reply_pure(q,qlen,fake,fake6,1,reply,&rlen);
        CHECK("dns unknown type always_answer TCP", ok2==1 && rlen==12+(qlen-12));
    }
    // 6. multiple labels: sub.example.com A
    {
        unsigned char q[512]; size_t qlen=build_query("sub.example.com",1,q);
        uint32_t fake=htonl(DNS_FAKE_IP_BASE+42);
        unsigned char fake6[16]; dns_build_fake_ip6(41,fake6);
        unsigned char reply[512]; size_t rlen=0;
        int ok=dns_build_reply_pure(q,qlen,fake,fake6,0,reply,&rlen);
        CHECK("dns sub domain A", ok==1 && rlen>0 && reply[6]==0 && reply[7]==1);
        // verify fake IP appears at end
        CHECK("dns sub domain fake ip", memcmp(reply+rlen-4,&fake,4)==0);
    }
    // 7. invalid: response already QR=1 -> 0
    {
        unsigned char q[512]; size_t qlen=build_query("example.com",1,q);
        q[2]|=0x80;
        uint32_t fake=htonl(DNS_FAKE_IP_BASE+1);
        unsigned char fake6[16]; dns_build_fake_ip6(0,fake6);
        unsigned char reply[512]; size_t rlen=0;
        int ok=dns_build_reply_pure(q,qlen,fake,fake6,0,reply,&rlen);
        CHECK("dns already response rejected", ok==0);
    }

    printf(g_fail?"\nRESULT: FAIL\n":"\nRESULT: PASS\n");
    return g_fail;
}
