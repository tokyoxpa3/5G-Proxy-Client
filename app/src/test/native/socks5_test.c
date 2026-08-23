// socks5_test.c — SOCKS5 編碼 golden test（host gcc 可編譯）
// 驗證：SOCKS5 請求編碼、UDP datagram frame 串流
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static inline uint16_t st_htons(uint16_t x){ return (uint16_t)((x>>8)|(x<<8)); }
#define htons st_htons
#define ntohs st_htons
#include "socks5_codec.h"

static int g_fail=0;
#define CHECK(name,cond) do{if(cond)printf("PASS  %s\n",name); else{printf("FAIL  %s\n",name);g_fail=1;}}while(0)
static void hexdump(const unsigned char *b,size_t n){for(size_t i=0;i<n;i++)printf("%02x%s",b[i],(i+1)%16==0?"\n":" "); if(n%16)printf("\n");}
static int eq(const unsigned char *a,const unsigned char *b,size_t n){return memcmp(a,b,n)==0;}

int main(void){
    // 1. hello no-auth
    {
        unsigned char out[8];
        int n=socks5_build_hello(NULL,NULL,out,sizeof out);
        unsigned char exp[]={0x05,0x01,0x00};
        CHECK("hello no-auth", n==3 && eq(out,exp,3));
    }
    // 2. hello auth
    {
        unsigned char out[8];
        int n=socks5_build_hello("u","p",out,sizeof out);
        unsigned char exp[]={0x05,0x01,0x02};
        CHECK("hello auth", n==3 && eq(out,exp,3));
    }
    // 3. auth encoding rfc1929
    {
        unsigned char out[64];
        int n=socks5_build_auth("ab","12",out,sizeof out);
        unsigned char exp[]={0x01,0x02,'a','b',0x02,'1','2'};
        CHECK("auth encoding", n==7 && eq(out,exp,7));
    }
    // 4. CONNECT IPv4 golden
    {
        unsigned char ip[4]={1,2,3,4};
        uint16_t port=htons(80);
        unsigned char out[64];
        int n=socks5_build_connect_request(ip,AF_INET,port,NULL,out,sizeof out);
        unsigned char exp[]={0x05,0x01,0x00,0x01,1,2,3,4,0x00,0x50};
        printf("  connect v4 bytes: "); hexdump(out,n);
        CHECK("connect ipv4 golden", n==10 && eq(out,exp,10));
    }
    // 5. CONNECT IPv6 golden 2001:db8::1:80
    {
        unsigned char ip6[16]={0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        uint16_t port=htons(443);
        unsigned char out[64];
        int n=socks5_build_connect_request(ip6,AF_INET6,port,NULL,out,sizeof out);
        unsigned char exp[22]={0x05,0x01,0x00,0x04,0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1,0x01,0xbb};
        // 01 bb = 443
        CHECK("connect ipv6 golden", n==22 && eq(out,exp,22));
    }
    // 6. CONNECT domain (fakedns) golden: example.com:80 -> ATYP 0x03
    {
        uint16_t port=htons(80);
        unsigned char out[64];
        int n=socks5_build_connect_request(NULL,AF_INET,port,"example.com",out,sizeof out);
        unsigned char exp[]={0x05,0x01,0x00,0x03,0x0b,'e','x','a','m','p','l','e','.','c','o','m',0x00,0x50};
        // 0x0b = 11 len
        CHECK("connect domain golden", n==18 && eq(out,exp,18));
        if(n!=18){printf(" got %d exp 18\n",n); hexdump(out,n);}
    }
    // 7. UDP datagram IPv4 + payload "hi"
    {
        unsigned char ip[4]={8,8,8,8};
        uint16_t port=htons(53);
        unsigned char payload[]={'h','i'};
        unsigned char out[64];
        int n=socks5_build_udp_datagram(ip,AF_INET,port,NULL,payload,sizeof payload,out,sizeof out);
        unsigned char exp[]={0x00,0x00,0x00,0x01,8,8,8,8,0x00,0x35,'h','i'};
        CHECK("udp datagram ipv4", n==12 && eq(out,exp,12));
    }
    // 8. UDP datagram domain + frame length prefix (UDP-in-TCP)
    {
        uint16_t port=htons(53);
        unsigned char payload[]={0x01,0x02};
        unsigned char out[64];
        int n=socks5_build_udp_frame(NULL,AF_INET,port,"example.com",payload,sizeof payload,out,sizeof out);
        // frame = 2byte len + datagram
        // datagram = 00 00 00 03 0b 'example.com' 00 35 01 02
        // datagram len = 3+1+1+11+2+2=20 => prefix 00 14
        unsigned char exp[]={0x00,0x14,0x00,0x00,0x00,0x03,0x0b,'e','x','a','m','p','l','e','.','c','o','m',0x00,0x35,0x01,0x02};
        CHECK("udp frame domain prefix", n==22 && eq(out,exp,22));
        if(n!=22){printf(" got %d\n",n); hexdump(out,n); printf("exp "); hexdump(exp,sizeof exp);}
    }
    // 9. UDP datagram IPv6
    {
        unsigned char ip6[16]={0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        uint16_t port=htons(1234);
        unsigned char out[64];
        int n=socks5_build_udp_datagram(ip6,AF_INET6,port,NULL,NULL,0,out,sizeof out);
        unsigned char exp[22]={0x00,0x00,0x00,0x04,0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1,0x04,0xd2};
        CHECK("udp datagram ipv6", n==22 && eq(out,exp,22));
    }
    // 10. parse round-trip
    {
        unsigned char ip[4]={1,2,3,4};
        uint16_t port=htons(80);
        unsigned char dg[64];
        int n=socks5_build_udp_datagram(ip,AF_INET,port,NULL,(unsigned char*)"hello",5,dg,sizeof dg);
        unsigned char rip[16]; int fam; uint16_t rport; const unsigned char *pl; size_t pln;
        int rc=socks5_parse_udp_datagram(dg,n,rip,&fam,&rport,NULL,0,&pl,&pln);
        CHECK("parse ipv4 roundtrip", rc==0 && fam==AF_INET && memcmp(rip,ip,4)==0 && rport==port && pln==5 && memcmp(pl,"hello",5)==0);
    }
    // 11. parse domain
    {
        unsigned char dg[64];
        uint16_t port=htons(53);
        int n=socks5_build_udp_datagram(NULL,AF_INET,port,"example.com",(unsigned char*)"x",1,dg,sizeof dg);
        char dom[64]; const unsigned char *pl; size_t pln;
        int rc=socks5_parse_udp_datagram(dg,n,NULL,NULL,NULL,dom,sizeof dom,&pl,&pln);
        CHECK("parse domain", rc==0 && strcmp(dom,"example.com")==0 && pln==1 && pl[0]=='x');
    }

    printf(g_fail?"\nRESULT: FAIL\n":"\nRESULT: PASS\n");
    return g_fail;
}
