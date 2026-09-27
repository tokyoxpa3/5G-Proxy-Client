// tun_engine_test.c — 主機端對端整合測試：連結真正的 tun_socks.c 引擎，
// 以假 SOCKS5 伺服器與 socketpair(SOCK_DGRAM) 當 TUN fd 驅動，驗證端到端行為。
//
// 這是測試金字塔最薄的一環：既有單元測試與 fuzz 只測抽離的純邏輯，
// 未跑過真正的 epoll 事件迴圈、TUN 讀寫、handshake 執行緒與 SOCKS5 狀態機。
// 僅測試用，需 host_jni_bridge.c 提供主機版 request_java_socket / notify_*。
//
// 覆蓋情境（每個情境獨立起一個引擎實例，假伺服器以全域旗標切換行為）：
//   1. 預設引擎：ICMP echo、TCP CONNECT echo、UDP relay echo、IPv4 分片重組、
//      TCP FIN 半關閉傳播、軟重連
//   2. RFC 1929 認證成功 → TCP echo 正常
//   3. RFC 1929 認證被拒 → RST + SE_EVENT_AUTH_FAIL
//   4. UDP-in-TCP（自訂指令 0x04）frame relay echo
//   5. UDP-in-TCP 伺服器不支援 → 退回標準 UDP ASSOCIATE(0x03) relay echo

#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "checksum.h"
#include "ip_parse.h"
#include "tcp_packet.h"
#include "jni_bridge.h"

// ---- 引擎公開介面（定義於 tun_socks.c，此處自行 extern，與 jni_bridge.c 一致） ----
extern int tun_socks_start(int tun_fd, const char *host, int port,
                           const char *user, const char *pass,
                           int udp_in_tcp, int remote_dns, const char *dns_passthrough);
extern void tun_socks_stop(void);
extern int tun_socks_is_running(void);
extern void tun_socks_reconnect(const char *new_host);
extern void tun_socks_get_stats(unsigned long long *to_server, unsigned long long *from_server,
                                int *tcp_sessions, int *udp_sessions);

// ---- host_jni_bridge.c 提供的測試斷言資料 ----
extern atomic_int g_host_last_server_event;
extern atomic_int g_host_engine_stopped;
extern int g_bridge_verbose;

static int g_fail = 0;
#define CHECK(name, cond) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); g_fail = 1; } \
} while (0)

// ================= 假 SOCKS5 伺服器 =================
// 每個情境在啟動引擎前設定全域旗標（引擎啟動/停止會重開所有連線，故無競態）：
//   g_fake_require_auth    1 = greeting 選 0x02、要求 RFC 1929 認證
//   g_fake_reject_auth     1 = 認證一律回 0x01 0x01（拒絶），測 AUTH_FAIL 路徑
//   g_fake_reject_udp_tcp  1 = cmd 0x04 回 REP=0x07，觸發引擎退回標準 UDP-in-UDP
// CONNECT(0x01) echo、UDP ASSOCIATE(0x03) relay echo、UDP-in-TCP(0x04) frame echo。
// 記錄最近一次 ATYP=0x03 的網域到 g_fake_last_domain（Remote DNS 驗證用）。

static int g_udp_relay_fd = -1;
static uint16_t g_udp_relay_port = 0;

static int g_fake_require_auth = 0;
static int g_fake_reject_auth = 0;
static int g_fake_reject_udp_tcp = 0;
static char g_fake_last_domain[256];
static volatile int g_fake_saw_domain = 0;

// 情境 7（上傳回壓）用：
//   g_fake_discard_upload 1 = CONNECT 後丟棄上傳（不回送），並把 SO_RCVBUF 縮小，
//                             讓引擎的 srv 送緩衝很快滿 → app_buf 才會真的被填滿
//   g_fake_stall_read_ms  >0 = CONNECT 回覆成功後先暫停讀取 N ms（逼出零視窗）
static int g_fake_discard_upload = 0;
static int g_fake_stall_read_ms = 0;
static atomic_ullong g_fake_upload_bytes;   // 丟棄模式下實際收到的位元組數
static atomic_int g_fake_upload_bad;        // 收到非預期內容的次數
static atomic_int g_fake_upload_exit_n;     // 讀取迴圈結束時的 recv 回傳值
static atomic_int g_fake_upload_exit_errno; // 讀取迴圈結束時的 errno

static int recv_exact(int fd, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, (char *)buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, (const char *)buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void *fake_client(void *arg) {
    int fd = (int)(intptr_t)arg;
    unsigned char buf[512];

    // 1. greeting
    if (recv_exact(fd, buf, 2) < 0) goto done;
    unsigned char nmethods = buf[1];
    if (recv_exact(fd, buf, nmethods) < 0) goto done;
    if (g_fake_require_auth) {
        unsigned char rep[2] = {0x05, 0x02};   // 要求 RFC 1929 認證
        send_all(fd, rep, 2);
        // RFC 1929：ver(1) ulen(1) user(ulen) plen(1) pass(plen)
        if (recv_exact(fd, buf, 2) < 0) goto done;
        unsigned char ulen = buf[1];
        if (recv_exact(fd, buf, ulen) < 0) goto done;
        if (recv_exact(fd, buf, 1) < 0) goto done;
        unsigned char plen = buf[0];
        if (recv_exact(fd, buf, plen) < 0) goto done;
        unsigned char aok[2] = {0x01, g_fake_reject_auth ? 0x01 : 0x00};
        send_all(fd, aok, 2);
        if (g_fake_reject_auth) goto done;   // 拒絶後引擎會 RST 並關閉
    } else {
        unsigned char rep[2] = {0x05, 0x00};   // no-auth
        send_all(fd, rep, 2);
    }

    // 2. 一條連線可接續多個 request（UDP-in-TCP 退回時引擎在同連線再送 0x03）
    for (;;) {
        if (recv_exact(fd, buf, 4) < 0) goto done;
        unsigned char cmd = buf[1];
        unsigned char atyp = buf[3];

        if (atyp == 0x01) {
            if (recv_exact(fd, buf, 6) < 0) goto done;   // 4-byte IP + 2-byte port
        } else if (atyp == 0x04) {
            if (recv_exact(fd, buf, 18) < 0) goto done;  // 16-byte IP + 2-byte port
        } else if (atyp == 0x03) {
            if (recv_exact(fd, buf, 1) < 0) goto done;
            unsigned char dl = buf[0];   // uint8_t，最大 255 < sizeof(256)，寫入必定安全
            if (recv_exact(fd, buf, dl) < 0) goto done;
            memcpy(g_fake_last_domain, buf, dl);
            g_fake_last_domain[dl] = '\0';
            g_fake_saw_domain = 1;
            if (recv_exact(fd, buf, 2) < 0) goto done;   // port
        } else {
            goto done;
        }

        if (cmd == 0x01) {
            // CONNECT: reply success, BND 0.0.0.0:0，然後 echo 回送
            unsigned char ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            send_all(fd, ok, 10);
            if (g_fake_stall_read_ms > 0) {
                // 先不讀：逼引擎把 app_buf（4 MiB）填滿並通告零視窗。
                // 不可順手縮小 SO_RCVBUF —— 那會觸發 silly-window 症候群，
                // 把恢復後的排空速率壓到 ~85 KB/s，測試永遠等不到完成。
                usleep((useconds_t)g_fake_stall_read_ms * 1000);
            }
            for (;;) {
                ssize_t n = recv(fd, buf, sizeof buf, 0);
                if (n <= 0) {
                    if (g_fake_discard_upload) {
                        atomic_store(&g_fake_upload_exit_n, (int)n);
                        atomic_store(&g_fake_upload_exit_errno, errno);
                    }
                    break;
                }
                if (g_fake_discard_upload) {
                    for (ssize_t i = 0; i < n; i++) {
                        if (buf[i] != 0xA5) atomic_fetch_add(&g_fake_upload_bad, 1);
                    }
                    atomic_fetch_add(&g_fake_upload_bytes, (unsigned long long)n);
                } else {
                    send_all(fd, buf, (size_t)n);
                }
            }
            goto done;
        } else if (cmd == 0x03) {
            // UDP ASSOCIATE: reply relay addr 127.0.0.1:g_udp_relay_port
            unsigned char ok[10] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1,
                                    (unsigned char)(g_udp_relay_port >> 8),
                                    (unsigned char)(g_udp_relay_port & 0xFF)};
            send_all(fd, ok, 10);
            while (recv(fd, buf, sizeof buf, 0) > 0) {}   // 阻塞直到關閉
            goto done;
        } else if (cmd == 0x04) {
            if (g_fake_reject_udp_tcp) {
                // 不支援：REP=0x07 (command not supported)；期待引擎同連線退回 0x03
                unsigned char no[10] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                send_all(fd, no, 10);
                continue;
            }
            // 支援 UDP-in-TCP：回 success 後在同連線做 frame echo（2-byte len + datagram）
            unsigned char ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            send_all(fd, ok, 10);
            for (;;) {
                if (recv_exact(fd, buf, 2) < 0) goto done;
                unsigned short flen = (unsigned short)((buf[0] << 8) | buf[1]);
                if (flen > sizeof buf) goto done;
                if (recv_exact(fd, buf, flen) < 0) goto done;
                unsigned char hdr[2];
                hdr[0] = (unsigned char)(flen >> 8);
                hdr[1] = (unsigned char)(flen & 0xFF);
                if (send_all(fd, hdr, 2) < 0) goto done;
                if (send_all(fd, buf, flen) < 0) goto done;
            }
        } else {
            goto done;
        }
    }

done:
    close(fd);
    return NULL;
}

static void *udp_relay_thread(void *arg) {
    (void)arg;
    unsigned char buf[4096];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_udp_relay_fd, buf, sizeof buf, 0,
                             (struct sockaddr *)&from, &fl);
        if (n <= 0) break;
        // echo 回送：收到的即為完整 SOCKS5 UDP 資料格（RSV+FRAG+ATYP+ADDR+PORT+DATA）
        sendto(g_udp_relay_fd, buf, (size_t)n, 0, (struct sockaddr *)&from, fl);
    }
    return NULL;
}

static void *fake_server_thread(void *arg) {
    int lfd = (int)(intptr_t)arg;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) break;
        pthread_t th;
        pthread_create(&th, NULL, fake_client, (void *)(intptr_t)cfd);
        pthread_detach(th);
    }
    return NULL;
}

// 啟動假伺服器（TCP 監聽 + UDP relay），回傳 TCP 監聽 fd（呼叫者負責關閉）
static int start_fake_server(int *tcp_port_out) {
    int one = 1;
    struct sockaddr_in sa;
    socklen_t sl;

    // TCP listener
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return -1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(lfd); return -1; }
    if (listen(lfd, 16) < 0) { close(lfd); return -1; }
    sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    *tcp_port_out = ntohs(sa.sin_port);

    // UDP relay
    g_udp_relay_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_relay_fd < 0) { close(lfd); return -1; }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(g_udp_relay_fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        close(lfd); close(g_udp_relay_fd); g_udp_relay_fd = -1; return -1;
    }
    sl = sizeof sa;
    getsockname(g_udp_relay_fd, (struct sockaddr *)&sa, &sl);
    g_udp_relay_port = ntohs(sa.sin_port);

    pthread_t th;
    pthread_create(&th, NULL, fake_server_thread, (void *)(intptr_t)lfd);
    pthread_detach(th);
    pthread_create(&th, NULL, udp_relay_thread, NULL);
    pthread_detach(th);

    return lfd;
}

// ================= 封包建構 / 解析 helpers =================

// RFC 1071 網際網路檢查和
static uint16_t inet_csum(const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1) sum += (uint16_t)data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// 建構 IPv4 ICMP echo request（含 IP + ICMP checksum）
static ssize_t build_icmp_echo4(const unsigned char src[4], const unsigned char dst[4],
                                uint16_t id, uint16_t seq,
                                const unsigned char *payload, size_t plen,
                                unsigned char *out, size_t cap) {
    size_t total = 20 + 8 + plen;
    if (cap < total) return -1;
    memset(out, 0, total);
    out[0] = 0x45;                          // IPv4, IHL=5
    out[2] = (unsigned char)(total >> 8);   // total length
    out[3] = (unsigned char)(total & 0xFF);
    out[4] = (unsigned char)(id >> 8);      // identification
    out[5] = (unsigned char)(id & 0xFF);
    out[8] = 64;                            // TTL
    out[9] = 1;                             // proto = ICMP
    memcpy(out + 12, src, 4);
    memcpy(out + 16, dst, 4);
    uint16_t ipc = inet_csum(out, 20);
    out[10] = (unsigned char)(ipc >> 8);    // header checksum
    out[11] = (unsigned char)(ipc & 0xFF);

    unsigned char *icmp = out + 20;
    icmp[0] = 8;                            // echo request
    icmp[1] = 0;                            // code
    icmp[4] = (unsigned char)(id >> 8);
    icmp[5] = (unsigned char)(id & 0xFF);
    icmp[6] = (unsigned char)(seq >> 8);
    icmp[7] = (unsigned char)(seq & 0xFF);
    memcpy(icmp + 8, payload, plen);
    uint16_t csc = inet_csum(icmp, 8 + plen);
    icmp[2] = (unsigned char)(csc >> 8);
    icmp[3] = (unsigned char)(csc & 0xFF);
    return (ssize_t)total;
}

// 回傳 IPv4 封包的 TCP payload 指標與長度；非 TCP 或無 payload 回 -1
static ssize_t tcp_payload(const unsigned char *pkt, size_t len,
                           const unsigned char **payload_out) {
    if (len < 20 || (pkt[0] >> 4) != 4) return -1;
    int ihl = (pkt[0] & 0x0F) * 4;
    if (len < (size_t)ihl + 20) return -1;
    if (pkt[9] != 6) return -1;   // 非 TCP
    const unsigned char *tcp = pkt + ihl;
    int thl = (tcp[12] >> 4) * 4;
    if (thl < 20 || len < (size_t)ihl + (size_t)thl) return -1;
    if (payload_out) *payload_out = tcp + thl;
    return (ssize_t)(len - ihl - thl);
}

// 回傳 IPv4 封包的 UDP payload 指標與長度；非 UDP 回 -1
static ssize_t udp_payload(const unsigned char *pkt, size_t len,
                           const unsigned char **payload_out) {
    if (len < 28 || (pkt[0] >> 4) != 4) return -1;
    int ihl = (pkt[0] & 0x0F) * 4;
    if (len < (size_t)ihl + 8) return -1;
    if (pkt[9] != 17) return -1;   // 非 UDP
    if (payload_out) *payload_out = pkt + ihl + 8;
    return (ssize_t)(len - ihl - 8);
}

// 取得 IPv4 封包 TCP 序號（host 序）
static uint32_t tcp_seq(const unsigned char *pkt) {
    int ihl = (pkt[0] & 0x0F) * 4;
    uint32_t v;
    memcpy(&v, pkt + ihl + 4, 4);
    return ntohl(v);
}

// 讀一封包（poll 逾時），回傳長度或 -1
static ssize_t read_tun(int fd, unsigned char *buf, size_t cap, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1;
    return read(fd, buf, cap);
}

// 在 timeout 內反覆讀封包直到 predicate 成立；回傳 1 成功 / 0 逾時
typedef int (*pkt_pred_t)(const unsigned char *, size_t, void *);
static int wait_for_packet(int fd, unsigned char *buf, size_t cap, int timeout_ms,
                           pkt_pred_t pred, void *ctx) {
    int attempts = timeout_ms / 50;
    if (attempts < 1) attempts = 1;
    for (int i = 0; i < attempts; i++) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int rc = poll(&pfd, 1, 50);
        if (rc <= 0) continue;
        ssize_t n = read(fd, buf, cap);
        if (n <= 0) continue;
        if (pred(buf, (size_t)n, ctx)) return 1;
    }
    return 0;
}

// predicate：比對 UDP payload
typedef struct { const unsigned char *needle; size_t nlen; } payload_ctx_t;
static int udp_has_payload(const unsigned char *pkt, size_t len, void *vctx) {
    payload_ctx_t *c = (payload_ctx_t *)vctx;
    const unsigned char *p;
    ssize_t plen = udp_payload(pkt, len, &p);
    return plen == (ssize_t)c->nlen && plen > 0 && memcmp(p, c->needle, c->nlen) == 0;
}
// predicate：比對 TCP payload
static int tcp_has_payload(const unsigned char *pkt, size_t len, void *vctx) {
    payload_ctx_t *c = (payload_ctx_t *)vctx;
    const unsigned char *p;
    ssize_t plen = tcp_payload(pkt, len, &p);
    return plen == (ssize_t)c->nlen && plen > 0 && memcmp(p, c->needle, c->nlen) == 0;
}
// predicate：TCP 帶 FIN 旗標
static int tcp_has_fin(const unsigned char *pkt, size_t len, void *vctx) {
    (void)vctx;
    if (len < 20 || (pkt[0] >> 4) != 4 || pkt[9] != 6) return 0;
    int ihl = (pkt[0] & 0x0F) * 4;
    if (len < (size_t)ihl + 14) return 0;
    return (pkt[ihl + 13] & 0x01) != 0;
}
// predicate：TCP 帶 RST 旗標
static int tcp_has_rst(const unsigned char *pkt, size_t len, void *vctx) {
    (void)vctx;
    if (len < 20 || (pkt[0] >> 4) != 4 || pkt[9] != 6) return 0;
    int ihl = (pkt[0] & 0x0F) * 4;
    if (len < (size_t)ihl + 14) return 0;
    return (pkt[ihl + 13] & 0x04) != 0;
}

// predicate：TCP 帶 RST 旗標，且「目的埠」等於 ctx->dport（用來鎖定特定 App 連線）
typedef struct { uint16_t dport; } rst_port_ctx_t;
static int tcp_has_rst_to(const unsigned char *pkt, size_t len, void *vctx) {
    rst_port_ctx_t *c = (rst_port_ctx_t *)vctx;
    if (!tcp_has_rst(pkt, len, NULL)) return 0;
    int ihl = (pkt[0] & 0x0F) * 4;
    uint16_t dp = (uint16_t)((pkt[ihl + 2] << 8) | pkt[ihl + 3]);
    return dp == c->dport;
}

// 把一個完整 UDP datagram 拆成兩片 IPv4 分片（frag0 = UDP 頭 8 bytes + MF=1；
// frag1 = 其餘 payload + MF=0）。分片偏移以 8 為單位，故首片固定取 8 bytes。
static void build_udp_fragments(const unsigned char src[4], const unsigned char dst[4],
                                uint16_t sport, uint16_t dport,
                                const unsigned char *msg, size_t mlen, uint16_t id,
                                unsigned char frag0[512], ssize_t *f0len,
                                unsigned char frag1[512], ssize_t *f1len) {
    unsigned char udp[520];
    size_t udp_len = 8 + mlen;
    udp[0] = (unsigned char)(sport >> 8); udp[1] = (unsigned char)(sport & 0xFF);
    udp[2] = (unsigned char)(dport >> 8); udp[3] = (unsigned char)(dport & 0xFF);
    udp[4] = (unsigned char)(udp_len >> 8); udp[5] = (unsigned char)(udp_len & 0xFF);
    udp[6] = 0; udp[7] = 0;                     // checksum：fake 伺服器僅 echo，不需正確
    memcpy(udp + 8, msg, mlen);

    // frag0：UDP 頭（8 bytes），offset=0, MF=1
    size_t fl0 = 8, t0 = 20 + fl0;
    memset(frag0, 0, t0);
    frag0[0] = 0x45;
    frag0[2] = (unsigned char)(t0 >> 8); frag0[3] = (unsigned char)(t0 & 0xFF);
    frag0[4] = (unsigned char)(id >> 8); frag0[5] = (unsigned char)(id & 0xFF);
    frag0[6] = 0x20; frag0[7] = 0x00;           // MF=1, offset=0
    frag0[8] = 64; frag0[9] = 17;               // TTL, proto UDP
    memcpy(frag0 + 12, src, 4); memcpy(frag0 + 16, dst, 4);
    uint16_t c0 = inet_csum(frag0, 20);
    frag0[10] = (unsigned char)(c0 >> 8); frag0[11] = (unsigned char)(c0 & 0xFF);
    memcpy(frag0 + 20, udp, fl0);
    *f0len = (ssize_t)t0;

    // frag1：其餘 payload（mlen bytes），offset=8, MF=0
    size_t fl1 = mlen, t1 = 20 + fl1;
    memset(frag1, 0, t1);
    frag1[0] = 0x45;
    frag1[2] = (unsigned char)(t1 >> 8); frag1[3] = (unsigned char)(t1 & 0xFF);
    frag1[4] = (unsigned char)(id >> 8); frag1[5] = (unsigned char)(id & 0xFF);
    frag1[6] = 0x00; frag1[7] = 0x01;           // MF=0, offset = 8/8 = 1
    frag1[8] = 64; frag1[9] = 17;
    memcpy(frag1 + 12, src, 4); memcpy(frag1 + 16, dst, 4);
    uint16_t c1 = inet_csum(frag1, 20);
    frag1[10] = (unsigned char)(c1 >> 8); frag1[11] = (unsigned char)(c1 & 0xFF);
    memcpy(frag1 + 20, udp + 8, fl1);
    *f1len = (ssize_t)t1;
}

// 建構單一 DNS A-record 查詢封包（ID、RD=1、QDCOUNT=1、QNAME、QTYPE=A、QCLASS=IN）。
// domain 為 '.' 分隔的 ASCII 網域；成功回傳長度，0 = 名稱非法或空間不足。
static size_t build_dns_a_query(const char *domain, unsigned char *out, size_t cap) {
    if (cap < 12) return 0;
    memset(out, 0, cap);
    out[0] = 0x12; out[1] = 0x34;   // 隨意 ID
    out[2] = 0x01;                  // RD=1
    out[5] = 0x01;                  // QDCOUNT=1
    size_t off = 12;

    const char *start = domain;
    for (;;) {
        const char *dot = strchr(start, '.');
        size_t lbl = dot ? (size_t)(dot - start) : strlen(start);
        if (lbl == 0 || lbl > 63) return 0;
        if (off + 1 + lbl + 1 > cap) return 0;
        out[off++] = (unsigned char)lbl;
        memcpy(out + off, start, lbl);
        off += lbl;
        if (!dot) break;
        start = dot + 1;
    }
    out[off++] = 0;                 // 名稱結尾
    out[off++] = 0; out[off++] = 1; // QTYPE=A
    out[off++] = 0; out[off++] = 1; // QCLASS=IN
    return off;
}

// ================= 情境 helpers =================

// 建立一對 socketpair TUN 並啟動引擎；成功回傳測試端 fd，失敗回傳 -1。
static int start_engine(int tcp_port, const char *user, const char *pass,
                        int udp_in_tcp, int remote_dns) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0) return -1;
    if (tun_socks_start(sp[0], "127.0.0.1", tcp_port, user, pass, udp_in_tcp, remote_dns, NULL) != 0) {
        close(sp[0]); close(sp[1]); return -1;
    }
    return sp[1];
}

// 完整 TCP CONNECT + "hello" echo：SYN → SYN-ACK → ACK → DATA → echo。
// seq 自 1000 起算。成功回傳 srv_isn（非 0），失敗回傳 0。
static uint32_t tcp_echo_hello(int test_fd, const unsigned char *app_ip,
                               const unsigned char *target_ip, uint16_t sport, uint16_t dport) {
    unsigned char pkt[512], rbuf[512];
    ssize_t n = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                  1000, 0, 0x02, NULL, 0, 64240, pkt, sizeof pkt);
    if (n <= 0) return 0;
    write(test_fd, pkt, (size_t)n);

    ssize_t r = read_tun(test_fd, rbuf, sizeof rbuf, 3000);
    if (r <= 0) return 0;
    int ihl = (rbuf[0] & 0x0F) * 4;
    uint8_t flags = rbuf[ihl + 13];
    uint32_t ack_field; memcpy(&ack_field, rbuf + ihl + 8, 4);
    if ((flags & 0x12) != 0x12 || ntohl(ack_field) != 1001) return 0;
    uint32_t srv_isn = tcp_seq(rbuf);

    unsigned char ackpkt[512];
    ssize_t an = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                   1001, srv_isn + 1, 0x10, NULL, 0, 64240, ackpkt, sizeof ackpkt);
    write(test_fd, ackpkt, (size_t)an);

    const unsigned char msg[] = "hello";
    unsigned char dpkt[512];
    ssize_t dn = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                   1001, srv_isn + 1, 0x18, msg, sizeof msg, 64240, dpkt, sizeof dpkt);
    write(test_fd, dpkt, (size_t)dn);

    payload_ctx_t pctx = { msg, sizeof msg };
    if (!wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, tcp_has_payload, &pctx)) return 0;
    return srv_isn;
}

// ================= 主測試 =================

static const unsigned char APP_IP[4] = {10, 8, 0, 2};
static const unsigned char TARGET_IP[4] = {8, 8, 8, 8};

// ---- 情境 7 用：視窗欄位讀取 / 只做交握 / 尊重流控的上傳驅動 ----

// 讀引擎通告的 window（bytes）：SYNACK 協商 wscale=10，故欄位單位為 1KB。
static uint32_t tcp_win_bytes(const unsigned char *pkt) {
    int ihl = (pkt[0] & 0x0F) * 4;
    uint16_t w;
    memcpy(&w, pkt + ihl + 14, 2);
    return (uint32_t)ntohs(w) << 10;
}

// 只做三向交握（不送資料）：成功回傳 1，srv_isn_out 為伺服器 ISN、
// win_out 為引擎在 SYNACK 通告的接收視窗（bytes，已乘 wscale）。
static int tcp_handshake_only(int test_fd, const unsigned char *app_ip,
                              const unsigned char *target_ip, uint16_t sport, uint16_t dport,
                              uint32_t *srv_isn_out, uint32_t *win_out) {
    unsigned char pkt[512], rbuf[512], ackpkt[512];
    ssize_t n = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                  1000, 0, 0x02, NULL, 0, 64240, pkt, sizeof pkt);
    if (n <= 0) return 0;
    write(test_fd, pkt, (size_t)n);
    ssize_t r = read_tun(test_fd, rbuf, sizeof rbuf, 3000);
    if (r <= 0) return 0;
    int ihl = (rbuf[0] & 0x0F) * 4;
    uint8_t flags = rbuf[ihl + 13];
    uint32_t ack_field; memcpy(&ack_field, rbuf + ihl + 8, 4);
    if ((flags & 0x12) != 0x12 || ntohl(ack_field) != 1001) return 0;
    *srv_isn_out = tcp_seq(rbuf);
    *win_out = tcp_win_bytes(rbuf);
    ssize_t an = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                   1001, *srv_isn_out + 1, 0x10, NULL, 0, 64240,
                                   ackpkt, sizeof ackpkt);
    if (an <= 0) return 0;
    write(test_fd, ackpkt, (size_t)an);
    return 1;
}

typedef struct {
    size_t accepted;   // 引擎 ACK 的位元組數（= 已進入 app_buf）
    size_t sent;       // 驅動實際送出的位元組數
    uint32_t min_win;  // 觀察到的最小通告視窗（0 = 真的通告過零視窗）
    int saw_zero;      // 是否觀察到引擎通告零視窗
    int saw_reopen;    // 零視窗之後是否又觀察到開窗（window update）
    int probe_acked;   // 緩衝滿時故意超窗送一段，引擎是否有回 ACK（不得沉默）
} upload_stat_t;

// 尊重流控的上傳驅動：嚴格遵守引擎通告的 window（在途量 <= acked + win），
// 因此不會送出引擎會拒收的資料。引擎排空後以 window-update ACK 開窗，驅動才繼續。
// 回傳 1 = total 位元組全部被 ACK；0 = 逾時（視為卡死）或連線異常。
static int tcp_upload_flow_controlled(int test_fd, uint16_t sport, uint16_t dport,
                                      uint32_t app_isn, uint32_t srv_isn, uint32_t win0,
                                      size_t total, upload_stat_t *st) {
    unsigned char wbuf[1600], rbuf[4096];
    unsigned char payload[1400];
    memset(payload, 0xA5, sizeof payload);
    size_t sent = 0, acked = 0;
    uint32_t win = win0;             // SYNACK 通告的初始視窗
    int zero_seen = 0;
    int zero_printed = 0;
    int probed = 0;
    int dbg = 0;
    st->min_win = win0;
    for (int iter = 0; iter < 500000; iter++) {
        // 1. 排空引擎→App 的封包：只取 ACK/視窗（本情境伺服器不回送資料）
        for (;;) {
            struct pollfd pfd = { .fd = test_fd, .events = POLLIN };
            if (poll(&pfd, 1, 0) <= 0) break;
            ssize_t r = read(test_fd, rbuf, sizeof rbuf);
            if (r <= 0) break;
            if (r < 20 || (rbuf[0] >> 4) != 4 || rbuf[9] != 6) continue;
            int ihl = (rbuf[0] & 0x0F) * 4;
            if ((size_t)ihl + 20 > (size_t)r) continue;
            uint8_t flags = rbuf[ihl + 13];
            if (flags & 0x04) return 0;                       // RST
            if (!(flags & 0x10)) continue;
            uint32_t ack_field; memcpy(&ack_field, rbuf + ihl + 8, 4);
            size_t a = (size_t)(ntohl(ack_field) - (app_isn + 1));
            if (a > acked) acked = a;
            win = tcp_win_bytes(rbuf);
            if (dbg < 3 || a > total || (win == 0 && !zero_printed)) {
                printf("  [upload] seq=%u ack=%u flags=0x%02x win=%u -> accepted=%zu (sent=%zu)\n",
                       tcp_seq(rbuf), ntohl(ack_field), flags, win, a, sent);
                dbg++;
                if (win == 0) zero_printed = 1;
            }
            if (win < st->min_win) st->min_win = win;
            if (win == 0) zero_seen = 1;
            else if (zero_seen) st->saw_reopen = 1;
        }
        if (acked >= total) {
            st->accepted = acked;
            st->sent = sent;
            st->saw_zero = zero_seen;
            return 1;
        }
        // 2. 在視窗內送資料
        size_t allow = (acked + win > sent) ? (acked + win - sent) : 0;
        if (allow > 0) {
            size_t chunk = allow > sizeof payload ? sizeof payload : allow;
            if (chunk > total - sent) chunk = total - sent;
            ssize_t n = tcp_build_segment(APP_IP, TARGET_IP, AF_INET, sport, dport,
                                          app_isn + 1 + (uint32_t)sent, srv_isn + 1, 0x18,
                                          payload, chunk, 64240, wbuf, sizeof wbuf);
            if (n <= 0) return 0;
            if (write(test_fd, wbuf, (size_t)n) != n) return 0;
            sent += chunk;
        } else {
            // 視窗關閉（win==0 → 剩餘空間 <1KB）。先把既有 ACK 全部排空，再故意送一段
            // 必定放不下的資料（1400 bytes > 剩餘空間）做「超窗探測」：引擎必須回一個
            // ACK（dup ACK，視窗仍為 0），讓 App 知道這是流控而不是封包遺失。
            // 舊版在緩衝滿時完全不 ACK → App 只能靠 RTO 重傳 → cwnd 砍到 1。
            for (;;) {
                struct pollfd pfd = { .fd = test_fd, .events = POLLIN };
                if (poll(&pfd, 1, 0) <= 0) break;
                ssize_t r = read(test_fd, rbuf, sizeof rbuf);
                if (r < 20 || (rbuf[0] >> 4) != 4 || rbuf[9] != 6) continue;
                int ihl2 = (rbuf[0] & 0x0F) * 4;
                if (!(rbuf[ihl2 + 13] & 0x10)) continue;
                uint32_t af; memcpy(&af, rbuf + ihl2 + 8, 4);
                size_t a2 = (size_t)(ntohl(af) - (app_isn + 1));
                if (a2 > acked) acked = a2;
                win = tcp_win_bytes(rbuf);
                if (win == 0) zero_seen = 1;
                else if (zero_seen) st->saw_reopen = 1;
            }
            if (win != 0) {
                probed = 0;            // 視窗已開，下次關閉時再探
            } else if (!probed) {
                probed = 1;
                ssize_t pn = tcp_build_segment(APP_IP, TARGET_IP, AF_INET, sport, dport,
                                               app_isn + 1 + (uint32_t)sent, srv_isn + 1, 0x18,
                                               payload, sizeof payload, 64240,
                                               wbuf, sizeof wbuf);
                if (pn > 0) write(test_fd, wbuf, (size_t)pn);
                for (int t = 0; t < 20 && !st->probe_acked; t++) {
                    struct pollfd pfd = { .fd = test_fd, .events = POLLIN };
                    if (poll(&pfd, 1, 50) <= 0) continue;
                    ssize_t r = read(test_fd, rbuf, sizeof rbuf);
                    if (r < 20 || (rbuf[0] >> 4) != 4 || rbuf[9] != 6) continue;
                    int ihl2 = (rbuf[0] & 0x0F) * 4;
                    uint8_t f2 = rbuf[ihl2 + 13];
                    if ((f2 & 0x10) && !(f2 & 0x04)) st->probe_acked = 1;
                }
            } else {
                // 零視窗、已探測過：等 window update。
                // 必須真的等待 —— 空轉會燒光迭代額度並搶走引擎執行緒的 CPU。
                struct pollfd pfd = { .fd = test_fd, .events = POLLIN };
                poll(&pfd, 1, 20);
            }
        }
    }
    st->accepted = acked;
    st->sent = sent;
    st->saw_zero = zero_seen;
    return 0;
}

int main(void) {
    printf("=== tun_engine integration test (real engine + fake SOCKS5 + socketpair TUN) ===\n");

    // 假伺服器（全域旗標在各情境間切換行為）
    int tcp_port;
    int lfd = start_fake_server(&tcp_port);
    CHECK("fake server start", lfd >= 0);
    printf("  fake SOCKS5 127.0.0.1:%d (udp relay :%d)\n", tcp_port, g_udp_relay_port);

    const unsigned char *app_ip = APP_IP;
    const unsigned char *target_ip = TARGET_IP;

    // ============ 情境 1：預設引擎（無認證、UDP-in-UDP、無 Remote DNS） ============
    {
        int test_fd = start_engine(tcp_port, "", "", 0, 0);
        CHECK("engine start (default)", test_fd >= 0);

        // ---------- 1.1 ICMP echo（不需伺服器） ----------
        {
            unsigned char pkt[512], rbuf[512];
            const unsigned char payload[] = "ping42";
            ssize_t n = build_icmp_echo4(app_ip, target_ip, 0x1234, 1, payload, sizeof payload, pkt, sizeof pkt);
            CHECK("icmp echo build", n > 0);
            write(test_fd, pkt, (size_t)n);
            ssize_t r = read_tun(test_fd, rbuf, sizeof rbuf, 3000);
            CHECK("icmp reply received", r > 0);
            if (r > 0) {
                int is_ipv4 = (r > 20 && (rbuf[0] >> 4) == 4);
                int is_icmp_echo_reply = (r > 28 && rbuf[9] == 1 && rbuf[20] == 0);
                int dst_is_app = (r > 19 && memcmp(rbuf + 16, app_ip, 4) == 0);
                CHECK("icmp reply is echo reply to app", is_ipv4 && is_icmp_echo_reply && dst_is_app);
            }
        }

        // ---------- 1.2 TCP CONNECT 三向交握 + echo ----------
        {
            uint32_t srv_isn = tcp_echo_hello(test_fd, app_ip, target_ip, htons(12345), htons(80));
            CHECK("tcp connect echo", srv_isn != 0);
            CHECK("tcp server event OK", atomic_load(&g_host_last_server_event) == SE_EVENT_OK);
        }

        // ---------- 1.3 UDP relay echo ----------
        {
            const uint16_t sport = htons(53000);
            const uint16_t dport = htons(53);
            const unsigned char msg[] = "ping";
            unsigned char pkt[512], rbuf[512];

            ssize_t n = udp_build_packet(app_ip, target_ip, AF_INET, sport, dport,
                                         msg, sizeof msg, pkt, sizeof pkt);
            CHECK("udp packet build", n > 0);
            write(test_fd, pkt, (size_t)n);

            payload_ctx_t pctx = { msg, sizeof msg };
            int got = wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, udp_has_payload, &pctx);
            CHECK("udp relay echo", got == 1);
        }

        // ---------- 1.4 分片 UDP 端到端重組 echo ----------
        {
            const uint16_t sport = htons(54000);
            const uint16_t dport = htons(53);
            const unsigned char msg[] = "frag-echo";
            unsigned char f0[512], f1[512], rbuf[512];
            ssize_t n0, n1;
            build_udp_fragments(app_ip, target_ip, sport, dport, msg, sizeof msg, 0x5678,
                                f0, &n0, f1, &n1);
            CHECK("frag udp build", n0 > 0 && n1 > 0);
            write(test_fd, f0, (size_t)n0);
            write(test_fd, f1, (size_t)n1);

            payload_ctx_t pctx = { msg, sizeof msg };
            int got = wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, udp_has_payload, &pctx);
            CHECK("fragmented udp reassembly echo", got == 1);
        }

        // ---------- 1.5 TCP FIN 半關閉：App FIN → SHUT_WR → server EOF → 引擎回 FIN ----------
        {
            const uint16_t sport = htons(12346);
            const uint16_t dport = htons(80);
            unsigned char rbuf[512];
            // 先完成一次 echo（"hello" 6 bytes），讓 seq 有確定基準：
            // echo 後 App 下一個 seq = 1001+6 = 1007、srv_next = srv_isn+7。
            uint32_t srv_isn = tcp_echo_hello(test_fd, app_ip, target_ip, sport, dport);
            CHECK("fin: echo precondition", srv_isn != 0);
            if (srv_isn != 0) {
                unsigned char finpkt[512];
                ssize_t fn = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                               1007, srv_isn + 7, 0x11, NULL, 0, 64240,
                                               finpkt, sizeof finpkt);
                write(test_fd, finpkt, (size_t)fn);
                int got = wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, tcp_has_fin, NULL);
                CHECK("tcp FIN propagated back", got == 1);
            }
        }

        // ---------- 1.6 軟重連：重置 session 但保留引擎；舊連線須收 RST，新連線仍可建立 ----------
        {
            const uint16_t sport = htons(12347);
            const uint16_t dport = htons(80);
            // 先建立一個活躍 session
            uint32_t srv_isn = tcp_echo_hello(test_fd, app_ip, target_ip, sport, dport);
            CHECK("reconnect: precondition session", srv_isn != 0);

            tun_socks_reconnect(NULL);
            usleep(300000);   // 等引擎迴圈處理 reset（kick + epoll 喚醒）

            CHECK("engine still running after soft reconnect", tun_socks_is_running() == 1);

            // 不變式：soft reset 必須對舊 App 連線送 RST。否則 App 的 TCP 堆疊仍以為連線
            // 活著，會繼續把資料送進黑洞，只能等自己的 RTO 才重撥（實例：Android 私人 DNS
            // 的 DoT 長連線 → 換網後 DNS 全死，只能手動重建隧道）。
            unsigned char rbuf[512];
            rst_port_ctx_t rctx = { 12347 };
            int got_rst = wait_for_packet(test_fd, rbuf, sizeof rbuf, 1500, tcp_has_rst_to, &rctx);
            CHECK("soft reconnect sends RST to old app session", got_rst == 1);
            // RST 的 seq 必須是「伺服器下一個序號」＝ App 的 RCV.NXT。若送 0，App 的 TCP 堆疊
            // 依 RFC 5961 只會回 challenge ACK、不重置連線 → App 永遠等不到通知（真正的缺陷）。
            // 本 session echo 過 "hello"（6 bytes）⇒ srv_next = srv_isn + 1 + 6。
            CHECK("soft reconnect RST seq = srv_next (RFC 5961)",
                  got_rst == 1 && tcp_seq(rbuf) == srv_isn + 7);

            // 新 session 仍可建立（證明重置未破壞引擎）。
            // 讀取時只認「回給新 session（sport2）」的 SYN-ACK，避免被殘餘 RST 干擾。
            const uint16_t sport2 = htons(12348);
            unsigned char syn[512];
            ssize_t n = tcp_build_segment(app_ip, target_ip, AF_INET, sport2, dport,
                                          1000, 0, 0x02, NULL, 0, 64240, syn, sizeof syn);
            write(test_fd, syn, (size_t)n);
            int got_synack = 0;
            for (int i = 0; i < 20 && !got_synack; i++) {
                ssize_t r = read_tun(test_fd, rbuf, sizeof rbuf, 300);
                if (r <= 0) break;
                if (r < 20 || (rbuf[0] >> 4) != 4 || rbuf[9] != 6) continue;
                int ihl = (rbuf[0] & 0x0F) * 4;
                if (r < (ssize_t)ihl + 14) continue;
                uint16_t dstp = (uint16_t)((rbuf[ihl + 2] << 8) | rbuf[ihl + 3]);
                if (dstp == 12348 && (rbuf[ihl + 13] & 0x12) == 0x12) got_synack = 1;
            }
            CHECK("tcp SYN-ACK after soft reconnect", got_synack);
        }

        // ---------- 1.7 乾淨停止 ----------
        tun_socks_stop();
        CHECK("engine stopped (default)", tun_socks_is_running() == 0);
        CHECK("no unexpected engine stop", atomic_load(&g_host_engine_stopped) == 0);
        close(test_fd);
    }

    // ============ 情境 2：RFC 1929 認證成功 → TCP echo 正常 ============
    {
        g_fake_require_auth = 1;
        g_fake_reject_auth = 0;
        atomic_store(&g_host_last_server_event, SE_EVENT_NONE);
        int test_fd = start_engine(tcp_port, "u", "p", 0, 0);
        CHECK("engine start (auth-ok)", test_fd >= 0);

        uint32_t srv_isn = tcp_echo_hello(test_fd, app_ip, target_ip, htons(12345), htons(80));
        CHECK("auth-ok: tcp echo", srv_isn != 0);
        CHECK("auth-ok: event OK", atomic_load(&g_host_last_server_event) == SE_EVENT_OK);

        tun_socks_stop();
        close(test_fd);
        g_fake_require_auth = 0;
    }

    // ============ 情境 3：RFC 1929 認證被拒 → RST + AUTH_FAIL ============
    {
        g_fake_require_auth = 1;
        g_fake_reject_auth = 1;
        atomic_store(&g_host_last_server_event, SE_EVENT_NONE);
        int test_fd = start_engine(tcp_port, "u", "p", 0, 0);
        CHECK("engine start (auth-reject)", test_fd >= 0);

        const uint16_t sport = htons(22345);
        const uint16_t dport = htons(80);
        unsigned char pkt[512], rbuf[512];
        ssize_t n = tcp_build_segment(app_ip, target_ip, AF_INET, sport, dport,
                                      1000, 0, 0x02, NULL, 0, 64240, pkt, sizeof pkt);
        write(test_fd, pkt, (size_t)n);
        ssize_t r = read_tun(test_fd, rbuf, sizeof rbuf, 3000);
        CHECK("auth-reject: SYN-ACK", r > 0);

        // 認證被拒 → 引擎送 RST，並通知 AUTH_FAIL（不觸發看門狗）
        int got = wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, tcp_has_rst, NULL);
        CHECK("auth-reject: RST received", got == 1);
        CHECK("auth-reject: event AUTH_FAIL", atomic_load(&g_host_last_server_event) == SE_EVENT_AUTH_FAIL);

        tun_socks_stop();
        close(test_fd);
        g_fake_require_auth = 0;
        g_fake_reject_auth = 0;
    }

    // ============ 情境 4：UDP-in-TCP（自訂指令 0x04）frame relay echo ============
    {
        g_fake_reject_udp_tcp = 0;
        int test_fd = start_engine(tcp_port, "", "", 1, 0);
        CHECK("engine start (udp-in-tcp)", test_fd >= 0);

        const uint16_t sport = htons(55000);
        const uint16_t dport = htons(53);
        const unsigned char msg[] = "ping";
        unsigned char pkt[512], rbuf[512];
        ssize_t n = udp_build_packet(app_ip, target_ip, AF_INET, sport, dport,
                                     msg, sizeof msg, pkt, sizeof pkt);
        CHECK("udp-in-tcp: packet build", n > 0);
        write(test_fd, pkt, (size_t)n);

        payload_ctx_t pctx = { msg, sizeof msg };
        int got = wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, udp_has_payload, &pctx);
        CHECK("udp-in-tcp: relay echo", got == 1);

        tun_socks_stop();
        close(test_fd);
    }

    // ============ 情境 5：UDP-in-TCP 伺服器不支援 → 退回標準 UDP ASSOCIATE ============
    {
        g_fake_reject_udp_tcp = 1;
        int test_fd = start_engine(tcp_port, "", "", 1, 0);
        CHECK("engine start (udp-tcp-fallback)", test_fd >= 0);

        const uint16_t sport = htons(56000);
        const uint16_t dport = htons(53);
        const unsigned char msg[] = "fb";
        unsigned char pkt[512], rbuf[512];
        ssize_t n = udp_build_packet(app_ip, target_ip, AF_INET, sport, dport,
                                     msg, sizeof msg, pkt, sizeof pkt);
        write(test_fd, pkt, (size_t)n);

        payload_ctx_t pctx = { msg, sizeof msg };
        int got = wait_for_packet(test_fd, rbuf, sizeof rbuf, 5000, udp_has_payload, &pctx);
        CHECK("udp-tcp fallback: relay echo via 0x03", got == 1);

        tun_socks_stop();
        close(test_fd);
        g_fake_reject_udp_tcp = 0;
    }

    // ============ 情境 6：Remote DNS（fakedns）端到端 ============
    // App 發 DNS A 查詢 → 引擎攔截回 fake IP（198.18/15）→ App 連 fake IP →
    // 引擎查回網域、以 ATYP=0x03 撥號。tcp_echo_hello 的 echo 往返保證 CONNECT
    // 已完成（假 server 也已在 ATYP=0x03 分支記錄網域），故其後讀網域無競態。
    {
        g_fake_saw_domain = 0;
        g_fake_last_domain[0] = '\0';
        int test_fd = start_engine(tcp_port, "", "", 0, 1);   // remote_dns=1
        CHECK("engine start (remote-dns)", test_fd >= 0);

        const unsigned char dns_ip[4] = {8, 8, 8, 8};
        const uint16_t sport = htons(57000);

        // 1. DNS A 查詢 example.com
        unsigned char dnsq[512], pkt[512], rbuf[512];
        size_t qlen = build_dns_a_query("example.com", dnsq, sizeof dnsq);
        CHECK("remote-dns: dns query build", qlen > 0);
        ssize_t n = udp_build_packet(app_ip, dns_ip, AF_INET, sport, htons(53),
                                     dnsq, qlen, pkt, sizeof pkt);
        CHECK("remote-dns: dns packet build", n > 0);
        write(test_fd, pkt, (size_t)n);

        // 2. 讀 DNS 回覆，解析 fake IP（A record 的 RDATA = 回覆末 4 bytes，網路序）
        ssize_t r = read_tun(test_fd, rbuf, sizeof rbuf, 3000);
        CHECK("remote-dns: dns reply received", r > 0);
        unsigned char fake_ip[4] = {0, 0, 0, 0};
        int dns_ok = 0;
        if (r > 0) {
            const unsigned char *payload;
            ssize_t plen = udp_payload(rbuf, (size_t)r, &payload);
            int qr = plen > 2 && (payload[2] & 0x80) != 0;             // QR=1
            int an = plen > 7 && payload[6] == 0 && payload[7] == 1;   // ANCOUNT=1
            if (qr && an && plen >= 4) {
                memcpy(fake_ip, payload + plen - 4, 4);
                dns_ok = (fake_ip[0] == 198 && fake_ip[1] == 18);      // 198.18.0.0/15
            }
        }
        CHECK("remote-dns: fake IP in 198.18/15", dns_ok);

        // 3. 連 fake IP：echo 往返完成 CONNECT，並驗證 server 收到網域
        if (dns_ok) {
            uint32_t srv_isn = tcp_echo_hello(test_fd, app_ip, fake_ip, htons(57001), htons(80));
            CHECK("remote-dns: tcp echo via fake IP", srv_isn != 0);
            CHECK("remote-dns: server saw domain", g_fake_saw_domain == 1);
            CHECK("remote-dns: domain = example.com", strcmp(g_fake_last_domain, "example.com") == 0);
        }

        tun_socks_stop();
        close(test_fd);
    }

    // ============ 情境 7：上傳回壓 —— app_buf 滿時通告零視窗，不是沉默不 ACK ============
    // 假伺服器交握後先暫停讀取並丟棄上傳 → 引擎的 app_buf（4 MiB）被填滿。
    // 期望：① 觀察到引擎通告 win==0；② 伺服器恢復後以 window-update 開窗；
    //       ③ 全部位元組都被 ACK 且完整抵達伺服器（無重複、無遺漏、無卡死）。
    // 舊版（tcp_win_field_pure free==0 回 1）永遠不會通告 0，且緩衝滿時完全不 ACK
    // → saw_zero 為 0 → 本情境失敗。這是回壓修正的迴歸守衛。
    {
        const size_t total = 16 * 1024 * 1024;   // 遠大於 app_buf(4 MiB) + srv 送緩衝
        const uint16_t sport = htons(58000), dport = htons(80);
        g_fake_discard_upload = 1;
        g_fake_stall_read_ms = 800;
        // 需要追 fd 生命週期（誤關 / 重用）時把 g_bridge_verbose 設 1，會多印 request/release 行
        g_bridge_verbose = 0;
        atomic_store(&g_fake_upload_bytes, 0);
        atomic_store(&g_fake_upload_bad, 0);
        atomic_store(&g_fake_upload_exit_n, 99);
        atomic_store(&g_fake_upload_exit_errno, 99);

        int test_fd = start_engine(tcp_port, "", "", 0, 0);
        CHECK("engine start (upload backpressure)", test_fd >= 0);

        uint32_t srv_isn = 0, win0 = 0;
        int hs = tcp_handshake_only(test_fd, app_ip, target_ip, sport, dport, &srv_isn, &win0);
        CHECK("upload: handshake", hs == 1);
        printf("  upload: SYNACK window = %u bytes\n", win0);

        upload_stat_t st = { 0, 0, 0, 0, 0, 0 };
        int done = hs ? tcp_upload_flow_controlled(test_fd, sport, dport, 1000, srv_isn,
                                                   win0, total, &st) : 0;
        printf("  upload: sent=%zu accepted=%zu min_win=%u\n", st.sent, st.accepted, st.min_win);
        CHECK("upload: all bytes accepted (no deadlock)", done == 1);
        CHECK("upload: zero window advertised", st.saw_zero == 1);
        CHECK("upload: full-buffer probe still ACKed (not silent)", st.probe_acked == 1);
        CHECK("upload: window reopened after drain", st.saw_reopen == 1);

        // 引擎非同步把 app_buf 沖給伺服器：等位元組全部抵達（同時驗證 EPOLLOUT 續送）
        unsigned long long got = 0;
        for (int i = 0; i < 200; i++) {
            got = atomic_load(&g_fake_upload_bytes);
            if (got >= total) break;
            usleep(50000);
        }
        printf("  upload: server received %llu / %zu bytes (loop_exit recv=%d errno=%d)\n",
               got, total, atomic_load(&g_fake_upload_exit_n),
               atomic_load(&g_fake_upload_exit_errno));
        {
            unsigned long long to_srv = 0, from_srv = 0;
            int tcps = 0, udps = 0;
            tun_socks_get_stats(&to_srv, &from_srv, &tcps, &udps);
            printf("  upload: engine bytes_to_server=%llu tcp_sessions=%d\n", to_srv, tcps);
        }
        CHECK("upload: all bytes reached server", got == total);
        CHECK("upload: payload intact", atomic_load(&g_fake_upload_bad) == 0);

        tun_socks_stop();
        close(test_fd);
        g_fake_discard_upload = 0;
        g_fake_stall_read_ms = 0;
        g_bridge_verbose = 0;
    }

    close(lfd);
    if (g_udp_relay_fd >= 0) close(g_udp_relay_fd);

    printf(g_fail ? "\nRESULT: FAIL (tun_engine)\n" : "\nRESULT: PASS (tun_engine)\n");
    return g_fail;
}
