// tun_socks.c — 客戶端 TUN → SOCKS5 引擎
// 流量路徑:
//   [App] --TUN--> 本引擎解析封包 --SOCKS5--> [SOCKS5 伺服器] --> [目標]
//   UDP/DNS/QUIC：SOCKS5 UDP ASSOCIATE relay
//   TCP：內建 TCP 狀態機，經 SOCKS5 CONNECT 轉發
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

#include "jni_bridge.h"

#define LOG_TAG "TunSocks"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define MAX_PACKET_SIZE 4160
#define MAX_EVENTS 256
#define TUN_MTU 4096
#define UDP_IDLE_TIMEOUT_SEC 330
#define HANDSHAKE_TIMEOUT_SEC 10
#define UDP_HASH_BUCKETS 256
#define MAX_UDP_SESSIONS 512

static int g_tun_fd = -1;
static int g_shutdown_pipe[2] = {-1, -1};
static volatile int g_running = 0;
static int g_epoll_fd = -1;
static pthread_t g_engine_thread;

static char g_srv_host[256];
static int g_srv_port = 1080;
static char g_auth_user[128];
static char g_auth_pass[128];
static int g_auth_enabled = 0;
static int g_udp_in_tcp = 0;    // 1 = UDP relay 走 TCP frame（cmd=0x04 擴充）

static atomic_int g_udp_session_count = 0;
static atomic_int g_handshake_inflight = 0;

// ---------- 位址抽象（v4 / v6 共用 session 結構） ----------

typedef struct {
    int family;             // AF_INET / AF_INET6
    unsigned char ip[16];   // 網路序位址（v4 存前 4 bytes）
} ip_addr_t;

static int ip_addr_eq(const ip_addr_t *a, const ip_addr_t *b) {
    return a->family == b->family && memcmp(a->ip, b->ip, 16) == 0;
}

static uint32_t ip_hash32(const ip_addr_t *a) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++) { h ^= a->ip[i]; h *= 16777619u; }
    return h ^ (uint32_t)a->family;
}

static void ip_to_str(const ip_addr_t *a, char *out, size_t n) {
    if (a->family == AF_INET6) inet_ntop(AF_INET6, a->ip, out, n);
    else inet_ntop(AF_INET, a->ip, out, n);
}

// ---------- TCP 會話（P2） ----------

#define TCP_HASH_BUCKETS 256
#define MAX_TCP_SESSIONS 512
#define TCP_APP_BUF_CAP (1024 * 1024)
#define TCP_SRV_BUF_CAP (1024 * 1024)
#define TCP_IDLE_TIMEOUT_SEC 300
#define TCP_READ_CHUNK (64 * 1024)

typedef struct tcp_sess {
    ip_addr_t src_ip;       // App 端來源 IP（v4/v6）
    uint16_t src_port;      // App 端來源 Port（網路序）
    ip_addr_t dst_ip;       // 真實目標 IP（v4/v6）
    uint16_t dst_port;      // 真實目標 Port（網路序）
    atomic_int srv_fd;      // SOCKS5 CONNECT 的 stream socket（Java protect）
    atomic_int state;       // 0=CONNECT 中 1=就緒
    atomic_int handshake_failed;
    int closed;             // engine 單一執行緒持有
    int want_out;           // srv_fd 已註冊 EPOLLOUT
    int srv_in_off;         // 緩衝滿時暫停讀 srv_fd
    uint32_t app_win;       // App 通告的 window（已乘 WS，bytes）
    uint32_t app_acked;     // App 已確認的最高 seq（host 序）
    uint8_t app_ws;         // App SYN 協商的 window scale
    uint32_t app_isn;       // App 的 ISN
    uint32_t app_next;      // 我方期望的 App 下一個 seq（= ACK 值）
    uint32_t srv_isn;       // 我方 ISN
    uint32_t srv_next;      // 我方下一個要送的 seq
    int app_fin;            // 已收到 App FIN
    int srv_eof;            // server 已 EOF（read 回 0）
    int srv_fin_sent;       // 已送 FIN 給 App
    unsigned char *app_buf; size_t app_off, app_len, app_cap;  // App→server 待送（off=已送出前綴）
    unsigned char *srv_buf; size_t srv_off, srv_len, srv_cap;  // server→App 待送（off=已寫 TUN 前綴）
    time_t last_active;
    struct tcp_sess *next;  // hash chain
} tcp_sess_t;

static tcp_sess_t *g_tcp_hash[TCP_HASH_BUCKETS];
static atomic_int g_tcp_session_count = 0;
static int g_kick_pipe[2] = {-1, -1};
static int g_tun_want_out = 0;

static unsigned tcp_hash_idx(const ip_addr_t *ip, uint16_t port) {
    return (ip_hash32(ip) ^ (uint32_t)port) % TCP_HASH_BUCKETS;
}

static uint32_t tcp_isn_counter = 0;
static uint32_t next_tcp_isn(void) {
    return ((uint32_t)time(NULL) ^ 0x5F3759DF) + (++tcp_isn_counter) * 2654435761u;
}

typedef struct udp_sess {
    ip_addr_t src_ip;       // App 端來源 IP（v4/v6）
    uint16_t src_port;      // App 端來源 Port（網路序）
    int control_fd;         // 通往伺服器的 TCP 控制連線（Java protect）
    int relay_fd;           // 伺服器 UDP relay 的 socket（Java protect）；UDP-in-TCP 時為 -1
    struct sockaddr_in relay_addr;
    int state;              // 0=handshake 中 1=就緒
    int closed;
    time_t last_active;
    unsigned char *pend_data;   // handshake 期間緩衝的首包（避免等 App 重傳）
    uint16_t pend_len;
    ip_addr_t pend_ip;          // 首包目標 IP（v4/v6）
    uint16_t pend_port;         // 首包目標 Port（網路序）
    // UDP-in-TCP：relay 直接走 control_fd 上的 frame 串流
    int udp_tcp;                // 1 = 使用 frame-over-TCP relay
    unsigned char *tx_buf; size_t tx_len, tx_off, tx_cap;   // → server 的待送佇列
    int tx_armed;               // control_fd 已註冊 EPOLLOUT
    unsigned char *rx_buf; size_t rx_len, rx_off, rx_cap;   // ← server 的串流緩衝
    int rx_want;                // -1 = 待讀 2-byte 長度欄；>=0 = 待讀 datagram 長度
    struct udp_sess *next;  // hash chain
} udp_sess_t;

static udp_sess_t *g_udp_hash[UDP_HASH_BUCKETS];
static pthread_mutex_t g_udp_hash_lock = PTHREAD_MUTEX_INITIALIZER;

static void udp_sess_free_bufs(udp_sess_t *sess);

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static unsigned udp_hash_idx(const ip_addr_t *ip, uint16_t port) {
    return (ip_hash32(ip) ^ (uint32_t)port) % UDP_HASH_BUCKETS;
}

// ---------- checksum ----------

// 以 32-bit 累加「byte-swapped 的 16-bit word」（大尾序資料以 little-endian 讀 4 bytes）
static uint32_t accum_swapped(const unsigned char *data, size_t len, uint32_t sum) {
    while (len >= 4) {
        uint32_t w;
        memcpy(&w, data, 4);
        sum += (w & 0xFFFF) + (w >> 16);
        data += 4; len -= 4;
    }
    while (len > 1) { sum += (uint32_t)((data[1] << 8) | data[0]); data += 2; len -= 2; }
    if (len) sum += (uint32_t)data[0];
    return sum;
}

// 完成累加並 swap 回真值（~ 後交換高低位元組）
static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t res = (uint16_t)~sum;
    return (uint16_t)((res >> 8) | (res << 8));
}

static uint16_t checksum16(const unsigned char *data, size_t len) {
    return checksum_finish(accum_swapped(data, len, 0));
}

static uint16_t tcpudp_checksum4(const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len) {
    unsigned char ph[12];
    memcpy(ph, saddr, 4);
    memcpy(ph + 4, daddr, 4);
    ph[8] = 0; ph[9] = proto;
    uint16_t l = htons((uint16_t)len);
    memcpy(ph + 10, &l, 2);
    uint32_t sum = accum_swapped(ph, 12, 0);
    sum = accum_swapped(data, len, sum);
    return checksum_finish(sum);
}

static uint16_t tcpudp_checksum6(const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len) {
    unsigned char ph[40];
    memcpy(ph, saddr, 16);
    memcpy(ph + 16, daddr, 16);
    uint32_t l = htonl((uint32_t)len);
    memcpy(ph + 32, &l, 4);
    ph[36] = 0; ph[37] = 0; ph[38] = 0; ph[39] = proto;
    uint32_t sum = accum_swapped(ph, 40, 0);
    sum = accum_swapped(data, len, sum);
    return checksum_finish(sum);
}

static uint16_t transport_checksum(int family, const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len) {
    if (family == AF_INET6) return tcpudp_checksum6(saddr, daddr, proto, data, len);
    return tcpudp_checksum4(saddr, daddr, proto, data, len);
}

// ---------- TUN 封包處理 ----------

static int parse_ipv4(const unsigned char *pkt, size_t len, uint8_t *proto, ip_addr_t *saddr, ip_addr_t *daddr, int *ihl) {
    if (len < 20) return -1;
    if ((pkt[0] >> 4) != 4) return -1;
    *ihl = (pkt[0] & 0x0F) * 4;
    if (*ihl < 20 || (size_t)*ihl > len) return -1;
    *proto = pkt[9];
    saddr->family = AF_INET; memcpy(saddr->ip, pkt + 12, 4); memset(saddr->ip + 4, 0, 12);
    daddr->family = AF_INET; memcpy(daddr->ip, pkt + 16, 4); memset(daddr->ip + 4, 0, 12);
    return 0;
}

// 注意：不處理 IPv6 extension header（常見無 ext header 的封包可正常運作）
static int parse_ipv6(const unsigned char *pkt, size_t len, uint8_t *proto, ip_addr_t *saddr, ip_addr_t *daddr) {
    if (len < 40) return -1;
    if ((pkt[0] >> 4) != 6) return -1;
    *proto = pkt[6];
    saddr->family = AF_INET6; memcpy(saddr->ip, pkt + 8, 16);
    daddr->family = AF_INET6; memcpy(daddr->ip, pkt + 24, 16);
    return 0;
}

// 回覆 App 的 IP 封包（relay 回應 → TUN）
static void write_ipv4_udp_to_tun(udp_sess_t *sess, const ip_addr_t *remote, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    if (plen > TUN_MTU - 28) { LOGE("relay UDP payload 過大 (%zu)，丟棄", plen); return; }
    unsigned char pkt[TUN_MTU];
    size_t total = 20 + 8 + plen;

    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2] = (total >> 8) & 0xFF; pkt[3] = total & 0xFF;
    pkt[4] = 0; pkt[5] = 0;
    pkt[6] = 0; pkt[7] = 0;
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    memcpy(pkt + 12, remote->ip, 4);
    memcpy(pkt + 16, sess->src_ip.ip, 4);
    pkt[10] = 0; pkt[11] = 0;   // checksum 欄位先歸零
    uint16_t csum = checksum16(pkt, 20);
    pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;

    size_t u = 20;
    memcpy(pkt + u, &remote_port, 2);
    memcpy(pkt + u + 2, &sess->src_port, 2);
    uint16_t ulen = (uint16_t)(8 + plen);
    pkt[u + 4] = ulen >> 8; pkt[u + 5] = ulen & 0xFF;
    pkt[u + 6] = 0; pkt[u + 7] = 0;
    memcpy(pkt + u + 8, payload, plen);
    uint16_t ucsum = tcpudp_checksum4(remote->ip, sess->src_ip.ip, 17, pkt + u, 8 + plen);
    pkt[u + 6] = ucsum >> 8; pkt[u + 7] = ucsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun failed: %s", strerror(errno));
}

static void write_ipv6_udp_to_tun(udp_sess_t *sess, const ip_addr_t *remote, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    if (plen > TUN_MTU - 48) { LOGE("relay UDP payload 過大 (%zu)，丟棄", plen); return; }
    unsigned char pkt[TUN_MTU];
    size_t total = 40 + 8 + plen;

    pkt[0] = 0x60;                        // version=6
    pkt[1] = 0; pkt[2] = 0; pkt[3] = 0;   // traffic class / flow label
    size_t pl = 8 + plen;
    pkt[4] = (pl >> 8) & 0xFF; pkt[5] = pl & 0xFF;   // payload length
    pkt[6] = 17;                          // next header = UDP
    pkt[7] = 64;                          // hop limit
    memcpy(pkt + 8, remote->ip, 16);
    memcpy(pkt + 24, sess->src_ip.ip, 16);

    size_t u = 40;
    memcpy(pkt + u, &remote_port, 2);
    memcpy(pkt + u + 2, &sess->src_port, 2);
    uint16_t ulen = (uint16_t)(8 + plen);
    pkt[u + 4] = ulen >> 8; pkt[u + 5] = ulen & 0xFF;
    pkt[u + 6] = 0; pkt[u + 7] = 0;
    memcpy(pkt + u + 8, payload, plen);
    uint16_t ucsum = tcpudp_checksum6(remote->ip, sess->src_ip.ip, 17, pkt + u, 8 + plen);
    pkt[u + 6] = ucsum >> 8; pkt[u + 7] = ucsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun failed: %s", strerror(errno));
}

static void write_udp_to_tun(udp_sess_t *sess, const ip_addr_t *remote, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    if (remote->family != sess->src_ip.family) { LOGE("relay 回應 family 不符，丟棄"); return; }
    if (sess->src_ip.family == AF_INET6) write_ipv6_udp_to_tun(sess, remote, remote_port, payload, plen);
    else write_ipv4_udp_to_tun(sess, remote, remote_port, payload, plen);
}

// P1：TCP 一律回 RST|ACK，讓 App 立即收到連線失敗（Phase 2 才實作 TCP 隧道）
static ssize_t write_tcp_to_tun(const ip_addr_t *saddr, const ip_addr_t *daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const unsigned char *payload, size_t plen);

static void send_tcp_rst(const ip_addr_t *src, const ip_addr_t *dst, const unsigned char *tcp, size_t tlen) {
    if (tlen < 20) return;
    uint16_t sport, dport;
    uint32_t seq;
    memcpy(&sport, tcp, 2);
    memcpy(&dport, tcp + 2, 2);
    memcpy(&seq, tcp + 4, 4);
    uint32_t seq_host = ntohl(seq);                      // 網路序 → host 序
    uint8_t off_flags = tcp[12];
    uint8_t flags = tcp[13];
    int tcp_hlen = (off_flags >> 4) * 4;
    if (tcp_hlen < 20 || tlen < (size_t)tcp_hlen) return;
    size_t payload = tlen - tcp_hlen;
    uint32_t ack_host = seq_host + (uint32_t)(payload + ((flags & 0x02) ? 1 : 0));
    // 回應方向：src←(dst_ip, dst_port)，seq=0, ack=對應值
    write_tcp_to_tun(dst, src, dport, sport, 0, ack_host, 0x14, NULL, 0);
}

// ---------- UDP 會話 ----------

static void handle_relay_udp(udp_sess_t *sess, const unsigned char *buf, ssize_t len);

// UDP-in-TCP：將一整個 frame（長度欄 + SOCKS5 datagram）加入送出佇列。
// 只在「未 arm EPOLLOUT」時才觸發第一次，避免重複 MOD。
static void udp_tcp_append(udp_sess_t *sess, const unsigned char *frame, size_t flen) {
    if (sess->tx_len + flen > sess->tx_cap) {
        LOGE("udp-in-tcp tx 佇列滿，丟棄 datagram");
        return;
    }
    if (sess->tx_len == 0) sess->tx_off = 0;
    memcpy(sess->tx_buf + sess->tx_off + sess->tx_len, frame, flen);
    sess->tx_len += flen;
    if (!sess->tx_armed) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR;
        ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, sess->control_fd, &ev) == 0) sess->tx_armed = 1;
    }
}

// 排空送出佇列；回傳 <0 = 連線已死
static int udp_tcp_flush(udp_sess_t *sess) {
    while (sess->tx_len > 0) {
        ssize_t n = send(sess->control_fd, sess->tx_buf + sess->tx_off, sess->tx_len, MSG_NOSIGNAL);
        if (n > 0) {
            sess->tx_off += (size_t)n;
            sess->tx_len -= (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            return -1;
        }
    }
    if (sess->tx_len == 0) {
        sess->tx_off = 0;
        if (sess->tx_armed) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
            ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
            if (epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, sess->control_fd, &ev) == 0) sess->tx_armed = 0;
        }
    }
    return 0;
}

// 從 control_fd 讀入並解析 frames；回傳 <0 = 連線已死
static int udp_tcp_read(udp_sess_t *sess) {
    // 1. 讀入可用位元組
    for (;;) {
        if (sess->rx_len == 0) sess->rx_off = 0;
        size_t space = sess->rx_cap - sess->rx_off - sess->rx_len;
        if (space == 0) return -1; // frame 長度欄異常（>rx_cap）→ 協定違規
        ssize_t n = recv(sess->control_fd, sess->rx_buf + sess->rx_off + sess->rx_len, space, 0);
        if (n > 0) {
            sess->rx_len += (size_t)n;
            continue;
        }
        if (n == 0) return -1; // EOF
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }
    // 2. 解析 frames
    for (;;) {
        if (sess->rx_want < 0) {
            if (sess->rx_len < 2) break;
            int L = (sess->rx_buf[sess->rx_off] << 8) | sess->rx_buf[sess->rx_off + 1];
            if (L < 4 || L > (int)sess->rx_cap) return -1;
            sess->rx_off += 2;
            sess->rx_len -= 2;
            sess->rx_want = L;
        }
        if ((size_t)sess->rx_want > sess->rx_len) break;
        handle_relay_udp(sess, sess->rx_buf + sess->rx_off, sess->rx_want);
        sess->rx_off += sess->rx_want;
        sess->rx_len -= sess->rx_want;
        sess->rx_want = -1;
    }
    if (sess->rx_len == 0) sess->rx_off = 0;
    return 0;
}

static void forward_udp_to_server(udp_sess_t *sess, const ip_addr_t *dst, uint16_t dst_port, const unsigned char *payload, size_t plen) {
    unsigned char frame[2 + 22 + MAX_PACKET_SIZE];
    if (plen > MAX_PACKET_SIZE) plen = MAX_PACKET_SIZE;
    size_t off = 2;
    memset(frame + 2, 0, 4);
    if (dst->family == AF_INET6) {
        frame[2 + 3] = 0x04; // ATYP IPv6
        memcpy(frame + 2 + 4, dst->ip, 16);
        memcpy(frame + 2 + 20, &dst_port, 2);
        off = 2 + 22;
    } else {
        frame[2 + 3] = 0x01; // ATYP IPv4
        memcpy(frame + 2 + 4, dst->ip, 4);
        memcpy(frame + 2 + 8, &dst_port, 2);
        off = 2 + 10;
    }
    memcpy(frame + off, payload, plen);
    int datalen = (int)(off - 2 + plen);
    frame[0] = (unsigned char)(datalen >> 8);
    frame[1] = (unsigned char)(datalen & 0xFF);

    if (sess->udp_tcp) {
        // UDP-in-TCP：frame 直接進控制連線的送出佇列
        udp_tcp_append(sess, frame, 2 + (size_t)datalen);
    } else {
        ssize_t sent = sendto(sess->relay_fd, frame + 2, (size_t)datalen, MSG_NOSIGNAL,
                              (struct sockaddr *)&sess->relay_addr, sizeof(sess->relay_addr));
        if (sent < 0) LOGE("relay sendto 失敗: %s", strerror(errno));
    }
}

static void *udp_session_thread(void *arg);

static void handle_tun_udp(const unsigned char *pkt, size_t len, size_t t, const ip_addr_t *src_ip, const ip_addr_t *dst_ip) {
    size_t u = t;
    if (u + 8 > len) return;
    uint16_t sport, dport, ulen;
    memcpy(&sport, pkt + u, 2);
    memcpy(&dport, pkt + u + 2, 2);
    memcpy(&ulen, pkt + u + 4, 2);
    size_t payload_len = ntohs(ulen);
    if (payload_len < 8) return;
    payload_len -= 8;
    if (u + 8 + payload_len > len) payload_len = len - u - 8;

    // 以 App 的 (src_ip, src_port) 作為會話鍵（一個 ASSOCIATE 可對多個目標）
    unsigned idx = udp_hash_idx(src_ip, sport);
    udp_sess_t *sess = NULL;
    int created = 0;
    pthread_mutex_lock(&g_udp_hash_lock);
    for (udp_sess_t *s = g_udp_hash[idx]; s; s = s->next) {
        if (ip_addr_eq(&s->src_ip, src_ip) && s->src_port == sport && !s->closed) { sess = s; break; }
    }
    if (!sess && atomic_load(&g_udp_session_count) < MAX_UDP_SESSIONS) {
        sess = calloc(1, sizeof(udp_sess_t));
        if (sess) {
            sess->src_ip = *src_ip;
            sess->src_port = sport;
            sess->control_fd = -1;
            sess->relay_fd = -1;
            sess->last_active = time(NULL);
            sess->next = g_udp_hash[idx];
            g_udp_hash[idx] = sess;
            atomic_fetch_add(&g_udp_session_count, 1);
            created = 1;
        }
    }
    pthread_mutex_unlock(&g_udp_hash_lock);

    if (!sess) return;

    if (created) {
        char b1[64], b2[64];
        ip_to_str(src_ip, b1, sizeof b1);
        ip_to_str(dst_ip, b2, sizeof b2);
        LOGI("udp session 建立 src=%s:%d dst=%s:%d",
             b1, ntohs(sport), b2, ntohs(dport));
        // 首次封包：啟動 handshake 線程；同時緩衝此封包，完成後立即轉發（不用等 App 重傳）
        // 上限 1400：涵蓋 QUIC Initial（~1200B）避免被丟棄等重傳
        if (payload_len <= 1400) {
            sess->pend_data = malloc(payload_len);
            if (sess->pend_data) {
                memcpy(sess->pend_data, pkt + u + 8, payload_len);
                sess->pend_len = (uint16_t)payload_len;
                sess->pend_ip = *dst_ip;
                sess->pend_port = dport;
            }
        }
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&th, &attr, udp_session_thread, sess);
        pthread_attr_destroy(&attr);
        if (rc != 0) {
            // 線程建立失敗：移除會話，避免永久卡在 connecting
            pthread_mutex_lock(&g_udp_hash_lock);
            udp_sess_t **pp = &g_udp_hash[idx];
            while (*pp && *pp != sess) pp = &(*pp)->next;
            if (*pp) {
                *pp = sess->next;
                sess->closed = 1;
                pthread_mutex_unlock(&g_udp_hash_lock);
                udp_sess_free_bufs(sess);
                free(sess);
                atomic_fetch_sub(&g_udp_session_count, 1);
            } else {
                pthread_mutex_unlock(&g_udp_hash_lock);
            }
        }
        return;
    }

    if (sess->state == 0) {
        // handshake 進行中：若尚未緩衝首包則緩衝，完成後由線程轉發
        pthread_mutex_lock(&g_udp_hash_lock);
        if (sess->state == 0 && !sess->pend_data && payload_len <= 1400) {
            sess->pend_data = malloc(payload_len);
            if (sess->pend_data) {
                memcpy(sess->pend_data, pkt + u + 8, payload_len);
                sess->pend_len = (uint16_t)payload_len;
                sess->pend_ip = *dst_ip;
                sess->pend_port = dport;
            }
        }
        pthread_mutex_unlock(&g_udp_hash_lock);
        return;
    }
    forward_udp_to_server(sess, dst_ip, dport, pkt + u + 8, payload_len);
}

static int send_all(int fd, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

// 釋放 session 的動態緩衝（pend / udp-in-tcp 收發佇列）；呼叫者仍需 free(sess)
static void udp_sess_free_bufs(udp_sess_t *sess) {
    if (sess->pend_data) { free(sess->pend_data); sess->pend_data = NULL; }
    if (sess->tx_buf) { free(sess->tx_buf); sess->tx_buf = NULL; }
    if (sess->rx_buf) { free(sess->rx_buf); sess->rx_buf = NULL; }
}

// 每當 App 送出第一個 UDP 封包，為該 (src_ip, src_port) 建立 SOCKS5 UDP 會話
static void *udp_session_thread(void *arg) {
    jni_attach_thread();
    atomic_fetch_add(&g_handshake_inflight, 1);
    udp_sess_t *sess = (udp_sess_t *)arg;
    unsigned char buf[320];
    int cfd = -1, rfd = -1;
    struct sockaddr_in relay = {0};

    // 1. TCP 控制連線（Java 已 connect + protect）
    cfd = request_java_socket(g_srv_host, g_srv_port, 0);
    if (cfd < 0) goto fail;
    if (!g_running) goto fail;
    struct timeval tv = {HANDSHAKE_TIMEOUT_SEC, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    // 2. SOCKS5 握手
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = g_auth_enabled ? 0x02 : 0x00;
    if (send_all(cfd, buf, 3) < 0) goto fail;
    if (recv_all(cfd, buf, 2) < 0) goto fail;
    if (buf[0] != 0x05) goto fail;
    if (buf[1] == 0x02) {
        // RFC 1929
        size_t ul = strlen(g_auth_user), pl = strlen(g_auth_pass);
        buf[0] = 0x01; buf[1] = (unsigned char)ul;
        memcpy(buf + 2, g_auth_user, ul);
        buf[2 + ul] = (unsigned char)pl;
        memcpy(buf + 3 + ul, g_auth_pass, pl);
        if (send_all(cfd, buf, 3 + ul + pl) < 0) goto fail;
        if (recv_all(cfd, buf, 2) < 0) goto fail;
        if (buf[0] != 0x01 || buf[1] != 0x00) goto fail;
    } else if (buf[1] != 0x00) {
        goto fail;
    }

    // 3. UDP ASSOCIATE
    unsigned char req[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    int udp_tcp = 0;
    if (g_udp_in_tcp) {
        // 先嘗試 UDP-in-TCP（自訂擴充指令 0x04）
        req[1] = 0x04;
        if (send_all(cfd, req, 10) < 0) goto fail;
        if (recv_all(cfd, buf, 4) < 0) goto fail;
        if (buf[0] != 0x05) goto fail;
        if (buf[1] == 0x00) {
            // 伺服器支援：relay 就是這條 TCP 連線，吃掉 BND.ADDR/PORT 即可
            int atyp_r = buf[3];
            if (atyp_r == 0x01) {
                if (recv_all(cfd, buf, 6) < 0) goto fail;
            } else if (atyp_r == 0x04) {
                if (recv_all(cfd, buf, 18) < 0) goto fail;
            } else {
                goto fail;
            }
            udp_tcp = 1;
        } else {
            // 伺服器不支援 0x04：同一連線退回標準 UDP ASSOCIATE（0x03）
            LOGI("伺服器不支援 UDP-in-TCP (REP=%d)，退回 UDP-in-UDP", buf[1]);
            req[1] = 0x03;
            if (send_all(cfd, req, 10) < 0) goto fail;
            if (recv_all(cfd, buf, 4) < 0) goto fail;
            if (buf[0] != 0x05 || buf[1] != 0x00) goto fail;
        }
    } else {
        if (send_all(cfd, req, 10) < 0) goto fail;
        if (recv_all(cfd, buf, 4) < 0) goto fail;
        if (buf[0] != 0x05 || buf[1] != 0x00) goto fail;
    }

    if (!udp_tcp) {
        int atyp = buf[3];
        if (atyp == 0x01) {
            if (recv_all(cfd, buf, 6) < 0) goto fail;
            relay.sin_family = AF_INET;
            memcpy(&relay.sin_addr, buf, 4);
            memcpy(&relay.sin_port, buf + 4, 2);
        } else {
            // P1：只支援 IPv4 relay 位址（自家伺服器固定回 v4）
            LOGE("UDP ASSOCIATE 回覆 ATYP=%d 不支援", atyp);
            goto fail;
        }

        // 4. UDP relay socket（Java protect，未 connect，由 sendto 指定目標）
        rfd = request_java_socket(g_srv_host, g_srv_port, 1);
        if (rfd < 0) goto fail;
        if (!g_running) goto fail;
        set_nonblocking(rfd);
    } else {
        // UDP-in-TCP：初始化 frame 串流的收發緩衝
        sess->udp_tcp = 1;
        sess->tx_cap = 65536;
        sess->tx_buf = malloc(sess->tx_cap);
        sess->rx_cap = 8192;
        sess->rx_buf = malloc(sess->rx_cap);
        sess->rx_want = -1;
        if (!sess->tx_buf || !sess->rx_buf) goto fail;
    }

    if (!g_running) goto fail;
    set_nonblocking(cfd);
    sess->control_fd = cfd;
    sess->relay_fd = rfd;
    sess->relay_addr = relay;

    // 先寫狀態再註冊 epoll（main loop 在 epoll_wait 回傳後才能看到 session）
    sess->state = 1;
    sess->last_active = time(NULL);
    struct epoll_event ev;
    // 注意：epoll_data 是 union，data.fd 與 data.ptr 共用記憶體。
    // 因此把 fd 號碼存進 data.fd 後，讀 data.ptr 會得到垃圾指標；
    // 改用「指標低 bit」區分事件來源：control 存原指標，relay 存指標|1。
    if (udp_tcp) {
        // UDP-in-TCP：control_fd 兼任 relay，以 tag=1 註冊
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR; ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
    } else {
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR; ev.data.ptr = sess;
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP; ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, rfd, &ev) < 0) { epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, cfd, NULL); goto fail; }
    }

    // 立即轉發 handshake 期間緩衝的首包（不需等 App 重傳）
    pthread_mutex_lock(&g_udp_hash_lock);
    unsigned char *pd = sess->pend_data;
    size_t pl = sess->pend_len;
    ip_addr_t pip = sess->pend_ip;
    uint16_t pport = sess->pend_port;
    sess->pend_data = NULL;
    sess->pend_len = 0;
    pthread_mutex_unlock(&g_udp_hash_lock);
    if (pd) {
        forward_udp_to_server(sess, &pip, pport, pd, pl);
        free(pd);
    }

    atomic_fetch_sub(&g_handshake_inflight, 1);
    if (udp_tcp) LOGI("udp handshake 完成: UDP-in-TCP (relay 走同一 TCP)");
    else LOGI("udp handshake 完成: relay=%s:%d", inet_ntoa(relay.sin_addr), ntohs(relay.sin_port));
    jni_detach_thread();
    return NULL;

fail:
    {
        char b1[64];
        ip_to_str(&sess->src_ip, b1, sizeof b1);
        LOGI("udp handshake 失敗 (src=%s:%d)", b1, ntohs(sess->src_port));
    }
    if (cfd >= 0) { release_java_socket(cfd); close(cfd); }
    if (rfd >= 0) { release_java_socket(rfd); close(rfd); }
    // 從 hash 移除並釋放（誰 unlink 誰 free，避免雙重釋放）
    pthread_mutex_lock(&g_udp_hash_lock);
    unsigned idx = udp_hash_idx(&sess->src_ip, sess->src_port);
    udp_sess_t **pp = &g_udp_hash[idx];
    while (*pp && *pp != sess) pp = &(*pp)->next;
    if (*pp) {
        *pp = sess->next;
        sess->closed = 1;
        pthread_mutex_unlock(&g_udp_hash_lock);
        udp_sess_free_bufs(sess);
        free(sess);
        atomic_fetch_sub(&g_udp_session_count, 1);
    } else {
        pthread_mutex_unlock(&g_udp_hash_lock);
    }
    atomic_fetch_sub(&g_handshake_inflight, 1);
    jni_detach_thread();
    return NULL;
}

// relay 回應 → 還原成 IP 封包寫回 TUN
static void handle_relay_udp(udp_sess_t *sess, const unsigned char *buf, ssize_t len) {
    if (len < 4) return;
    int atyp = buf[3];
    if (atyp == 0x01) {
        if (len < 10) return;
        ip_addr_t remote = { .family = AF_INET };
        memcpy(remote.ip, buf + 4, 4);
        uint16_t rport;
        memcpy(&rport, buf + 8, 2);
        size_t plen = (size_t)len - 10;
        write_udp_to_tun(sess, &remote, rport, buf + 10, plen);
    } else if (atyp == 0x04) {
        if (len < 22) return;
        ip_addr_t remote = { .family = AF_INET6 };
        memcpy(remote.ip, buf + 4, 16);
        uint16_t rport;
        memcpy(&rport, buf + 20, 2);
        size_t plen = (size_t)len - 22;
        write_udp_to_tun(sess, &remote, rport, buf + 22, plen);
    } else {
        // domain 回應丟棄
    }
}

static void close_session_fds(udp_sess_t *sess) {
    if (sess->control_fd >= 0) {
        if (g_epoll_fd >= 0) epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, sess->control_fd, NULL);
        release_java_socket(sess->control_fd);
        close(sess->control_fd);
        sess->control_fd = -1;
    }
    if (sess->relay_fd >= 0) {
        if (g_epoll_fd >= 0) epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, sess->relay_fd, NULL);
        release_java_socket(sess->relay_fd);
        close(sess->relay_fd);
        sess->relay_fd = -1;
    }
}

// ---------- TCP 封包處理 ----------

// 送出 TCP 封包給 App（以 App 觀點：saddr/daddr 為 IP 位址，sport/dport 為埠）
// seq/ack 以 host byte order 傳入，內部轉網路序寫出
static ssize_t write_tcp_to_tun(const ip_addr_t *saddr, const ip_addr_t *daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const unsigned char *payload, size_t plen) {
    int is6 = (saddr->family == AF_INET6);
    size_t ip_hlen = is6 ? 40 : 20;
    if (ip_hlen + 20 + plen > TUN_MTU) { LOGE("tcp 封包過大 (%zu)，丟棄", plen); return -1; }
    unsigned char pkt[TUN_MTU];
    size_t total = ip_hlen + 20 + plen;

    if (is6) {
        pkt[0] = 0x60;
        pkt[1] = 0; pkt[2] = 0; pkt[3] = 0;
        size_t pl = 20 + plen;
        pkt[4] = (pl >> 8) & 0xFF; pkt[5] = pl & 0xFF;
        pkt[6] = 6;
        pkt[7] = 64;
        memcpy(pkt + 8, saddr->ip, 16);
        memcpy(pkt + 24, daddr->ip, 16);
    } else {
        pkt[0] = 0x45; pkt[1] = 0;
        pkt[2] = (total >> 8) & 0xFF; pkt[3] = total & 0xFF;
        pkt[4] = 0; pkt[5] = 0;
        pkt[6] = 0; pkt[7] = 0;
        pkt[8] = 64;
        pkt[9] = 6;
        memcpy(pkt + 12, saddr->ip, 4);
        memcpy(pkt + 16, daddr->ip, 4);
        pkt[10] = 0; pkt[11] = 0;   // checksum 欄位先歸零
        uint16_t csum = checksum16(pkt, 20);
        pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;
    }

    size_t u = ip_hlen;
    memcpy(pkt + u, &sport, 2);
    memcpy(pkt + u + 2, &dport, 2);
    uint32_t seq_n = htonl(seq);
    uint32_t ack_n = htonl(ack);
    memcpy(pkt + u + 4, &seq_n, 4);
    memcpy(pkt + u + 8, &ack_n, 4);
    pkt[u + 12] = 0x50;
    pkt[u + 13] = flags;
    pkt[u + 14] = 0xFF; pkt[u + 15] = 0xFF;   // window 65535
    pkt[u + 16] = 0; pkt[u + 17] = 0;
    pkt[u + 18] = 0; pkt[u + 19] = 0;
    if (plen) memcpy(pkt + u + 20, payload, plen);
    uint16_t tcsum = transport_checksum(saddr->family, saddr->ip, daddr->ip, 6, pkt + u, 20 + plen);
    pkt[u + 16] = tcsum >> 8; pkt[u + 17] = tcsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun tcp failed: %s", strerror(errno));
    return w;
}

static void send_tcp_synack(tcp_sess_t *sess) {
    if (g_tun_fd < 0) return;
    int is6 = (sess->src_ip.family == AF_INET6);
    size_t ip_hlen = is6 ? 40 : 20;
    unsigned char pkt[TUN_MTU];
    size_t total = ip_hlen + 32;                     // 32-byte TCP（MSS + WS 選項）

    if (is6) {
        pkt[0] = 0x60;
        pkt[1] = 0; pkt[2] = 0; pkt[3] = 0;
        size_t pl = 32;
        pkt[4] = (pl >> 8) & 0xFF; pkt[5] = pl & 0xFF;
        pkt[6] = 6;
        pkt[7] = 64;
        memcpy(pkt + 8, sess->dst_ip.ip, 16);
        memcpy(pkt + 24, sess->src_ip.ip, 16);
    } else {
        pkt[0] = 0x45; pkt[1] = 0;
        pkt[2] = (total >> 8) & 0xFF; pkt[3] = total & 0xFF;
        pkt[4] = 0; pkt[5] = 0;
        pkt[6] = 0; pkt[7] = 0;
        pkt[8] = 64;
        pkt[9] = 6;
        memcpy(pkt + 12, sess->dst_ip.ip, 4);
        memcpy(pkt + 16, sess->src_ip.ip, 4);
        pkt[10] = 0; pkt[11] = 0;   // checksum 欄位先歸零
        uint16_t csum = checksum16(pkt, 20);
        pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;
    }

    size_t u = ip_hlen;
    memcpy(pkt + u, &sess->dst_port, 2);
    memcpy(pkt + u + 2, &sess->src_port, 2);
    uint32_t isn_n = htonl(sess->srv_isn);
    uint32_t ack_n = htonl(sess->app_next);
    memcpy(pkt + u + 4, &isn_n, 4);
    memcpy(pkt + u + 8, &ack_n, 4);
    pkt[u + 12] = 0x80;            // 32-byte TCP header（含 MSS + WS）
    pkt[u + 13] = 0x12;            // SYN|ACK
    pkt[u + 14] = 0xFF; pkt[u + 15] = 0xFF;
    pkt[u + 16] = 0; pkt[u + 17] = 0;   // checksum 欄位先歸零
    pkt[u + 18] = 0; pkt[u + 19] = 0;
    pkt[u + 20] = 0x02; pkt[u + 21] = 0x04;   // kind=2(MSS) len=4
    uint16_t mss = htons((uint16_t)(TUN_MTU - (is6 ? 60 : 40)));
    memcpy(pkt + u + 22, &mss, 2);            // MSS 依 family 調整（v6 多 20 bytes header）
    pkt[u + 24] = 0x01; pkt[u + 25] = 0x01;   // NOP NOP
    pkt[u + 26] = 0x03; pkt[u + 27] = 0x03;   // kind=3(WS) len=3
    pkt[u + 28] = 0x0A;                        // shift=10（與 App 提議相同）
    pkt[u + 29] = 0; pkt[u + 30] = 0; pkt[u + 31] = 0;
    uint16_t tcsum = transport_checksum(sess->src_ip.family, sess->dst_ip.ip, sess->src_ip.ip, 6, pkt + u, 32);
    pkt[u + 16] = tcsum >> 8; pkt[u + 17] = tcsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0) LOGE("write tun SYN-ACK failed: %s (errno=%d)", strerror(errno), errno);
    else if (w != (ssize_t)total) LOGI("write tun SYN-ACK partial %zd/%zu", w, total);
}

static void send_tcp_ack(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x10, NULL, 0);
}

static void send_tcp_fin(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x11, NULL, 0);
}

static void send_session_rst(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     0, sess->app_next, 0x14, NULL, 0);
}

// ---------- 背景連線用 IO（poll 短循環 + g_running 檢查） ----------

static int wait_fd(int fd, short events, int timeout_ms) {
    int waited = 0;
    while (waited < timeout_ms) {
        struct pollfd p = { fd, events, 0 };
        int r = poll(&p, 1, 100);
        if (r > 0) return 0;
        if (r < 0) return -1;
        waited += 100;
        if (!g_running) return -1;
    }
    return -1;
}

static int net_send_all(int fd, const unsigned char *buf, size_t len) {
    while (len) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n > 0) { buf += n; len -= (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_fd(fd, POLLOUT, 10000) < 0) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

static int net_recv_all(int fd, unsigned char *buf, size_t len) {
    while (len) {
        ssize_t n = recv(fd, buf, len, 0);
        if (n > 0) { buf += n; len -= (size_t)n; continue; }
        if (n == 0) return -1;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (wait_fd(fd, POLLIN, 10000) < 0) return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

// ---------- TCP 會話管理 ----------

static void tcp_session_destroy(tcp_sess_t *sess) {
    int fd = atomic_load(&sess->srv_fd);
    if (fd >= 0) {
        if (g_epoll_fd >= 0) epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        release_java_socket(fd);
        close(fd);
        atomic_store(&sess->srv_fd, -1);
    }
    unsigned idx = tcp_hash_idx(&sess->src_ip, sess->src_port);
    tcp_sess_t **pp = &g_tcp_hash[idx];
    while (*pp && *pp != sess) pp = &(*pp)->next;
    if (*pp) *pp = sess->next;
    free(sess->app_buf);
    free(sess->srv_buf);
    free(sess);
    atomic_fetch_sub(&g_tcp_session_count, 1);
}

// engine 單一執行緒呼叫（唯一釋放 session 之處，background 線程不碰 hash）
static void close_tcp_session(tcp_sess_t *sess, int send_rst) {
    if (sess->closed) return;
    sess->closed = 1;
    LOGI("tcp session 關閉 app_bytes=%u srv_bytes=%u rst=%d",
         (uint32_t)(sess->app_next - sess->app_isn - 1),
         (uint32_t)(sess->srv_next - sess->srv_isn - 1), send_rst);
    if (send_rst) send_session_rst(sess);
    tcp_session_destroy(sess);
}

static void set_srv_events(tcp_sess_t *sess) {
    int fd = atomic_load(&sess->srv_fd);
    if (fd < 0) return;
    struct epoll_event ev;
    ev.events = EPOLLERR | EPOLLRDHUP | (sess->srv_in_off ? 0 : EPOLLIN)
              | (sess->want_out ? EPOLLOUT : 0);
    ev.data.ptr = (tcp_sess_t *)((uintptr_t)sess | 3);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

static void set_srv_out(tcp_sess_t *sess, int enable) {
    if (sess->want_out == enable) return;
    sess->want_out = enable;
    set_srv_events(sess);
}

static void set_srv_in(tcp_sess_t *sess, int enable) {
    if (sess->srv_in_off == !enable) return;
    sess->srv_in_off = !enable;
    set_srv_events(sess);
}

static void set_tun_epoll_out(int enable) {
    if (g_tun_want_out == enable || g_tun_fd < 0 || g_epoll_fd < 0) return;
    g_tun_want_out = enable;
    struct epoll_event ev;
    ev.events = EPOLLIN | (enable ? EPOLLOUT : 0);
    ev.data.fd = g_tun_fd;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, g_tun_fd, &ev);
}

// server→App：把緩衝的資料切成 TCP segment 寫回 TUN
static void flush_tcp_srv_buf(tcp_sess_t *sess) {
    while (sess->srv_len > 0) {
        size_t seg_max = (sess->src_ip.family == AF_INET6) ? (TUN_MTU - 60) : (TUN_MTU - 40);
        size_t chunk = sess->srv_len;
        if (chunk > seg_max) chunk = seg_max;
        // 流量控制：App 通告 window 已滿 → 暫停送出，等 App ACK 開窗
        if (sess->srv_next - sess->app_acked >= sess->app_win) break;
        ssize_t w = write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                                     sess->srv_next, sess->app_next, 0x18,
                                     sess->srv_buf + sess->srv_off, chunk);
        if (w < 0) { set_tun_epoll_out(1); return; }
        sess->srv_next += (uint32_t)chunk;
        sess->srv_off += chunk;
        sess->srv_len -= chunk;
        if (sess->srv_len == 0) sess->srv_off = 0;
    }
    // 已送出超過一半前綴 → 搬移回收空間（分攤成本，避免逐 segment memmove）
    if (sess->srv_off >= TCP_SRV_BUF_CAP / 2) {
        memmove(sess->srv_buf, sess->srv_buf + sess->srv_off, sess->srv_len);
        sess->srv_off = 0;
    }
    if (sess->srv_in_off && sess->srv_len < TCP_SRV_BUF_CAP / 2) set_srv_in(sess, 1);
    if (sess->srv_eof && sess->srv_len == 0 && !sess->srv_fin_sent) {
        sess->srv_fin_sent = 1;
        send_tcp_fin(sess);
    }
}

// App→server：把緩衝的資料寫到 srv_fd（fatal 只標記 closed，不釋放）
static void flush_tcp_app_buf(tcp_sess_t *sess) {
    int fd = atomic_load(&sess->srv_fd);
    if (fd < 0) return;
    while (sess->app_len > 0) {
        ssize_t n = send(fd, sess->app_buf + sess->app_off, sess->app_len, MSG_NOSIGNAL);
        if (n > 0) {
            sess->app_off += (size_t)n;
            sess->app_len -= (size_t)n;
            if (sess->app_len == 0) sess->app_off = 0;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            sess->closed = 1;
            return;
        }
    }
    if (sess->app_len == 0) {
        set_srv_out(sess, 0);
        if (sess->app_fin) shutdown(fd, SHUT_WR);
    }
}

// 在 app_buf 尾部保留 need 位元組空間（不足時先 compact）；回傳寫入位置或 NULL
static unsigned char *app_buf_reserve(tcp_sess_t *sess, size_t need) {
    if (sess->app_buf == NULL) sess->app_buf = malloc(TCP_APP_BUF_CAP);
    if (!sess->app_buf) return NULL;
    if (sess->app_off > 0 && sess->app_len > 0) {
        memmove(sess->app_buf, sess->app_buf + sess->app_off, sess->app_len);
        sess->app_off = 0;
    }
    if (sess->app_off + sess->app_len + need > TCP_APP_BUF_CAP) return NULL;
    return sess->app_buf + sess->app_off + sess->app_len;
}

static void flush_all_tcp(void) {
    int any_pending = 0;
    for (int b = 0; b < TCP_HASH_BUCKETS; b++) {
        tcp_sess_t *s = g_tcp_hash[b];
        while (s) {
            tcp_sess_t *n = s->next;
            if (!s->closed && atomic_load(&s->state) == 1) {
                if (s->srv_len > 0) { flush_tcp_srv_buf(s); if (s->srv_len > 0) any_pending = 1; }
                if (s->app_len > 0) {
                    flush_tcp_app_buf(s);
                    if (s->closed) tcp_session_destroy(s);   // fatal → 銷毀
                }
            }
            s = n;
        }
    }
    set_tun_epoll_out(any_pending);
}

// 清除 connect 失敗的 session（由 kick 觸發）
static void tcp_engine_sweep(void) {
    tcp_sess_t *garbage[128];
    int gc = 0;
    for (int b = 0; b < TCP_HASH_BUCKETS && gc < 128; b++) {
        for (tcp_sess_t *s = g_tcp_hash[b]; s && gc < 128; s = s->next) {
            if (!s->closed && atomic_load(&s->handshake_failed)) { s->closed = 1; garbage[gc++] = s; }
        }
    }
    for (int i = 0; i < gc; i++) tcp_session_destroy(garbage[i]);
}

// SOCKS5 CONNECT 背景線程：完成後註冊 epoll 並 kick 引擎送出緩衝資料
static void *tcp_connect_thread(void *arg) {
    jni_attach_thread();
    atomic_fetch_add(&g_handshake_inflight, 1);
    tcp_sess_t *sess = (tcp_sess_t *)arg;
    unsigned char buf[320];
    int sfd = -1;

    sfd = request_java_socket(g_srv_host, g_srv_port, 0);
    if (sfd < 0) goto fail;
    if (!g_running) goto fail;
    set_nonblocking(sfd);

    buf[0] = 0x05; buf[1] = 0x01; buf[2] = g_auth_enabled ? 0x02 : 0x00;
    if (net_send_all(sfd, buf, 3) < 0) goto fail;
    if (net_recv_all(sfd, buf, 2) < 0) goto fail;
    if (buf[0] != 0x05) goto fail;
    if (buf[1] == 0x02) {
        size_t ul = strlen(g_auth_user), pl = strlen(g_auth_pass);
        buf[0] = 0x01; buf[1] = (unsigned char)ul;
        memcpy(buf + 2, g_auth_user, ul);
        buf[2 + ul] = (unsigned char)pl;
        memcpy(buf + 3 + ul, g_auth_pass, pl);
        if (net_send_all(sfd, buf, 3 + ul + pl) < 0) goto fail;
        if (net_recv_all(sfd, buf, 2) < 0) goto fail;
        if (buf[0] != 0x01 || buf[1] != 0x00) goto fail;
    } else if (buf[1] != 0x00) {
        goto fail;
    }

    unsigned char req[22] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    int req_len;
    if (sess->dst_ip.family == AF_INET6) {
        req[3] = 0x04; // ATYP IPv6
        memcpy(req + 4, sess->dst_ip.ip, 16);
        memcpy(req + 20, &sess->dst_port, 2);
        req_len = 22;
    } else {
        memcpy(req + 4, sess->dst_ip.ip, 4);
        memcpy(req + 8, &sess->dst_port, 2);
        req_len = 10;
    }
    if (net_send_all(sfd, req, req_len) < 0) goto fail;
    if (net_recv_all(sfd, buf, 4) < 0) goto fail;
    if (buf[0] != 0x05 || buf[1] != 0x00) goto fail;
    int atyp = buf[3];
    if (atyp == 0x01) {
        if (net_recv_all(sfd, buf, 6) < 0) goto fail;
    } else if (atyp == 0x03) {
        unsigned char al;
        if (net_recv_all(sfd, buf, 1) < 0) goto fail;
        al = buf[0];
        if (net_recv_all(sfd, buf, al + 2) < 0) goto fail;
    } else if (atyp == 0x04) {
        if (net_recv_all(sfd, buf, 18) < 0) goto fail;
    } else {
        goto fail;
    }

    atomic_store(&sess->srv_fd, sfd);
    atomic_store(&sess->state, 1);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
    ev.data.ptr = (tcp_sess_t *)((uintptr_t)sess | 3);
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
        atomic_store(&sess->srv_fd, -1);
        goto fail;
    }
    if (g_kick_pipe[1] >= 0) { char k = 1; write(g_kick_pipe[1], &k, 1); }
    char b1[64];
    ip_to_str(&sess->dst_ip, b1, sizeof b1);
    LOGI("tcp connect 完成 -> %s:%d", b1, ntohs(sess->dst_port));
    atomic_fetch_sub(&g_handshake_inflight, 1);
    jni_detach_thread();
    return NULL;

fail:
    ip_to_str(&sess->dst_ip, b1, sizeof b1);
    LOGI("tcp connect 失敗 -> %s:%d", b1, ntohs(sess->dst_port));
    if (sfd >= 0) { release_java_socket(sfd); close(sfd); }
    if (g_tun_fd >= 0) send_session_rst(sess);
    atomic_store(&sess->handshake_failed, 1);
    if (g_kick_pipe[1] >= 0) { char k = 1; write(g_kick_pipe[1], &k, 1); }
    atomic_fetch_sub(&g_handshake_inflight, 1);
    jni_detach_thread();
    return NULL;
}

// 處理來自 TUN 的 TCP 封包（P2 TCP 狀態機）
static void handle_tun_tcp(const unsigned char *pkt, size_t len, size_t t,
                           const ip_addr_t *src_ip, const ip_addr_t *dst_ip) {
    if (t + 20 > len) return;
    uint16_t sport, dport;
    uint32_t seq;
    memcpy(&sport, pkt + t, 2);
    memcpy(&dport, pkt + t + 2, 2);
    memcpy(&seq, pkt + t + 4, 4);
    uint32_t seq_host = ntohl(seq);                        // 網路序 → host 序
    uint32_t ack_field;
    memcpy(&ack_field, pkt + t + 8, 4);
    uint32_t ack_host = ntohl(ack_field);
    uint8_t off_flags = pkt[t + 12];
    uint8_t flags = pkt[t + 13];
    int tcp_hlen = (off_flags >> 4) * 4;
    if (tcp_hlen < 20 || t + (size_t)tcp_hlen > len) return;
    size_t payload_len = len - t - (size_t)tcp_hlen;

    unsigned idx = tcp_hash_idx(src_ip, sport);
    tcp_sess_t *sess = NULL;
    for (tcp_sess_t *s = g_tcp_hash[idx]; s; s = s->next) {
        if (ip_addr_eq(&s->src_ip, src_ip) && s->src_port == sport && !s->closed) { sess = s; break; }
    }

    if (!sess) {
        if (!(flags & 0x02) || (flags & 0x10)) return;   // 僅 SYN 可建立（SYN+ACK 忽略）
        if (atomic_load(&g_tcp_session_count) >= MAX_TCP_SESSIONS) {
            send_tcp_rst(src_ip, dst_ip, pkt + t, len - t);   // 滿載 → RST
            return;
        }
        sess = calloc(1, sizeof(tcp_sess_t));
        if (!sess) return;
        sess->src_ip = *src_ip; sess->src_port = sport;
        sess->dst_ip = *dst_ip; sess->dst_port = dport;
        atomic_store(&sess->srv_fd, -1);
        sess->app_isn = seq_host;
        sess->app_next = seq_host + 1;
        sess->srv_isn = next_tcp_isn();
        sess->srv_next = sess->srv_isn + 1;
        sess->app_acked = sess->srv_isn + 1;
        sess->app_win = 0x3FFFFFFF;          // 未知前不限制
        for (int o = 20; o + 2 <= tcp_hlen; ) {   // 解析 App SYN 的 window scale
            uint8_t k = pkt[t + o];
            if (k == 0) break;
            if (k == 1) { o += 1; continue; }
            if (k == 3 && o + 3 <= tcp_hlen) sess->app_ws = pkt[t + o + 2];
            if (o + 1 < tcp_hlen) o += pkt[t + o + 1];
            else break;
        }
        sess->last_active = time(NULL);
        sess->next = g_tcp_hash[idx];
        g_tcp_hash[idx] = sess;
        atomic_fetch_add(&g_tcp_session_count, 1);

        char b1[64], b2[64];
        ip_to_str(src_ip, b1, sizeof b1);
        ip_to_str(dst_ip, b2, sizeof b2);
        LOGI("tcp session 建立 src=%s:%d -> dst=%s:%d",
             b1, ntohs(sport), b2, ntohs(dport));
        send_tcp_synack(sess);

        pthread_t th; pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&th, &attr, tcp_connect_thread, sess);
        pthread_attr_destroy(&attr);
        if (rc != 0) close_tcp_session(sess, 1);
        return;
    }

    if (atomic_load(&sess->handshake_failed)) {
        if ((flags & 0x02) && !(flags & 0x10)) {
            close_tcp_session(sess, 0);                    // 取代失敗的舊會話
            handle_tun_tcp(pkt, len, t, src_ip, dst_ip);
        }
        return;
    }

    sess->last_active = time(NULL);

    // 更新 App 通告的 window（乘 WS）與 ack，供 srv→App 流量控制
    uint16_t win_field;
    memcpy(&win_field, pkt + t + 14, 2);
    sess->app_win = ((uint32_t)ntohs(win_field)) << sess->app_ws;
    if (ack_host > sess->app_acked) sess->app_acked = ack_host;

    if ((flags & 0x02) && !(flags & 0x10)) {               // SYN 重傳
        if (atomic_load(&sess->state) == 0) send_tcp_synack(sess);
        return;
    }

    if (flags & 0x04) {                                    // RST
        char b1[64];
        ip_to_str(src_ip, b1, sizeof b1);
        LOGI("tcp RST from app state=%d %s:%d", atomic_load(&sess->state),
             b1, ntohs(sport));
        close_tcp_session(sess, 0);
        return;
    }

    if (seq_host != sess->app_next) {                     // 亂序 / 重傳 → 重複 ACK
        send_tcp_ack(sess);
        if (sess->srv_len > 0) flush_tcp_srv_buf(sess);    // dup-ACK 仍可能開窗
        return;
    }

    if (sess->srv_fin_sent) {                              // 我方已送 FIN
        if (payload_len == 0) close_tcp_session(sess, 0);
        else close_tcp_session(sess, 1);
        return;
    }

    if (payload_len == 0 && (flags & 0x10)) {              // 純 ACK：確認 app 收到資料
        if (sess->srv_len > 0) flush_tcp_srv_buf(sess);    // ACK 開窗 → 續送
        return;
    }

    if (payload_len > 0) {
        if (atomic_load(&sess->state) == 0) {
            // CONNECT 中：緩衝並 ACK（避免等 app 重傳），建立後由 kick 觸發送出
            unsigned char *dst = app_buf_reserve(sess, payload_len);
            if (dst) {
                memcpy(dst, pkt + t + (size_t)tcp_hlen, payload_len);
                sess->app_len += payload_len;
                sess->app_next += (uint32_t)payload_len;
                send_tcp_ack(sess);
            }
            // 緩衝滿 / malloc 失敗：不 ACK → app 重傳
        } else {
            int sfd = atomic_load(&sess->srv_fd);
            if (sfd < 0) return;
            if (sess->app_len == 0) {
                ssize_t n = send(sfd, pkt + t + (size_t)tcp_hlen, payload_len, MSG_NOSIGNAL);
                if (n == (ssize_t)payload_len) {
                    sess->app_next += (uint32_t)payload_len;
                    send_tcp_ack(sess);
                } else if (n > 0) {
                    sess->app_next += (uint32_t)n;
                    unsigned char *dst = app_buf_reserve(sess, payload_len - (size_t)n);
                    if (dst) {
                        memcpy(dst, pkt + t + (size_t)tcp_hlen + n, payload_len - (size_t)n);
                        sess->app_len = payload_len - (size_t)n;
                        send_tcp_ack(sess);
                        set_srv_out(sess, 1);
                    }
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    unsigned char *dst = app_buf_reserve(sess, payload_len);
                    if (dst) {
                        memcpy(dst, pkt + t + (size_t)tcp_hlen, payload_len);
                        sess->app_len = payload_len;
                        sess->app_next += (uint32_t)payload_len;
                        send_tcp_ack(sess);
                        set_srv_out(sess, 1);
                    }
                } else {
                    close_tcp_session(sess, 1);
                    return;
                }
            } else {
                unsigned char *dst = app_buf_reserve(sess, payload_len);
                if (dst) {
                    memcpy(dst, pkt + t + (size_t)tcp_hlen, payload_len);
                    sess->app_len += payload_len;
                    sess->app_next += (uint32_t)payload_len;
                    send_tcp_ack(sess);
                }
            }
        }
    }

    if (flags & 0x01) {                                    // FIN
        LOGI("tcp FIN from app (app_next=%u srv_next=%u)", sess->app_next, sess->srv_next);
        sess->app_next += 1;
        sess->app_fin = 1;
        send_tcp_ack(sess);
        if (sess->srv_fin_sent) { close_tcp_session(sess, 0); return; }
        if (sess->app_len == 0) {
            int sfd = atomic_load(&sess->srv_fd);
            if (sfd >= 0) shutdown(sfd, SHUT_WR);
        }
        if (sess->srv_eof) close_tcp_session(sess, 0);
    }

    if (sess->srv_len > 0) {                               // App ACK/開窗 → 續送
        flush_tcp_srv_buf(sess);
    }
}

// srv_fd 事件：server→App 資料 / EOF / 可寫
static void handle_tcp_event(tcp_sess_t *sess, uint32_t ev, time_t now) {
    if (sess->closed) return;
    sess->last_active = now;
    if (atomic_load(&sess->state) != 1) return;
    int sfd = atomic_load(&sess->srv_fd);
    if (sfd < 0) return;

    if (ev & EPOLLOUT) {
        if (sess->app_len > 0) flush_tcp_app_buf(sess);
        if (sess->closed) { tcp_session_destroy(sess); return; }
    }
    if (ev & (EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
        if (ev & (EPOLLERR | EPOLLHUP)) { close_tcp_session(sess, 1); return; }
        for (;;) {
            if (sess->srv_buf == NULL) sess->srv_buf = malloc(TCP_SRV_BUF_CAP);
            if (!sess->srv_buf) { close_tcp_session(sess, 1); return; }
            // 前綴已送出超過一半 → 搬移回收空間（分攤成本）
            if (sess->srv_off >= TCP_SRV_BUF_CAP / 2) {
                memmove(sess->srv_buf, sess->srv_buf + sess->srv_off, sess->srv_len);
                sess->srv_off = 0;
            }
            size_t used = sess->srv_off + sess->srv_len;
            if (used >= TCP_SRV_BUF_CAP) {
                // 緩衝滿：暫停讀取，等 App 消化後（flush 內）再續，靠 relay TCP 回壓
                if (sess->srv_len == 0) { close_tcp_session(sess, 1); return; }
                set_srv_in(sess, 0);
                break;
            }
            size_t want = TCP_SRV_BUF_CAP - used;
            if (want > TCP_READ_CHUNK) want = TCP_READ_CHUNK;
            ssize_t r = recv(sfd, sess->srv_buf + used, want, 0);
            if (r > 0) {
                sess->srv_len += (size_t)r;
                flush_tcp_srv_buf(sess);
                if (sess->closed) return;
            } else if (r == 0) {
                sess->srv_eof = 1;
                flush_tcp_srv_buf(sess);
                break;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                close_tcp_session(sess, 1);
                return;
            }
        }
    }
}

// ---------- TUN 讀取與主迴圈 ----------

static void handle_tun_packet(const unsigned char *pkt, size_t len) {
    if (len < 1) return;
    int ver = pkt[0] >> 4;
    if (ver == 4) {
        uint8_t proto;
        ip_addr_t saddr, daddr;
        int ihl;
        if (parse_ipv4(pkt, len, &proto, &saddr, &daddr, &ihl) < 0) return;
        if (proto == 17) {
            handle_tun_udp(pkt, len, (size_t)ihl, &saddr, &daddr);
        } else if (proto == 6) {
            handle_tun_tcp(pkt, len, (size_t)ihl, &saddr, &daddr);
        }
        return;
    }
    if (ver == 6) {
        uint8_t proto;
        ip_addr_t saddr, daddr;
        if (parse_ipv6(pkt, len, &proto, &saddr, &daddr) < 0) return;
        if (proto == 17) {
            handle_tun_udp(pkt, len, 40, &saddr, &daddr);
        } else if (proto == 6) {
            handle_tun_tcp(pkt, len, 40, &saddr, &daddr);
        }
        return;
    }
}

static void read_tun_packets(void) {
    unsigned char pkt[MAX_PACKET_SIZE];
    for (;;) {
        ssize_t n = read(g_tun_fd, pkt, sizeof pkt);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOGE("tun read error: %s", strerror(errno));
            break;
        }
        if (n == 0) break;
        handle_tun_packet(pkt, (size_t)n);
    }
}

static void *engine_loop(void *arg) {
    jni_attach_thread();
    struct epoll_event events[MAX_EVENTS];
    time_t last_gc = time(NULL);

    while (g_running) {
        int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 2000);
        time_t now = time(NULL);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == g_shutdown_pipe[0]) goto shutdown;
            if (events[i].data.fd == g_tun_fd) { read_tun_packets(); flush_all_tcp(); continue; }
            if (events[i].data.fd == g_kick_pipe[0]) {
                char d[64];
                while (read(g_kick_pipe[0], d, sizeof d) > 0) {}
                tcp_engine_sweep();
                flush_all_tcp();
                continue;
            }

            uintptr_t raw = (uintptr_t)events[i].data.ptr;
            int tag = (int)(raw & 3);
            if (tag == 3) {
                tcp_sess_t *ts = (tcp_sess_t *)(raw & ~(uintptr_t)3);
                if (!ts->closed) handle_tcp_event(ts, events[i].events, now);
                continue;
            }

            udp_sess_t *sess = (udp_sess_t *)(raw & ~(uintptr_t)1);
            if (sess->closed) continue;
            sess->last_active = now;

            uint32_t ev = events[i].events;
            int fatal = 0;
            if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) fatal = 1;
            int is_relay = (tag & 1) != 0;

            if (!fatal && !is_relay) {
                // 控制通道握手後不應有流量；任何事件（含 FIN）皆視為斷線
                fatal = 1;
            } else if (!fatal && is_relay) {
                if (sess->udp_tcp) {
                    // UDP-in-TCP：cfd 同時是控制與 relay
                    if (ev & EPOLLOUT) {
                        if (udp_tcp_flush(sess) < 0) fatal = 1;
                    }
                    if (!fatal && (ev & EPOLLIN)) {
                        if (udp_tcp_read(sess) < 0) fatal = 1;
                    }
                } else {
                    unsigned char buf[MAX_PACKET_SIZE + 64];
                    ssize_t r = recvfrom(sess->relay_fd, buf, sizeof buf, 0, NULL, NULL);
                    if (r > 0) {
                        handle_relay_udp(sess, buf, r);
                    } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        fatal = 1;
                    }
                }
            }

            if (fatal) {
                pthread_mutex_lock(&g_udp_hash_lock);
                if (!sess->closed) {
                    sess->closed = 1;
                    unsigned idx = udp_hash_idx(&sess->src_ip, sess->src_port);
                    udp_sess_t **pp = &g_udp_hash[idx];
                    while (*pp && *pp != sess) pp = &(*pp)->next;
                    if (*pp) *pp = sess->next;
                    pthread_mutex_unlock(&g_udp_hash_lock);
                    close_session_fds(sess);
                    udp_sess_free_bufs(sess);
                    free(sess);
                    atomic_fetch_sub(&g_udp_session_count, 1);
                } else {
                    pthread_mutex_unlock(&g_udp_hash_lock);
                }
            }
        }

        // 閒置 GC（每 5 秒）
        if (now - last_gc >= 5) {
            last_gc = now;
            udp_sess_t *garbage[MAX_EVENTS];
            int gc = 0;
            pthread_mutex_lock(&g_udp_hash_lock);
            for (int b = 0; b < UDP_HASH_BUCKETS; b++) {
                udp_sess_t **pp = &g_udp_hash[b];
                while (*pp) {
                    udp_sess_t *s = *pp;
                    // 垃圾桶滿了就跳過該 session，下一輪再收
                    if (now - s->last_active > UDP_IDLE_TIMEOUT_SEC && gc < MAX_EVENTS) {
                        s->closed = 1;
                        *pp = s->next;
                        garbage[gc++] = s;
                        continue;
                    }
                    pp = &s->next;
                }
            }
            pthread_mutex_unlock(&g_udp_hash_lock);
            for (int i = 0; i < gc; i++) {
                close_session_fds(garbage[i]);
                udp_sess_free_bufs(garbage[i]);
                free(garbage[i]);
                atomic_fetch_sub(&g_udp_session_count, 1);
            }

            // TCP 閒置 / 失敗會話回收
            tcp_sess_t *tcp_garbage[MAX_EVENTS];
            int tgc = 0;
            for (int b = 0; b < TCP_HASH_BUCKETS && tgc < MAX_EVENTS; b++) {
                for (tcp_sess_t *s = g_tcp_hash[b]; s && tgc < MAX_EVENTS; s = s->next) {
                    int idle = !s->closed && atomic_load(&s->state) == 1 &&
                               now - s->last_active > TCP_IDLE_TIMEOUT_SEC;
                    if (s->closed || atomic_load(&s->handshake_failed) || idle) {
                        s->closed = 1;
                        tcp_garbage[tgc++] = s;
                    }
                }
            }
            for (int i = 0; i < tgc; i++) {
                if (!atomic_load(&tcp_garbage[i]->handshake_failed)) send_session_rst(tcp_garbage[i]);
                tcp_session_destroy(tcp_garbage[i]);
            }
        }
    }

shutdown:
    // 先關 TUN：VPN 立刻拆除，網路馬上還原（fd 由 native 全權關閉）
    if (g_tun_fd >= 0) { close(g_tun_fd); g_tun_fd = -1; }

    // 等待 handshake 線程結束，避免釋放仍在使用的 session（最多等 5 秒）
    {
        int waited_ms = 0;
        while (atomic_load(&g_handshake_inflight) > 0 && waited_ms < 5000) {
            usleep(100000);
            waited_ms += 100;
        }
    }

    // 收集並關閉所有 session
    udp_sess_t *to_close = NULL;
    pthread_mutex_lock(&g_udp_hash_lock);
    for (int b = 0; b < UDP_HASH_BUCKETS; b++) {
        udp_sess_t *s = g_udp_hash[b];
        g_udp_hash[b] = NULL;
        while (s) { udp_sess_t *n = s->next; s->next = to_close; to_close = s; s = n; }
    }
    pthread_mutex_unlock(&g_udp_hash_lock);
    while (to_close) {
        udp_sess_t *n = to_close->next;
        close_session_fds(to_close);
        udp_sess_free_bufs(to_close);
        free(to_close);
        to_close = n;
    }

    // 關閉所有 TCP session（thread 已 join，無並發）
    tcp_sess_t *tc = NULL;
    for (int b = 0; b < TCP_HASH_BUCKETS; b++) {
        tcp_sess_t *s = g_tcp_hash[b];
        g_tcp_hash[b] = NULL;
        while (s) { tcp_sess_t *n = s->next; s->next = tc; tc = s; s = n; }
    }
    while (tc) {
        tcp_sess_t *n = tc->next;
        tc->closed = 1;
        tcp_session_destroy(tc);
        tc = n;
    }

    if (g_epoll_fd >= 0) { close(g_epoll_fd); g_epoll_fd = -1; }
    jni_detach_thread();
    return NULL;
}

// ---------- 對外介面 ----------

int tun_socks_start(int tun_fd, const char *host, int port, const char *user, const char *pass, int udp_in_tcp) {
    if (g_running) return -1;

    g_tun_fd = tun_fd;
    strncpy(g_srv_host, host, sizeof(g_srv_host) - 1);
    g_srv_host[sizeof(g_srv_host) - 1] = '\0';
    g_srv_port = port;
    g_auth_enabled = (user && user[0]) || (pass && pass[0]);
    strncpy(g_auth_user, user ? user : "", sizeof(g_auth_user) - 1);
    strncpy(g_auth_pass, pass ? pass : "", sizeof(g_auth_pass) - 1);
    g_udp_in_tcp = udp_in_tcp ? 1 : 0;

    set_nonblocking(g_tun_fd);

    if (pipe(g_shutdown_pipe) < 0) return -1;
    set_nonblocking(g_shutdown_pipe[0]);
    set_nonblocking(g_shutdown_pipe[1]);

    if (pipe(g_kick_pipe) < 0) {
        close(g_shutdown_pipe[0]); close(g_shutdown_pipe[1]);
        g_shutdown_pipe[0] = g_shutdown_pipe[1] = -1;
        return -1;
    }
    set_nonblocking(g_kick_pipe[0]);
    set_nonblocking(g_kick_pipe[1]);

    g_epoll_fd = epoll_create1(0);
    if (g_epoll_fd < 0) {
        close(g_shutdown_pipe[0]); close(g_shutdown_pipe[1]);
        close(g_kick_pipe[0]); close(g_kick_pipe[1]);
        g_shutdown_pipe[0] = g_shutdown_pipe[1] = -1;
        g_kick_pipe[0] = g_kick_pipe[1] = -1;
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.fd = g_shutdown_pipe[0];
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_shutdown_pipe[0], &ev);
    ev.events = EPOLLIN; ev.data.fd = g_kick_pipe[0];
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_kick_pipe[0], &ev);
    ev.events = EPOLLIN; ev.data.fd = g_tun_fd;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_tun_fd, &ev);

    g_running = 1;
    if (pthread_create(&g_engine_thread, NULL, engine_loop, NULL) != 0) {
        g_running = 0;
        if (g_epoll_fd >= 0) { close(g_epoll_fd); g_epoll_fd = -1; }
        if (g_shutdown_pipe[0] != -1) { close(g_shutdown_pipe[0]); g_shutdown_pipe[0] = -1; }
        if (g_shutdown_pipe[1] != -1) { close(g_shutdown_pipe[1]); g_shutdown_pipe[1] = -1; }
        if (g_kick_pipe[0] != -1) { close(g_kick_pipe[0]); g_kick_pipe[0] = -1; }
        if (g_kick_pipe[1] != -1) { close(g_kick_pipe[1]); g_kick_pipe[1] = -1; }
        if (g_tun_fd >= 0) { close(g_tun_fd); g_tun_fd = -1; }
        return -1;
    }
    LOGI("tunnel started: server=%s:%d auth=%d", g_srv_host, g_srv_port, g_auth_enabled);
    return 0;
}

void tun_socks_stop(void) {
    if (!g_running) return;
    g_running = 0;
    if (g_shutdown_pipe[1] != -1) {
        char stop_sig = 1;
        for (int k = 0; k < 10; k++) write(g_shutdown_pipe[1], &stop_sig, 1);
    }
    pthread_join(g_engine_thread, NULL);
    if (g_shutdown_pipe[0] != -1) { close(g_shutdown_pipe[0]); g_shutdown_pipe[0] = -1; }
    if (g_shutdown_pipe[1] != -1) { close(g_shutdown_pipe[1]); g_shutdown_pipe[1] = -1; }
    if (g_kick_pipe[0] != -1) { close(g_kick_pipe[0]); g_kick_pipe[0] = -1; }
    if (g_kick_pipe[1] != -1) { close(g_kick_pipe[1]); g_kick_pipe[1] = -1; }
    LOGI("tunnel stopped");
}
