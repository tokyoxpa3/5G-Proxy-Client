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

#define MAX_PACKET_SIZE 4096
#define MAX_EVENTS 256
#define TUN_MTU 1500
#define UDP_IDLE_TIMEOUT_SEC 120
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

static atomic_int g_udp_session_count = 0;
static atomic_int g_handshake_inflight = 0;

// ---------- TCP 會話（P2） ----------

#define TCP_HASH_BUCKETS 256
#define MAX_TCP_SESSIONS 512
#define TCP_APP_BUF_CAP (256 * 1024)
#define TCP_SRV_BUF_CAP (256 * 1024)
#define TCP_IDLE_TIMEOUT_SEC 300

typedef struct tcp_sess {
    uint32_t src_ip;        // App 端來源 IP（網路序）
    uint16_t src_port;      // App 端來源 Port（網路序）
    uint32_t dst_ip;        // 真實目標 IP（網路序）
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
    unsigned char *app_buf; size_t app_len, app_cap;  // App→server 待送
    unsigned char *srv_buf; size_t srv_len, srv_cap;  // server→App 待送（寫 TUN）
    time_t last_active;
    struct tcp_sess *next;  // hash chain
} tcp_sess_t;

static tcp_sess_t *g_tcp_hash[TCP_HASH_BUCKETS];
static atomic_int g_tcp_session_count = 0;
static int g_kick_pipe[2] = {-1, -1};
static int g_tun_want_out = 0;

static unsigned tcp_hash_idx(uint32_t ip, uint16_t port) {
    return ((ip >> 16) ^ ip ^ (uint32_t)port) % TCP_HASH_BUCKETS;
}

static uint32_t tcp_isn_counter = 0;
static uint32_t next_tcp_isn(void) {
    return ((uint32_t)time(NULL) ^ 0x5F3759DF) + (++tcp_isn_counter) * 2654435761u;
}

typedef struct udp_sess {
    uint32_t src_ip;        // App 端來源 IP（網路序）
    uint16_t src_port;      // App 端來源 Port（網路序）
    int control_fd;         // 通往伺服器的 TCP 控制連線（Java protect）
    int relay_fd;           // 伺服器 UDP relay 的 socket（Java protect）
    struct sockaddr_in relay_addr;
    int state;              // 0=handshake 中 1=就緒
    int closed;
    time_t last_active;
    unsigned char *pend_data;   // handshake 期間緩衝的首包（避免等 App 重傳）
    uint16_t pend_len;
    uint32_t pend_ip;           // 首包目標 IP（網路序）
    uint16_t pend_port;         // 首包目標 Port（網路序）
    struct udp_sess *next;  // hash chain
} udp_sess_t;

static udp_sess_t *g_udp_hash[UDP_HASH_BUCKETS];
static pthread_mutex_t g_udp_hash_lock = PTHREAD_MUTEX_INITIALIZER;

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static unsigned udp_hash_idx(uint32_t ip, uint16_t port) {
    return ((ip >> 16) ^ ip ^ (uint32_t)port) % UDP_HASH_BUCKETS;
}

// ---------- checksum ----------

static uint16_t checksum16(const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) { sum += ((uint16_t)data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += (uint16_t)data[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcpudp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto, const unsigned char *data, size_t len) {
    uint32_t sum = 0;
    unsigned char ph[12];
    memcpy(ph, &saddr, 4);
    memcpy(ph + 4, &daddr, 4);
    ph[8] = 0; ph[9] = proto;
    uint16_t l = htons((uint16_t)len);
    memcpy(ph + 10, &l, 2);
    for (int i = 0; i < 12; i += 2) sum += ((uint16_t)ph[i] << 8) | ph[i + 1];
    while (len > 1) { sum += ((uint16_t)data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += (uint16_t)data[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// ---------- TUN 封包處理 ----------

static int parse_ipv4(const unsigned char *pkt, size_t len, uint8_t *proto, uint32_t *saddr, uint32_t *daddr, int *ihl) {
    if (len < 20) return -1;
    if ((pkt[0] >> 4) != 4) return -1;
    *ihl = (pkt[0] & 0x0F) * 4;
    if (*ihl < 20 || (size_t)*ihl > len) return -1;
    *proto = pkt[9];
    memcpy(saddr, pkt + 12, 4);
    memcpy(daddr, pkt + 16, 4);
    return 0;
}

// 回覆 App 的 IP 封包（relay 回應 → TUN）
static void write_ipv4_udp_to_tun(udp_sess_t *sess, uint32_t remote_ip, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    if (plen > TUN_MTU - 28) { LOGE("relay UDP payload 過大 (%zu)，丟棄", plen); return; }
    unsigned char pkt[TUN_MTU];
    memset(pkt, 0, sizeof pkt);
    size_t total = 20 + 8 + plen;

    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2] = (total >> 8) & 0xFF; pkt[3] = total & 0xFF;
    pkt[4] = 0; pkt[5] = 0;
    pkt[6] = 0; pkt[7] = 0;
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    memcpy(pkt + 12, &remote_ip, 4);
    memcpy(pkt + 16, &sess->src_ip, 4);
    uint16_t csum = checksum16(pkt, 20);
    pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;

    size_t u = 20;
    memcpy(pkt + u, &remote_port, 2);
    memcpy(pkt + u + 2, &sess->src_port, 2);
    uint16_t ulen = (uint16_t)(8 + plen);
    pkt[u + 4] = ulen >> 8; pkt[u + 5] = ulen & 0xFF;
    pkt[u + 6] = 0; pkt[u + 7] = 0;
    memcpy(pkt + u + 8, payload, plen);
    uint16_t ucsum = tcpudp_checksum(remote_ip, sess->src_ip, 17, pkt + u, 8 + plen);
    pkt[u + 6] = ucsum >> 8; pkt[u + 7] = ucsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun failed: %s", strerror(errno));
}

// P1：TCP 一律回 RST|ACK，讓 App 立即收到連線失敗（Phase 2 才實作 TCP 隧道）
static void send_tcp_rst(uint32_t saddr, uint32_t daddr, const unsigned char *tcp, size_t tlen) {
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
    uint32_t ack = htonl(ack_host);                      // host 序 → 網路序

    unsigned char rst[TUN_MTU];
    memset(rst, 0, sizeof rst);
    size_t total = 20 + 20;
    rst[0] = 0x45;
    rst[2] = (total >> 8) & 0xFF; rst[3] = total & 0xFF;
    rst[8] = 64;
    rst[9] = 6; // TCP
    memcpy(rst + 12, &daddr, 4);
    memcpy(rst + 16, &saddr, 4);
    uint16_t csum = checksum16(rst, 20);
    rst[10] = csum >> 8; rst[11] = csum & 0xFF;

    size_t u = 20;
    memcpy(rst + u, &dport, 2);
    memcpy(rst + u + 2, &sport, 2);
    uint32_t zero = 0;
    memcpy(rst + u + 4, &zero, 4);
    memcpy(rst + u + 8, &ack, 4);
    rst[u + 12] = 0x50;
    rst[u + 13] = 0x14; // RST|ACK
    rst[u + 14] = 0; rst[u + 15] = 0;
    uint16_t tcsum = tcpudp_checksum(daddr, saddr, 6, rst + u, 20);
    rst[u + 16] = tcsum >> 8; rst[u + 17] = tcsum & 0xFF;

    ssize_t w = write(g_tun_fd, rst, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun RST failed: %s", strerror(errno));
}

// ---------- UDP 會話 ----------

static void forward_udp_to_server(udp_sess_t *sess, uint32_t dst_ip, uint16_t dst_port, const unsigned char *payload, size_t plen) {
    unsigned char frame[10 + MAX_PACKET_SIZE];
    if (plen > MAX_PACKET_SIZE) plen = MAX_PACKET_SIZE;
    memset(frame, 0, 4);
    frame[3] = 0x01; // ATYP IPv4
    memcpy(frame + 4, &dst_ip, 4);
    memcpy(frame + 8, &dst_port, 2);
    memcpy(frame + 10, payload, plen);
    ssize_t sent = sendto(sess->relay_fd, frame, 10 + plen, MSG_NOSIGNAL,
                          (struct sockaddr *)&sess->relay_addr, sizeof(sess->relay_addr));
    if (sent < 0) LOGE("relay sendto 失敗: %s", strerror(errno));
}

static void *udp_session_thread(void *arg);

static void handle_tun_udp(const unsigned char *pkt, size_t len, int ihl, uint32_t src_ip, uint32_t dst_ip) {
    size_t u = ihl;
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
        if (s->src_ip == src_ip && s->src_port == sport && !s->closed) { sess = s; break; }
    }
    if (!sess && atomic_load(&g_udp_session_count) < MAX_UDP_SESSIONS) {
        sess = calloc(1, sizeof(udp_sess_t));
        if (sess) {
            sess->src_ip = src_ip;
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
        char b1[16], b2[16];
        strcpy(b1, inet_ntoa(*(struct in_addr *)&src_ip));
        strcpy(b2, inet_ntoa(*(struct in_addr *)&dst_ip));
        LOGI("udp session 建立 src=%s:%d dst=%s:%d",
             b1, ntohs(sport), b2, ntohs(dport));
        // 首次封包：啟動 handshake 線程；同時緩衝此封包，完成後立即轉發（不用等 App 重傳）
        // 上限 1400：涵蓋 QUIC Initial（~1200B）避免被丟棄等重傳
        if (payload_len <= 1400) {
            sess->pend_data = malloc(payload_len);
            if (sess->pend_data) {
                memcpy(sess->pend_data, pkt + u + 8, payload_len);
                sess->pend_len = (uint16_t)payload_len;
                sess->pend_ip = dst_ip;
                sess->pend_port = dport;
            }
        }
        pthread_t t;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&t, &attr, udp_session_thread, sess);
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
                free(sess->pend_data);
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
                sess->pend_ip = dst_ip;
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
    if (send_all(cfd, req, 10) < 0) goto fail;
    if (recv_all(cfd, buf, 4) < 0) goto fail;
    if (buf[0] != 0x05 || buf[1] != 0x00) goto fail;
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

    if (!g_running) goto fail;
    set_nonblocking(cfd);
    set_nonblocking(rfd);
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
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR; ev.data.ptr = sess;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP; ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, rfd, &ev) < 0) { epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, cfd, NULL); goto fail; }

    // 立即轉發 handshake 期間緩衝的首包（不需等 App 重傳）
    pthread_mutex_lock(&g_udp_hash_lock);
    unsigned char *pd = sess->pend_data;
    size_t pl = sess->pend_len;
    uint32_t pip = sess->pend_ip;
    uint16_t pport = sess->pend_port;
    sess->pend_data = NULL;
    sess->pend_len = 0;
    pthread_mutex_unlock(&g_udp_hash_lock);
    if (pd) {
        forward_udp_to_server(sess, pip, pport, pd, pl);
        free(pd);
    }

    atomic_fetch_sub(&g_handshake_inflight, 1);
    LOGI("udp handshake 完成: relay=%s:%d", inet_ntoa(relay.sin_addr), ntohs(relay.sin_port));
    jni_detach_thread();
    return NULL;

fail:
    LOGI("udp handshake 失敗 (src=%s:%d)", inet_ntoa(*(struct in_addr *)&sess->src_ip), ntohs(sess->src_port));
    if (cfd >= 0) { release_java_socket(cfd); close(cfd); }
    if (rfd >= 0) { release_java_socket(rfd); close(rfd); }
    // 從 hash 移除並釋放（誰 unlink 誰 free，避免雙重釋放）
    pthread_mutex_lock(&g_udp_hash_lock);
    unsigned idx = udp_hash_idx(sess->src_ip, sess->src_port);
    udp_sess_t **pp = &g_udp_hash[idx];
    while (*pp && *pp != sess) pp = &(*pp)->next;
    if (*pp) {
        *pp = sess->next;
        sess->closed = 1;
        pthread_mutex_unlock(&g_udp_hash_lock);
        free(sess->pend_data);
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
    if (len < 10) return;
    int atyp = buf[3];
    if (atyp == 0x01) {
        uint32_t remote;
        uint16_t rport;
        memcpy(&remote, buf + 4, 4);
        memcpy(&rport, buf + 8, 2);
        size_t plen = (size_t)len - 10;
        write_ipv4_udp_to_tun(sess, remote, rport, buf + 10, plen);
    } else {
        // P1：domain / IPv6 回應丟棄
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
static ssize_t write_tcp_to_tun(uint32_t saddr, uint32_t daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const unsigned char *payload, size_t plen) {
    if (20 + 20 + plen > TUN_MTU) { LOGE("tcp 封包過大 (%zu)，丟棄", plen); return -1; }
    unsigned char pkt[TUN_MTU];
    memset(pkt, 0, sizeof pkt);
    size_t total = 20 + 20 + plen;

    pkt[0] = 0x45; pkt[1] = 0;
    pkt[2] = (total >> 8) & 0xFF; pkt[3] = total & 0xFF;
    pkt[4] = 0; pkt[5] = 0;
    pkt[6] = 0; pkt[7] = 0;
    pkt[8] = 64;
    pkt[9] = 6;
    memcpy(pkt + 12, &saddr, 4);
    memcpy(pkt + 16, &daddr, 4);
    uint16_t csum = checksum16(pkt, 20);
    pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;

    size_t u = 20;
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
    uint16_t tcsum = tcpudp_checksum(saddr, daddr, 6, pkt + u, 20 + plen);
    pkt[u + 16] = tcsum >> 8; pkt[u + 17] = tcsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun tcp failed: %s", strerror(errno));
    return w;
}

static void send_tcp_synack(tcp_sess_t *sess) {
    if (g_tun_fd < 0) return;
    unsigned char pkt[TUN_MTU];
    memset(pkt, 0, sizeof pkt);
    size_t total = 20 + 32;                     // 20 IP + 32 TCP（MSS + WS 選項）
    pkt[0] = 0x45; pkt[1] = 0;
    pkt[2] = (total >> 8) & 0xFF; pkt[3] = total & 0xFF;
    pkt[8] = 64;
    pkt[9] = 6;
    memcpy(pkt + 12, &sess->dst_ip, 4);
    memcpy(pkt + 16, &sess->src_ip, 4);
    uint16_t csum = checksum16(pkt, 20);
    pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;

    size_t u = 20;
    memcpy(pkt + u, &sess->dst_port, 2);
    memcpy(pkt + u + 2, &sess->src_port, 2);
    uint32_t isn_n = htonl(sess->srv_isn);
    uint32_t ack_n = htonl(sess->app_next);
    memcpy(pkt + u + 4, &isn_n, 4);
    memcpy(pkt + u + 8, &ack_n, 4);
    pkt[u + 12] = 0x80;            // 32-byte TCP header（含 MSS + WS）
    pkt[u + 13] = 0x12;            // SYN|ACK
    pkt[u + 14] = 0xFF; pkt[u + 15] = 0xFF;
    pkt[u + 20] = 0x02; pkt[u + 21] = 0x04;   // kind=2(MSS) len=4
    pkt[u + 22] = 0x05; pkt[u + 23] = 0xB4;   // MSS=1460
    pkt[u + 24] = 0x01; pkt[u + 25] = 0x01;   // NOP NOP
    pkt[u + 26] = 0x03; pkt[u + 27] = 0x03;   // kind=3(WS) len=3
    pkt[u + 28] = 0x0A;                        // shift=10（與 App 提議相同）
    uint16_t tcsum = tcpudp_checksum(sess->dst_ip, sess->src_ip, 6, pkt + u, 32);
    pkt[u + 16] = tcsum >> 8; pkt[u + 17] = tcsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0) LOGE("write tun SYN-ACK failed: %s (errno=%d)", strerror(errno), errno);
    else if (w != (ssize_t)total) LOGI("write tun SYN-ACK partial %zd/%zu", w, total);
}

static void send_tcp_ack(tcp_sess_t *sess) {
    write_tcp_to_tun(sess->dst_ip, sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x10, NULL, 0);
}

static void send_tcp_fin(tcp_sess_t *sess) {
    write_tcp_to_tun(sess->dst_ip, sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x11, NULL, 0);
}

static void send_session_rst(tcp_sess_t *sess) {
    write_tcp_to_tun(sess->dst_ip, sess->src_ip, sess->dst_port, sess->src_port,
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
    unsigned idx = tcp_hash_idx(sess->src_ip, sess->src_port);
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
        size_t chunk = sess->srv_len;
        if (chunk > TUN_MTU - 40) chunk = TUN_MTU - 40;
        // 流量控制：App 通告 window 已滿 → 暫停送出，等 App ACK 開窗
        if (sess->srv_next - sess->app_acked >= sess->app_win) break;
        ssize_t w = write_tcp_to_tun(sess->dst_ip, sess->src_ip, sess->dst_port, sess->src_port,
                                     sess->srv_next, sess->app_next, 0x18, sess->srv_buf, chunk);
        if (w < 0) { set_tun_epoll_out(1); return; }
        sess->srv_next += (uint32_t)chunk;
        memmove(sess->srv_buf, sess->srv_buf + chunk, sess->srv_len - chunk);
        sess->srv_len -= chunk;
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
        ssize_t n = send(fd, sess->app_buf, sess->app_len, MSG_NOSIGNAL);
        if (n > 0) {
            memmove(sess->app_buf, sess->app_buf + n, sess->app_len - (size_t)n);
            sess->app_len -= (size_t)n;
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

    unsigned char req[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    memcpy(req + 4, &sess->dst_ip, 4);
    memcpy(req + 8, &sess->dst_port, 2);
    if (net_send_all(sfd, req, 10) < 0) goto fail;
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
    LOGI("tcp connect 完成 -> %s:%d", inet_ntoa(*(struct in_addr *)&sess->dst_ip), ntohs(sess->dst_port));
    atomic_fetch_sub(&g_handshake_inflight, 1);
    jni_detach_thread();
    return NULL;

fail:
    LOGI("tcp connect 失敗 -> %s:%d", inet_ntoa(*(struct in_addr *)&sess->dst_ip), ntohs(sess->dst_port));
    if (sfd >= 0) { release_java_socket(sfd); close(sfd); }
    if (g_tun_fd >= 0) send_session_rst(sess);
    atomic_store(&sess->handshake_failed, 1);
    if (g_kick_pipe[1] >= 0) { char k = 1; write(g_kick_pipe[1], &k, 1); }
    atomic_fetch_sub(&g_handshake_inflight, 1);
    jni_detach_thread();
    return NULL;
}

// 處理來自 TUN 的 TCP 封包（P2 TCP 狀態機）
static void handle_tun_tcp(const unsigned char *pkt, size_t len, int ihl,
                           uint32_t src_ip, uint32_t dst_ip) {
    size_t t = (size_t)ihl;
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
        if (s->src_ip == src_ip && s->src_port == sport && !s->closed) { sess = s; break; }
    }

    if (!sess) {
        if (!(flags & 0x02) || (flags & 0x10)) return;   // 僅 SYN 可建立（SYN+ACK 忽略）
        if (atomic_load(&g_tcp_session_count) >= MAX_TCP_SESSIONS) {
            send_tcp_rst(src_ip, dst_ip, pkt + t, len - t);   // 滿載 → RST
            return;
        }
        sess = calloc(1, sizeof(tcp_sess_t));
        if (!sess) return;
        sess->src_ip = src_ip; sess->src_port = sport;
        sess->dst_ip = dst_ip; sess->dst_port = dport;
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

        char b1[16], b2[16];
        strcpy(b1, inet_ntoa(*(struct in_addr *)&src_ip));
        strcpy(b2, inet_ntoa(*(struct in_addr *)&dst_ip));
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
            handle_tun_tcp(pkt, len, ihl, src_ip, dst_ip);
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
        LOGI("tcp RST from app state=%d %s:%d", atomic_load(&sess->state),
             inet_ntoa(*(struct in_addr *)&src_ip), ntohs(sport));
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
            if (sess->app_buf == NULL) sess->app_buf = malloc(TCP_APP_BUF_CAP);
            if (sess->app_buf && sess->app_len + payload_len <= TCP_APP_BUF_CAP) {
                memcpy(sess->app_buf + sess->app_len, pkt + t + (size_t)tcp_hlen, payload_len);
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
                    if (sess->app_buf == NULL) sess->app_buf = malloc(TCP_APP_BUF_CAP);
                    if (sess->app_buf && payload_len - (size_t)n <= TCP_APP_BUF_CAP) {
                        memcpy(sess->app_buf, pkt + t + (size_t)tcp_hlen + n, payload_len - (size_t)n);
                        sess->app_len = payload_len - (size_t)n;
                        send_tcp_ack(sess);
                        set_srv_out(sess, 1);
                    }
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (sess->app_buf == NULL) sess->app_buf = malloc(TCP_APP_BUF_CAP);
                    if (sess->app_buf && payload_len <= TCP_APP_BUF_CAP) {
                        memcpy(sess->app_buf, pkt + t + (size_t)tcp_hlen, payload_len);
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
                if (sess->app_buf && sess->app_len + payload_len <= TCP_APP_BUF_CAP) {
                    memcpy(sess->app_buf + sess->app_len, pkt + t + (size_t)tcp_hlen, payload_len);
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
            unsigned char tmp[TUN_MTU];
            ssize_t r = recv(sfd, tmp, sizeof tmp, 0);
            if (r > 0) {
                if (sess->srv_buf == NULL) sess->srv_buf = malloc(TCP_SRV_BUF_CAP);
                if (!sess->srv_buf) { close_tcp_session(sess, 1); return; }
                if (sess->srv_len + (size_t)r > TCP_SRV_BUF_CAP) {
                    // 緩衝滿：暫停讀取，等 App 消化後（flush 內）再續，靠 relay TCP 回壓
                    if (sess->srv_len == 0) { close_tcp_session(sess, 1); return; }
                    set_srv_in(sess, 0);
                    break;
                }
                memcpy(sess->srv_buf + sess->srv_len, tmp, (size_t)r);
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
        uint32_t saddr, daddr;
        int ihl;
        if (parse_ipv4(pkt, len, &proto, &saddr, &daddr, &ihl) < 0) return;
        if (proto == 17) {
            handle_tun_udp(pkt, len, ihl, saddr, daddr);
        } else if (proto == 6) {
            handle_tun_tcp(pkt, len, ihl, saddr, daddr);
        }
        return;
    }
    // P1：IPv6 封包丟棄
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
                unsigned char buf[MAX_PACKET_SIZE + 64];
                ssize_t r = recvfrom(sess->relay_fd, buf, sizeof buf, 0, NULL, NULL);
                if (r > 0) {
                    handle_relay_udp(sess, buf, r);
                } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fatal = 1;
                }
            }

            if (fatal) {
                pthread_mutex_lock(&g_udp_hash_lock);
                if (!sess->closed) {
                    sess->closed = 1;
                    unsigned idx = udp_hash_idx(sess->src_ip, sess->src_port);
                    udp_sess_t **pp = &g_udp_hash[idx];
                    while (*pp && *pp != sess) pp = &(*pp)->next;
                    if (*pp) *pp = sess->next;
                    pthread_mutex_unlock(&g_udp_hash_lock);
                    close_session_fds(sess);
                    free(sess->pend_data);
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
                free(garbage[i]->pend_data);
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

int tun_socks_start(int tun_fd, const char *host, int port, const char *user, const char *pass) {
    if (g_running) return -1;

    g_tun_fd = tun_fd;
    strncpy(g_srv_host, host, sizeof(g_srv_host) - 1);
    g_srv_host[sizeof(g_srv_host) - 1] = '\0';
    g_srv_port = port;
    g_auth_enabled = (user && user[0]) || (pass && pass[0]);
    strncpy(g_auth_user, user ? user : "", sizeof(g_auth_user) - 1);
    strncpy(g_auth_pass, pass ? pass : "", sizeof(g_auth_pass) - 1);

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
