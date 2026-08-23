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
#include <strings.h>
#include <android/log.h>

#include "jni_bridge.h"
#include "checksum.h"

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
static int g_remote_dns = 0;    // 1 = Remote DNS（fakedns）：攔截 DNS、以網域撥號

static atomic_int g_udp_session_count = 0;
static atomic_int g_handshake_inflight = 0;

// 流量統計（payload bytes 累計，供通知列即時顯示）
static atomic_ullong g_bytes_to_server = 0;    // App → SOCKS5 伺服器
static atomic_ullong g_bytes_from_server = 0;  // SOCKS5 伺服器 → App

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
#define TCP_APP_BUF_CAP (4 * 1024 * 1024)
#define TCP_SRV_BUF_CAP (1024 * 1024)
#define TCP_IDLE_TIMEOUT_SEC 300
#define TCP_READ_CHUNK (64 * 1024)

typedef struct tcp_sess {
    ip_addr_t src_ip;       // App 端來源 IP（v4/v6）
    uint16_t src_port;      // App 端來源 Port（網路序）
    ip_addr_t dst_ip;       // 真實目標 IP（v4/v6）
    uint16_t dst_port;      // 真實目標 Port（網路序）
    char dst_domain[256];   // Remote DNS：fake IP 對應的網域（若非空則以 ATYP=0x03 撥號）
    atomic_int srv_fd;      // SOCKS5 CONNECT 的 stream socket（Java protect）
    atomic_int state;       // 0=CONNECT 中 1=就緒
    atomic_int handshake_failed;
    atomic_int thread_done; // 背景 connect 線程結束標記（釋放前檢查）
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
    struct sockaddr_storage relay_addr;   // 伺服器 UDP relay 位址（v4/v6）
    socklen_t relay_len;                  // relay_addr 有效長度（0 = 未設定）
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
    atomic_int thread_done;     // handshake 線程結束標記（釋放前檢查）
    struct udp_sess *next;  // hash chain
} udp_sess_t;

static udp_sess_t *g_udp_hash[UDP_HASH_BUCKETS];
static pthread_mutex_t g_udp_hash_lock = PTHREAD_MUTEX_INITIALIZER;

static udp_sess_t *g_udp_graveyard = NULL;   // 線程未結束前暫存待釋放 session（受 g_udp_hash_lock 保護）
static tcp_sess_t *g_tcp_graveyard = NULL;   // 同上（僅 engine 單執行緒存取）

static void udp_sess_free_bufs(udp_sess_t *sess);

// ---------- Remote DNS（fakedns） ----------
// 攔截 App 的 DNS 查詢（UDP/53），回覆保留網段的 fake IP；
// 之後 App 對 fake IP 的連線（TCP/UDP）改以網域名稱（ATYP=0x03）向 SOCKS5 伺服器撥號，
// 由伺服器端解析——即使 SOCKS5 伺服器不支援 UDP relay 也能解析網域。
// 引擎單執行緒與 UDP handshake 線程皆會存取，以 mutex 保護。

#define FAKE_DNS_ENTRIES 512
#define FAKE_DNS_REPLY_TTL_SEC 60
#define FAKE_DNS_IDLE_SEC 300
#define FAKE_IP_BASE 0xC6120000u   // 198.18.0.0（RFC 2544 保留網段）

typedef struct {
    uint32_t fake_ip;            // 網路序（v4 fake）
    unsigned char fake_ip6[16];  // 對應的 fake IPv6（供 AAAA 回覆）
    char domain[256];
    time_t last_used;
    int in_use;
} fake_dns_entry_t;

// 由 entry 索引產生穩定的 fake IPv6：fd00::5e<idx+1>（16-bit 索引放最後兩 byte，
// byte13=0x5E 標記避免撞上 TUN 本機位址 fd00::2）
static void fake_dns_build_ip6(int idx, unsigned char out[16]) {
    memset(out, 0, 16);
    out[0] = 0xFD;
    out[13] = 0x5E;
    out[14] = (unsigned char)(((idx + 1) >> 8) & 0xFF);
    out[15] = (unsigned char)((idx + 1) & 0xFF);
}

static fake_dns_entry_t g_fake_dns[FAKE_DNS_ENTRIES];
static unsigned g_fake_dns_next = 0;
static pthread_mutex_t g_fake_dns_lock = PTHREAD_MUTEX_INITIALIZER;

// 取得 fake IP 對應的 32-bit 鍵（非 v4 回傳 0）
static uint32_t fake_dns_key(const ip_addr_t *ip) {
    if (ip->family != AF_INET) return 0;
    uint32_t k;
    memcpy(&k, ip->ip, 4);
    return k;
}

// 分配（或重用）網域的 fake IP；回傳網路序 IP（0=失敗），ip6_out 帶出對應 fake IPv6
static uint32_t fake_dns_alloc(const char *domain, unsigned char ip6_out[16]) {
    time_t now = time(NULL);
    uint32_t fake = 0;
    pthread_mutex_lock(&g_fake_dns_lock);
    // 1. 同網域已有映射 → 直接回傳（刷新 last_used）
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &g_fake_dns[i];
        if (e->in_use && strcmp(e->domain, domain) == 0) {
            e->last_used = now;
            fake = e->fake_ip;
            if (ip6_out) memcpy(ip6_out, e->fake_ip6, 16);
            goto out;
        }
    }
    // 2. 依序尋找空位或已閒置逾時的項目
    for (int round = 0; round < FAKE_DNS_ENTRIES; round++) {
        unsigned idx = (g_fake_dns_next + (unsigned)round) % FAKE_DNS_ENTRIES;
        fake_dns_entry_t *e = &g_fake_dns[idx];
        if (!e->in_use || now - e->last_used > FAKE_DNS_IDLE_SEC) {
            e->in_use = 1;
            e->fake_ip = htonl(FAKE_IP_BASE + idx + 1);
            strncpy(e->domain, domain, sizeof(e->domain) - 1);
            e->domain[sizeof(e->domain) - 1] = '\0';
            e->last_used = now;
            g_fake_dns_next = (idx + 1) % FAKE_DNS_ENTRIES;
            fake = e->fake_ip;
            fake_dns_build_ip6((int)idx, e->fake_ip6);
            if (ip6_out) memcpy(ip6_out, e->fake_ip6, 16);
            goto out;
        }
    }
    // 3. 全滿且皆未逾時 → LRU 淘汰最舊者
    {
        unsigned oldest = 0;
        for (int i = 1; i < FAKE_DNS_ENTRIES; i++)
            if (g_fake_dns[i].last_used < g_fake_dns[oldest].last_used) oldest = (unsigned)i;
        fake_dns_entry_t *e = &g_fake_dns[oldest];
        e->in_use = 1;
        e->fake_ip = htonl(FAKE_IP_BASE + oldest + 1);
        strncpy(e->domain, domain, sizeof(e->domain) - 1);
        e->domain[sizeof(e->domain) - 1] = '\0';
        e->last_used = now;
        g_fake_dns_next = (oldest + 1) % FAKE_DNS_ENTRIES;
        fake = e->fake_ip;
        fake_dns_build_ip6((int)oldest, e->fake_ip6);
        if (ip6_out) memcpy(ip6_out, e->fake_ip6, 16);
    }
out:
    pthread_mutex_unlock(&g_fake_dns_lock);
    return fake;
}

// 查詢 fake IP → 網域；回傳 1=找到（domain 帶出），0=無映射
static int fake_dns_lookup(uint32_t fake_ip, char *domain, size_t dn) {
    pthread_mutex_lock(&g_fake_dns_lock);
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &g_fake_dns[i];
        if (e->in_use && e->fake_ip == fake_ip) {
            e->last_used = time(NULL);
            strncpy(domain, e->domain, dn - 1);
            domain[dn - 1] = '\0';
            pthread_mutex_unlock(&g_fake_dns_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_fake_dns_lock);
    return 0;
}

// 依網域找對應的 fake IP（大小寫不敏感；找不到回傳 0）
static uint32_t fake_dns_find_domain(const char *domain) {
    uint32_t fake = 0;
    pthread_mutex_lock(&g_fake_dns_lock);
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &g_fake_dns[i];
        if (e->in_use && strcasecmp(e->domain, domain) == 0) {
            e->last_used = time(NULL);
            fake = e->fake_ip;
            break;
        }
    }
    pthread_mutex_unlock(&g_fake_dns_lock);
    return fake;
}

// 查詢 fake IPv6 → 網域；回傳 1=找到（domain 帶出），0=無映射
static int fake_dns_lookup6(const unsigned char ip6[16], char *domain, size_t dn) {
    pthread_mutex_lock(&g_fake_dns_lock);
    for (int i = 0; i < FAKE_DNS_ENTRIES; i++) {
        fake_dns_entry_t *e = &g_fake_dns[i];
        if (e->in_use && memcmp(e->fake_ip6, ip6, 16) == 0) {
            e->last_used = time(NULL);
            strncpy(domain, e->domain, dn - 1);
            domain[dn - 1] = '\0';
            pthread_mutex_unlock(&g_fake_dns_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_fake_dns_lock);
    return 0;
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static unsigned udp_hash_idx(const ip_addr_t *ip, uint16_t port) {
    return (ip_hash32(ip) ^ (uint32_t)port) % UDP_HASH_BUCKETS;
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

// 沿 IPv6 extension header 鏈走到真正的 L4 協定，輸出傳輸層偏移 l4off。
// 支援 Hop-by-Hop(0)/Routing(43)/Destination(60)/AH(51)；Fragment(44) 需重組，直接丟棄。
static int parse_ipv6(const unsigned char *pkt, size_t len, uint8_t *proto, ip_addr_t *saddr, ip_addr_t *daddr, size_t *l4off) {
    if (len < 40) return -1;
    if ((pkt[0] >> 4) != 6) return -1;
    saddr->family = AF_INET6; memcpy(saddr->ip, pkt + 8, 16);
    daddr->family = AF_INET6; memcpy(daddr->ip, pkt + 24, 16);

    size_t off = 40;
    uint8_t nh = pkt[6];
    for (int hops = 0; hops < 8; hops++) {
        if (nh == 17 || nh == 6 || nh == 58) { *proto = nh; *l4off = off; return 0; }
        if (nh == 44) return -1;                   // Fragment：無法重組，直接丟棄
        if (off + 8 > len) return -1;
        size_t hlen;
        if (nh == 51)                              hlen = ((size_t)pkt[off + 1] + 2) * 4;   // AH
        else if (nh == 0 || nh == 43 || nh == 60)  hlen = ((size_t)pkt[off + 1] + 1) * 8;   // Hop-by-Hop / Routing / Destination
        else return -1;                                                                      // 不認識的 ext header
        if (hlen < 8 || off + hlen > len) return -1;
        nh = pkt[off];
        off += hlen;
    }
    return -1;                                      // 超過層數上限
}

// 回覆 App 的 IP 封包（relay 回應 → TUN）；_ex 版本以顯式位址取代 session
static void write_ipv4_udp_to_tun_ex(const ip_addr_t *app_ip, uint16_t app_port,
                                     const ip_addr_t *remote, uint16_t remote_port,
                                     const unsigned char *payload, size_t plen) {
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
    memcpy(pkt + 16, app_ip->ip, 4);
    pkt[10] = 0; pkt[11] = 0;   // checksum 欄位先歸零
    uint16_t csum = checksum16(pkt, 20);
    pkt[10] = csum >> 8; pkt[11] = csum & 0xFF;

    size_t u = 20;
    memcpy(pkt + u, &remote_port, 2);
    memcpy(pkt + u + 2, &app_port, 2);
    uint16_t ulen = (uint16_t)(8 + plen);
    pkt[u + 4] = ulen >> 8; pkt[u + 5] = ulen & 0xFF;
    pkt[u + 6] = 0; pkt[u + 7] = 0;
    memcpy(pkt + u + 8, payload, plen);
    uint16_t ucsum = tcpudp_checksum4(remote->ip, app_ip->ip, 17, pkt + u, 8 + plen);
    pkt[u + 6] = ucsum >> 8; pkt[u + 7] = ucsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun failed: %s", strerror(errno));
}

static void write_ipv6_udp_to_tun_ex(const ip_addr_t *app_ip, uint16_t app_port,
                                     const ip_addr_t *remote, uint16_t remote_port,
                                     const unsigned char *payload, size_t plen) {
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
    memcpy(pkt + 24, app_ip->ip, 16);

    size_t u = 40;
    memcpy(pkt + u, &remote_port, 2);
    memcpy(pkt + u + 2, &app_port, 2);
    uint16_t ulen = (uint16_t)(8 + plen);
    pkt[u + 4] = ulen >> 8; pkt[u + 5] = ulen & 0xFF;
    pkt[u + 6] = 0; pkt[u + 7] = 0;
    memcpy(pkt + u + 8, payload, plen);
    uint16_t ucsum = tcpudp_checksum6(remote->ip, app_ip->ip, 17, pkt + u, 8 + plen);
    pkt[u + 6] = ucsum >> 8; pkt[u + 7] = ucsum & 0xFF;

    ssize_t w = write(g_tun_fd, pkt, total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun failed: %s", strerror(errno));
}

static void write_ipv4_udp_to_tun(udp_sess_t *sess, const ip_addr_t *remote, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    write_ipv4_udp_to_tun_ex(&sess->src_ip, sess->src_port, remote, remote_port, payload, plen);
}

static void write_ipv6_udp_to_tun(udp_sess_t *sess, const ip_addr_t *remote, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    write_ipv6_udp_to_tun_ex(&sess->src_ip, sess->src_port, remote, remote_port, payload, plen);
}

static void write_udp_to_tun(udp_sess_t *sess, const ip_addr_t *remote, uint16_t remote_port, const unsigned char *payload, size_t plen) {
    if (remote->family != sess->src_ip.family) { LOGE("relay 回應 family 不符，丟棄"); return; }
    atomic_fetch_add(&g_bytes_from_server, (unsigned long long)plen);
    if (sess->src_ip.family == AF_INET6) write_ipv6_udp_to_tun(sess, remote, remote_port, payload, plen);
    else write_ipv4_udp_to_tun(sess, remote, remote_port, payload, plen);
}

// 以「DNS 伺服器 → App」方向寫出 UDP 封包（fakedns 合成回覆用）
static void write_udp_reply_to_tun(const ip_addr_t *app_ip, uint16_t app_port,
                                   const ip_addr_t *dns_ip, uint16_t dns_port,
                                   const unsigned char *payload, size_t plen) {
    if (dns_ip->family != app_ip->family) { LOGE("dns 回覆 family 不符，丟棄"); return; }
    if (app_ip->family == AF_INET6)
        write_ipv6_udp_to_tun_ex(app_ip, app_port, dns_ip, dns_port, payload, plen);
    else
        write_ipv4_udp_to_tun_ex(app_ip, app_port, dns_ip, dns_port, payload, plen);
}

// P1：TCP 一律回 RST|ACK，讓 App 立即收到連線失敗（Phase 2 才實作 TCP 隧道）
static ssize_t write_tcp_to_tun(const ip_addr_t *saddr, const ip_addr_t *daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const unsigned char *payload, size_t plen,
                                uint16_t win);

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
    write_tcp_to_tun(dst, src, dport, sport, 0, ack_host, 0x14, NULL, 0, 0);
}

// ---------- UDP 會話 ----------

static void handle_relay_udp(udp_sess_t *sess, const unsigned char *buf, ssize_t len);

// ---------- handshake 執行緒池 ----------
// 以固定 worker 數取代 per-session detached thread，避免連線尖峰時大量建立執行緒。
// submit 遞增 g_handshake_inflight、job 結尾遞減；關閉時確定性排空並 join worker。
#define HS_POOL_WORKERS 16

typedef struct hs_job {
    void *(*fn)(void *);
    void *arg;
    struct hs_job *next;
} hs_job_t;

static pthread_t g_hs_workers[HS_POOL_WORKERS];
static int g_hs_worker_count = 0;
static pthread_mutex_t g_hs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hs_cond = PTHREAD_COND_INITIALIZER;
static hs_job_t *g_hs_head = NULL;
static hs_job_t *g_hs_tail = NULL;
static int g_hs_running = 0;

static void *hs_worker(void *arg) {
    (void)arg;
    jni_attach_thread();
    for (;;) {
        pthread_mutex_lock(&g_hs_lock);
        while (g_hs_running && !g_hs_head)
            pthread_cond_wait(&g_hs_cond, &g_hs_lock);
        if (!g_hs_running && !g_hs_head) {
            pthread_mutex_unlock(&g_hs_lock);
            break;
        }
        hs_job_t *job = g_hs_head;
        g_hs_head = job->next;
        if (!g_hs_head) g_hs_tail = NULL;
        pthread_mutex_unlock(&g_hs_lock);
        job->fn(job->arg);
        free(job);
    }
    jni_detach_thread();
    return NULL;
}

static void hs_pool_start(void) {
    if (g_hs_running) return;
    g_hs_running = 1;
    g_hs_worker_count = 0;
    for (int i = 0; i < HS_POOL_WORKERS; i++) {
        if (pthread_create(&g_hs_workers[g_hs_worker_count], NULL, hs_worker, NULL) == 0)
            g_hs_worker_count++;
    }
}

static void hs_pool_stop(void) {
    if (!g_hs_running) return;
    pthread_mutex_lock(&g_hs_lock);
    g_hs_running = 0;
    pthread_cond_broadcast(&g_hs_cond);
    pthread_mutex_unlock(&g_hs_lock);
    for (int i = 0; i < g_hs_worker_count; i++)
        pthread_join(g_hs_workers[i], NULL);
    g_hs_worker_count = 0;
}

static int hs_submit(void *(*fn)(void *), void *arg) {
    hs_job_t *job = malloc(sizeof(*job));
    if (!job) return -1;
    job->fn = fn;
    job->arg = arg;
    job->next = NULL;
    atomic_fetch_add(&g_handshake_inflight, 1);
    pthread_mutex_lock(&g_hs_lock);
    if (!g_hs_running) {
        pthread_mutex_unlock(&g_hs_lock);
        atomic_fetch_sub(&g_handshake_inflight, 1);
        free(job);
        return -1;
    }
    if (g_hs_tail) g_hs_tail->next = job;
    else g_hs_head = job;
    g_hs_tail = job;
    pthread_cond_signal(&g_hs_cond);
    pthread_mutex_unlock(&g_hs_lock);
    return 0;
}

// UDP-in-TCP：將一整個 frame（長度欄 + SOCKS5 datagram）加入送出佇列。
// 只在「未 arm EPOLLOUT」時才觸發第一次，避免重複 MOD。
static void udp_tcp_append(udp_sess_t *sess, const unsigned char *frame, size_t flen) {
    if (sess->tx_len == 0) sess->tx_off = 0;
    if (sess->tx_off + sess->tx_len + flen > sess->tx_cap) {
        // 尾部空間不足：先壓縮（tx_off>0 時），仍不足才丟棄
        if (sess->tx_off > 0 && sess->tx_len + flen <= sess->tx_cap) {
            memmove(sess->tx_buf, sess->tx_buf + sess->tx_off, sess->tx_len);
            sess->tx_off = 0;
        } else {
            LOGE("udp-in-tcp tx 佇列滿，丟棄 datagram");
            return;
        }
    }
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
    unsigned char frame[2 + 262 + MAX_PACKET_SIZE];
    if (plen > MAX_PACKET_SIZE) plen = MAX_PACKET_SIZE;
    size_t off = 2;
    memset(frame + 2, 0, 4);
    char dom[256];
    int use_domain = 0;
    if (g_remote_dns && dst->family == AF_INET) {
        uint32_t k;
        memcpy(&k, dst->ip, 4);
        use_domain = fake_dns_lookup(k, dom, sizeof dom);
    } else if (g_remote_dns && dst->family == AF_INET6) {
        // fake IPv6 → 以網域撥號（Remote DNS 的 AAAA 路徑）
        use_domain = fake_dns_lookup6(dst->ip, dom, sizeof dom);
    }
    if (use_domain) {
        size_t dl = strlen(dom);
        frame[2 + 3] = 0x03;                // ATYP domain
        frame[2 + 4] = (unsigned char)dl;   // LEN
        memcpy(frame + 2 + 5, dom, dl);
        memcpy(frame + 2 + 5 + dl, &dst_port, 2);
        off = 2 + 7 + dl;
    } else if (dst->family == AF_INET6) {
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
    atomic_fetch_add(&g_bytes_to_server, (unsigned long long)plen);
    int datalen = (int)(off - 2 + plen);
    frame[0] = (unsigned char)(datalen >> 8);
    frame[1] = (unsigned char)(datalen & 0xFF);

    if (sess->udp_tcp) {
        // UDP-in-TCP：frame 直接進控制連線的送出佇列
        udp_tcp_append(sess, frame, 2 + (size_t)datalen);
    } else {
        ssize_t sent = sendto(sess->relay_fd, frame + 2, (size_t)datalen, MSG_NOSIGNAL,
                              (struct sockaddr *)&sess->relay_addr, sess->relay_len);
        if (sent < 0) LOGE("relay sendto 失敗: %s", strerror(errno));
    }
}

static void *udp_session_thread(void *arg);

// 攔截 App 的 DNS 查詢（A/AAAA、單一 question、IN class）：
// 分配 fake IP 並合成回覆寫回 TUN；回傳 1=已處理，0=放行走 relay。
static int dns_try_intercept(const unsigned char *q, size_t qlen,
                             const ip_addr_t *src_ip, const ip_addr_t *dst_ip,
                             uint16_t sport, uint16_t dport) {
    if (qlen < 17) return 0;
    uint16_t flags = (uint16_t)((q[2] << 8) | q[3]);
    if (flags & 0x8000) return 0;                 // 不是查詢
    if ((flags & 0x7800) != 0) return 0;          // 僅支援 QUERY (opcode=0)
    if (((q[4] << 8) | q[5]) != 1) return 0;      // 僅單一 question

    size_t off = 12;
    char name[256];
    size_t nlen = 0;
    for (;;) {
        if (off >= qlen) return 0;
        uint8_t l = q[off];
        if (l == 0) { off++; break; }
        if ((l & 0xC0) == 0xC0) return 0;         // 壓縮指標不處理
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
    if (qclass != 1) return 0;                    // 僅 IN
    if (qtype != 1 && qtype != 28 && qtype != 65) return 0;   // 僅 A / AAAA / HTTPS(65)
    name[nlen] = '\0';
    size_t qend = off + 4;

    unsigned char fake6[16];
    uint32_t fake = fake_dns_alloc(name, fake6);
    if (!fake) return 0;

    unsigned char r[512];
    size_t rl = 0;
    memcpy(r, q, 12);
    r[2] = (unsigned char)(0x80 | (q[2] & 0x01));  // QR=1，保留 RD
    r[3] = 0x80;                                   // RA
    r[6] = 0; r[7] = 0;                            // ANCOUNT（下面視 qtype 設定）
    r[8] = 0; r[9] = 0;                            // NSCOUNT
    r[10] = 0; r[11] = 0;                          // ARCOUNT
    rl = 12;
    memcpy(r + rl, q + 12, qend - 12);             // 原 question
    rl += qend - 12;
    if (qtype == 1) {
        r[6] = 0; r[7] = 1;                        // ANCOUNT = 1
        r[rl++] = 0xC0; r[rl++] = 0x0C;            // 名稱指標 → question
        r[rl++] = 0; r[rl++] = 1;                  // TYPE A
        r[rl++] = 0; r[rl++] = 1;                  // CLASS IN
        uint32_t ttl = htonl(FAKE_DNS_REPLY_TTL_SEC);
        memcpy(r + rl, &ttl, 4); rl += 4;
        r[rl++] = 0; r[rl++] = 4;                  // RDLENGTH
        memcpy(r + rl, &fake, 4); rl += 4;
    } else if (qtype == 28) {
        // AAAA：回 fake IPv6（fd00::/8 僅在 TUN 內路由），雙棧 App 可直接以 v6 連線
        r[6] = 0; r[7] = 1;                        // ANCOUNT = 1
        r[rl++] = 0xC0; r[rl++] = 0x0C;            // 名稱指標 → question
        r[rl++] = 0; r[rl++] = 28;                 // TYPE AAAA
        r[rl++] = 0; r[rl++] = 1;                  // CLASS IN
        uint32_t ttl = htonl(FAKE_DNS_REPLY_TTL_SEC);
        memcpy(r + rl, &ttl, 4); rl += 4;
        r[rl++] = 0; r[rl++] = 16;                 // RDLENGTH
        memcpy(r + rl, fake6, 16); rl += 16;
    }
    // HTTPS（qtype=65）：回 NOERROR 空答 → App 自動退回 A/AAAA 查詢
    write_udp_reply_to_tun(src_ip, sport, dst_ip, dport, r, rl);
    return 1;
}

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

    // Remote DNS：攔截 UDP/53 查詢，直接回覆 fake IP（不建立 relay 會話）
    if (g_remote_dns && ntohs(dport) == 53) {
        if (dns_try_intercept(pkt + u + 8, payload_len, src_ip, dst_ip, sport, dport)) return;
    }

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
        if (hs_submit(udp_session_thread, sess) != 0) {
            // 提交失敗：移除會話，避免永久卡在 connecting
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
    if (!sess->closed) forward_udp_to_server(sess, dst_ip, dport, pkt + u + 8, payload_len);
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
    udp_sess_t *sess = (udp_sess_t *)arg;
    unsigned char buf[320];
    int cfd = -1, rfd = -1;
    struct sockaddr_storage relay = {0};
    socklen_t relay_len = 0;
    int network_fail = 1;   // 網路層失敗旗標（同 tcp_connect_thread）

    // 1. TCP 控制連線（Java 已 connect + protect）
    cfd = request_java_socket(g_srv_host, g_srv_port, 0);
    if (cfd < 0) goto fail;
    if (!g_running) { network_fail = 0; goto fail; }
    struct timeval tv = {HANDSHAKE_TIMEOUT_SEC, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    // 2. SOCKS5 握手
    buf[0] = 0x05; buf[1] = 0x01; buf[2] = g_auth_enabled ? 0x02 : 0x00;
    if (send_all(cfd, buf, 3) < 0) goto fail;
    if (recv_all(cfd, buf, 2) < 0) goto fail;
    if (buf[0] != 0x05) { network_fail = 0; goto fail; }   // 對方不是 SOCKS5
    if (buf[1] == 0x02) {
        // RFC 1929
        size_t ul = strlen(g_auth_user), pl = strlen(g_auth_pass);
        buf[0] = 0x01; buf[1] = (unsigned char)ul;
        memcpy(buf + 2, g_auth_user, ul);
        buf[2 + ul] = (unsigned char)pl;
        memcpy(buf + 3 + ul, g_auth_pass, pl);
        if (send_all(cfd, buf, 3 + ul + pl) < 0) goto fail;
        if (recv_all(cfd, buf, 2) < 0) goto fail;
        if (buf[0] != 0x01 || buf[1] != 0x00) { network_fail = 0; goto fail; }   // 認證被拒
    } else if (buf[1] != 0x00) {
        network_fail = 0;   // 伺服器拒絕認證方式
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
        if (buf[0] != 0x05) { network_fail = 0; goto fail; }
        if (buf[1] == 0x00) {
            // 伺服器支援：relay 就是這條 TCP 連線，吃掉 BND.ADDR/PORT 即可
            int atyp_r = buf[3];
            if (atyp_r == 0x01) {
                if (recv_all(cfd, buf, 6) < 0) goto fail;
            } else if (atyp_r == 0x04) {
                if (recv_all(cfd, buf, 18) < 0) goto fail;
            } else {
                network_fail = 0;
                goto fail;
            }
            udp_tcp = 1;
        } else {
            // 伺服器不支援 0x04：同一連線退回標準 UDP ASSOCIATE（0x03）
            LOGI("伺服器不支援 UDP-in-TCP (REP=%d)，退回 UDP-in-UDP", buf[1]);
            req[1] = 0x03;
            if (send_all(cfd, req, 10) < 0) goto fail;
            if (recv_all(cfd, buf, 4) < 0) goto fail;
            if (buf[0] != 0x05 || buf[1] != 0x00) { network_fail = 0; goto fail; }
        }
    } else {
        if (send_all(cfd, req, 10) < 0) goto fail;
        if (recv_all(cfd, buf, 4) < 0) goto fail;
        if (buf[0] != 0x05 || buf[1] != 0x00) { network_fail = 0; goto fail; }
    }

    if (!udp_tcp) {
        int atyp = buf[3];
        if (atyp == 0x01) {
            if (recv_all(cfd, buf, 6) < 0) goto fail;
            struct sockaddr_in *r4 = (struct sockaddr_in *)&relay;
            r4->sin_family = AF_INET;
            memcpy(&r4->sin_addr, buf, 4);
            memcpy(&r4->sin_port, buf + 4, 2);
            relay_len = sizeof(struct sockaddr_in);
        } else if (atyp == 0x04) {
            if (recv_all(cfd, buf, 18) < 0) goto fail;
            struct sockaddr_in6 *r6 = (struct sockaddr_in6 *)&relay;
            r6->sin6_family = AF_INET6;
            memcpy(&r6->sin6_addr, buf, 16);
            memcpy(&r6->sin6_port, buf + 16, 2);
            relay_len = sizeof(struct sockaddr_in6);
        } else {
            // 不支援其他 ATYP（0x03 網域 relay 位址極少見，且此處無法解析）
            LOGE("UDP ASSOCIATE 回覆 ATYP=%d 不支援", atyp);
            network_fail = 0;
            goto fail;
        }

        // 4. UDP relay socket（Java protect，未 connect，由 sendto 指定目標）
        rfd = request_java_socket(g_srv_host, g_srv_port, 1);
        if (rfd < 0) goto fail;
        if (!g_running) { network_fail = 0; goto fail; }
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
    sess->relay_len = relay_len;

    // 在註冊 epoll 前先轉發 handshake 期間緩衝的首包，
    // 避免線程與 engine 並發操作 tx_buf（UDP-in-TCP）
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

    // 先寫狀態再註冊 epoll（main loop 在 epoll_wait 回傳後才能看到 session）
    sess->state = 1;
    sess->last_active = time(NULL);
    struct epoll_event ev;
    // 注意：epoll_data 是 union，data.fd 與 data.ptr 共用記憶體。
    // 因此把 fd 號碼存進 data.fd 後，讀 data.ptr 會得到垃圾指標；
    // 改用「指標低 bit」區分事件來源：control 存原指標，relay 存指標|1。
    if (udp_tcp) {
        // UDP-in-TCP：control_fd 兼任 relay，以 tag=1 註冊
        unsigned int uev = EPOLLIN | EPOLLRDHUP | EPOLLERR;
        if (sess->tx_len > 0) uev |= EPOLLOUT;   // 首包已入隊：需立即排空
        ev.events = uev; ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
    } else {
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR; ev.data.ptr = sess;
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP; ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, rfd, &ev) < 0) { epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, cfd, NULL); goto fail; }
    }

    atomic_store(&sess->thread_done, 1);   // 先標記，engine 才可安全 free（shutdown 等 inflight==0）
    atomic_fetch_sub(&g_handshake_inflight, 1);
    if (udp_tcp) LOGI("udp handshake 完成: UDP-in-TCP (relay 走同一 TCP)");
    else {
        char rbuf[64];
        uint16_t rport = 0;
        if (relay_len == sizeof(struct sockaddr_in)) {
            struct sockaddr_in *r4 = (struct sockaddr_in *)&relay;
            inet_ntop(AF_INET, &r4->sin_addr, rbuf, sizeof rbuf);
            rport = ntohs(r4->sin_port);
        } else {
            struct sockaddr_in6 *r6 = (struct sockaddr_in6 *)&relay;
            inet_ntop(AF_INET6, &r6->sin6_addr, rbuf, sizeof rbuf);
            rport = ntohs(r6->sin6_port);
        }
        LOGI("udp handshake 完成: relay=%s:%d", rbuf, rport);
    }
    notify_server_event(1);
    return NULL;

fail:
    {
        char b1[64];
        ip_to_str(&sess->src_ip, b1, sizeof b1);
        LOGI("udp handshake 失敗 (src=%s:%d)", b1, ntohs(sess->src_port));
    }
    if (network_fail) notify_server_event(0);
    if (cfd >= 0) { release_java_socket(cfd); close(cfd); sess->control_fd = -1; }
    if (rfd >= 0) { release_java_socket(rfd); close(rfd); sess->relay_fd = -1; }
    // 從 hash 移除；記憶體保留至線程結束（thread_done=1）後由 graveyard collect 釋放，
    // 避免 engine（handle_tun_udp）在 unlock 後仍使用 sess 造成 UAF
    pthread_mutex_lock(&g_udp_hash_lock);
    unsigned idx = udp_hash_idx(&sess->src_ip, sess->src_port);
    udp_sess_t **pp = &g_udp_hash[idx];
    while (*pp && *pp != sess) pp = &(*pp)->next;
    if (*pp && !sess->closed) {
        *pp = sess->next;
        sess->closed = 1;
        sess->next = g_udp_graveyard;
        g_udp_graveyard = sess;
    }
    pthread_mutex_unlock(&g_udp_hash_lock);
    atomic_store(&sess->thread_done, 1);
    atomic_fetch_sub(&g_handshake_inflight, 1);
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
    } else if (atyp == 0x03) {
        // 伺服器以網域回應：改以該網域的 fake IP 作為來源，App 才認得
        if (len < 7) return;
        uint8_t dl = buf[4];
        if ((size_t)len < 7u + dl) return;
        char dom[256];
        size_t n = dl < sizeof(dom) - 1 ? dl : sizeof(dom) - 1;
        memcpy(dom, buf + 5, n);
        dom[n] = '\0';
        uint16_t rport;
        memcpy(&rport, buf + 5 + dl, 2);
        size_t plen = (size_t)len - 7u - dl;
        uint32_t fake = fake_dns_find_domain(dom);
        if (!fake) return;   // 無映射（非 Remote DNS 流量）→ 丟棄
        ip_addr_t remote = { .family = AF_INET };
        memcpy(remote.ip, &fake, 4);
        write_udp_to_tun(sess, &remote, rport, buf + 7 + dl, plen);
    } else {
        // 其他 ATYP 回應丟棄
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

// 兩階段釋放：一律移入 graveyard，真正 free 統一在 udp_graveyard_collect() 執行
// （位於 event 批次處理結束後、loop 結尾）。原因：UDP session 有 control+relay 兩條 fd，
// 同一批次可能出現兩個事件指向同一 session——若第一個事件就 free，第二個事件會讀寫
// 已釋放（甚至已被新 session 重用）的記憶體，損壞 hash 鏈。
// 呼叫端須先關閉 fds（或先呼叫 close_session_fds），且已自 hash unlink。
static void udp_sess_release(udp_sess_t *sess) {
    pthread_mutex_lock(&g_udp_hash_lock);
    sess->next = g_udp_graveyard;
    g_udp_graveyard = sess;
    pthread_mutex_unlock(&g_udp_hash_lock);
}

static void udp_graveyard_collect(void) {
    pthread_mutex_lock(&g_udp_hash_lock);
    udp_sess_t **pp = &g_udp_graveyard;
    while (*pp) {
        udp_sess_t *s = *pp;
        if (atomic_load(&s->thread_done)) {
            *pp = s->next;
            pthread_mutex_unlock(&g_udp_hash_lock);
            close_session_fds(s);
            udp_sess_free_bufs(s);
            free(s);
            atomic_fetch_sub(&g_udp_session_count, 1);
            pthread_mutex_lock(&g_udp_hash_lock);
        } else {
            pp = &s->next;
        }
    }
    pthread_mutex_unlock(&g_udp_hash_lock);
}

// ---------- TCP 封包處理 ----------

// 送出 TCP 封包給 App（以 App 觀點：saddr/daddr 為 IP 位址，sport/dport 為埠）
// seq/ack 以 host byte order 傳入，內部轉網路序寫出
static ssize_t write_tcp_to_tun(const ip_addr_t *saddr, const ip_addr_t *daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const unsigned char *payload, size_t plen,
                                uint16_t win) {
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
    pkt[u + 14] = (uint8_t)(win >> 8); pkt[u + 15] = (uint8_t)(win & 0xFF);
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
    pkt[u + 14] = (uint8_t)((TCP_APP_BUF_CAP >> 10) >> 8);
    pkt[u + 15] = (uint8_t)((TCP_APP_BUF_CAP >> 10) & 0xFF);
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

// 引擎對 App 通告的接收 window：app_buf 剩餘空間（SYNACK 協商 shift=10，單位 1KB）
static uint16_t tcp_win_field(const tcp_sess_t *sess) {
    size_t occ = sess->app_off + sess->app_len;
    size_t free = (occ >= TCP_APP_BUF_CAP) ? 0 : (TCP_APP_BUF_CAP - occ);
    uint16_t w = (uint16_t)(free >> 10);
    return (w > 0) ? w : 1;
}

static void send_tcp_ack(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x10, NULL, 0, tcp_win_field(sess));
}

static void send_tcp_fin(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x11, NULL, 0, tcp_win_field(sess));
}

static void send_session_rst(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     0, sess->app_next, 0x14, NULL, 0, 0);
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

// engine 單一執行緒呼叫（唯一釋放 session 之處，background 線程不碰 hash）
// 兩階段釋放：若背景 connect 線程尚未結束（thread_done==0），先移入 graveyard，
// 由 engine_loop 每輪結尾的 tcp_graveyard_collect() 在 thread_done==1 後真正 free。
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
    if (!*pp) {
        // 已不在 hash（可能已進 graveyard）→ 防止 double free
        LOGE("tcp_session_destroy: session 不在 hash，跳過釋放");
        return;
    }
    *pp = sess->next;
    // 一律移入 graveyard，由 tcp_graveyard_collect()（每批 epoll 事件處理完）統一 free。
    // 若 thread_done==1 時立即 free，本批事件中殘留的同 session 事件會讀到已釋放記憶體（UAF）。
    sess->next = g_tcp_graveyard;
    g_tcp_graveyard = sess;
}

static void tcp_graveyard_collect(void) {
    tcp_sess_t **pp = &g_tcp_graveyard;
    while (*pp) {
        tcp_sess_t *s = *pp;
        if (atomic_load(&s->thread_done)) {
            *pp = s->next;
            free(s->app_buf);
            free(s->srv_buf);
            free(s);
            atomic_fetch_sub(&g_tcp_session_count, 1);
        } else {
            pp = &s->next;
        }
    }
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
                                     sess->srv_buf + sess->srv_off, chunk, tcp_win_field(sess));
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
    size_t before = sess->app_len;
    while (sess->app_len > 0) {
        ssize_t n = send(fd, sess->app_buf + sess->app_off, sess->app_len, MSG_NOSIGNAL);
        if (n > 0) {
            atomic_fetch_add(&g_bytes_to_server, (unsigned long long)n);
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
    // 排空後重開 window：主動送 window-update ACK，避免 App 停在縮小的窗上死鎖
    if (sess->app_len < before && !sess->closed && atomic_load(&sess->state) == 1) {
        send_tcp_ack(sess);
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
    tcp_sess_t *sess = (tcp_sess_t *)arg;
    unsigned char buf[320];
    int sfd = -1;
    int fd_stored = 0;   // srv_fd 是否已交由 engine 管理（之後線程不再 close）
    int network_fail = 1;   // 網路層失敗旗標：伺服器明確拒絕（auth/REP≠0/非 SOCKS5）時清除，不觸發自動重連

    sfd = request_java_socket(g_srv_host, g_srv_port, 0);
    if (sfd < 0) goto fail;
    if (!g_running) { network_fail = 0; goto fail; }
    set_nonblocking(sfd);

    buf[0] = 0x05; buf[1] = 0x01; buf[2] = g_auth_enabled ? 0x02 : 0x00;
    if (net_send_all(sfd, buf, 3) < 0) goto fail;
    if (net_recv_all(sfd, buf, 2) < 0) goto fail;
    if (buf[0] != 0x05) { network_fail = 0; goto fail; }   // 對方不是 SOCKS5：重連無益
    if (buf[1] == 0x02) {
        size_t ul = strlen(g_auth_user), pl = strlen(g_auth_pass);
        buf[0] = 0x01; buf[1] = (unsigned char)ul;
        memcpy(buf + 2, g_auth_user, ul);
        buf[2 + ul] = (unsigned char)pl;
        memcpy(buf + 3 + ul, g_auth_pass, pl);
        if (net_send_all(sfd, buf, 3 + ul + pl) < 0) goto fail;
        if (net_recv_all(sfd, buf, 2) < 0) goto fail;
        if (buf[0] != 0x01 || buf[1] != 0x00) { network_fail = 0; goto fail; }   // 認證被拒
    } else if (buf[1] != 0x00) {
        network_fail = 0;   // 伺服器拒絕認證方式
        goto fail;
    }

    unsigned char req[300] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    int req_len;
    if (sess->dst_domain[0]) {
        // Remote DNS：ATYP=0x03，由伺服器端解析網域
        size_t dl = strlen(sess->dst_domain);
        req[3] = 0x03;
        req[4] = (unsigned char)dl;
        memcpy(req + 5, sess->dst_domain, dl);
        memcpy(req + 5 + dl, &sess->dst_port, 2);
        req_len = 5 + (int)dl + 2;
    } else if (sess->dst_ip.family == AF_INET6) {
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
    if (buf[0] != 0x05 || buf[1] != 0x00) { network_fail = 0; goto fail; }   // REP≠0：伺服器端結果，非網路斷線
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
        network_fail = 0;
        goto fail;
    }

    atomic_store(&sess->srv_fd, sfd);
    fd_stored = 1;
    atomic_store(&sess->state, 1);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
    ev.data.ptr = (tcp_sess_t *)((uintptr_t)sess | 3);
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
        // fd 已交予 engine（srv_fd=sfd），engine 銷毀時會關閉，線程不再 close
        atomic_store(&sess->handshake_failed, 1);
        if (g_kick_pipe[1] >= 0) { char k = 1; write(g_kick_pipe[1], &k, 1); }
        goto done;
    }
    if (g_kick_pipe[1] >= 0) { char k = 1; write(g_kick_pipe[1], &k, 1); }
    char b1[64];
    ip_to_str(&sess->dst_ip, b1, sizeof b1);
    LOGI("tcp connect 完成 -> %s:%d", b1, ntohs(sess->dst_port));
    notify_server_event(1);
    goto done;

fail:
    ip_to_str(&sess->dst_ip, b1, sizeof b1);
    LOGI("tcp connect 失敗 -> %s:%d", b1, ntohs(sess->dst_port));
    if (network_fail) notify_server_event(0);
    // 只有 store 前（fd_stored==0）的失敗才由線程 close；store 後 fd 屬 engine 所有
    if (sfd >= 0 && !fd_stored) { release_java_socket(sfd); close(sfd); }
    if (g_tun_fd >= 0) send_session_rst(sess);
    atomic_store(&sess->handshake_failed, 1);
    if (g_kick_pipe[1] >= 0) { char k = 1; write(g_kick_pipe[1], &k, 1); }

done:
    atomic_store(&sess->thread_done, 1);   // 先標記，engine 才可安全 free（shutdown 等 inflight==0）
    atomic_fetch_sub(&g_handshake_inflight, 1);
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
        if (g_remote_dns) {
            // fake IP（v4/v6）→ 記錄網域，connect 線程以 ATYP=0x03 撥號（由伺服器端解析）
            if (dst_ip->family == AF_INET) {
                uint32_t k;
                memcpy(&k, dst_ip->ip, 4);
                fake_dns_lookup(k, sess->dst_domain, sizeof(sess->dst_domain));
            } else if (dst_ip->family == AF_INET6) {
                fake_dns_lookup6(dst_ip->ip, sess->dst_domain, sizeof(sess->dst_domain));
            }
        }
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

        if (hs_submit(tcp_connect_thread, sess) != 0) close_tcp_session(sess, 1);
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
    // 迴繞安全比較（RFC1323 式）：單一連線傳輸超過 4GB 後序號迴繞，
    // 普通大小比較會拒絕更新 ack → app_acked 凍結 → 流控誤判窗口耗盡而卡死
    if ((int32_t)(ack_host - sess->app_acked) > 0) sess->app_acked = ack_host;

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
            if (!dst) { flush_tcp_app_buf(sess); dst = app_buf_reserve(sess, payload_len); }
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
            // 一律先入 app_buf 再 flush：直接 send 遇到 partial 時，App 重傳餘數會被重複接受
            unsigned char *dst = app_buf_reserve(sess, payload_len);
            if (!dst) {
                flush_tcp_app_buf(sess);
                if (sess->closed) return;
                dst = app_buf_reserve(sess, payload_len);
            }
            if (dst) {
                memcpy(dst, pkt + t + (size_t)tcp_hlen, payload_len);
                sess->app_len += payload_len;
                sess->app_next += (uint32_t)payload_len;
                send_tcp_ack(sess);
                set_srv_out(sess, 1);
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
                atomic_fetch_add(&g_bytes_from_server, (unsigned long long)r);
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

// ---------- ICMP Echo 回應（本機 ping 也通） ----------

// IPv4 ICMP echo request → 本機直接回 echo reply（不經過 SOCKS5）
static void handle_icmp4(const unsigned char *pkt, size_t len, int ihl,
                         const ip_addr_t *saddr, const ip_addr_t *daddr) {
    size_t t = (size_t)ihl;
    if (t + 8 > len) return;
    if (pkt[t] != 8 || pkt[t + 1] != 0) return;   // 僅處理 echo request
    if (len > TUN_MTU) return;
    unsigned char reply[TUN_MTU];
    memcpy(reply, pkt, len);
    // 交換 IP 來源/目的，重算 IP checksum
    memcpy(reply + 12, daddr->ip, 4);
    memcpy(reply + 16, saddr->ip, 4);
    reply[8] = 64;
    reply[10] = 0; reply[11] = 0;
    uint16_t csum = checksum16(reply, (size_t)ihl);
    reply[10] = csum >> 8; reply[11] = csum & 0xFF;
    // echo reply，重算 ICMP checksum
    reply[t] = 0;
    reply[t + 2] = 0; reply[t + 3] = 0;
    uint16_t icsum = checksum16(reply + t, len - t);
    reply[t + 2] = icsum >> 8; reply[t + 3] = icsum & 0xFF;
    ssize_t w = write(g_tun_fd, reply, len);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun icmp4 failed: %s", strerror(errno));
}

// IPv6 ICMPv6 echo request → 本機回 echo reply
static void handle_icmp6(const unsigned char *pkt, size_t len,
                         const ip_addr_t *saddr, const ip_addr_t *daddr) {
    if (len < 48 || len > TUN_MTU) return;
    if (pkt[40] != 128 || pkt[41] != 0) return;   // 僅處理 echo request
    unsigned char reply[TUN_MTU];
    memcpy(reply, pkt, len);
    // 交換 IPv6 來源/目的
    memcpy(reply + 8, daddr->ip, 16);
    memcpy(reply + 24, saddr->ip, 16);
    reply[7] = 64;
    // echo reply，重算 ICMPv6 checksum（含 pseudo-header）
    reply[40] = 129;
    reply[42] = 0; reply[43] = 0;
    uint16_t icsum = tcpudp_checksum6(daddr->ip, saddr->ip, 58, reply + 40, len - 40);
    reply[42] = icsum >> 8; reply[43] = icsum & 0xFF;
    ssize_t w = write(g_tun_fd, reply, len);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun icmp6 failed: %s", strerror(errno));
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
        } else if (proto == 1) {
            handle_icmp4(pkt, len, ihl, &saddr, &daddr);
        }
        return;
    }
    if (ver == 6) {
        uint8_t proto;
        ip_addr_t saddr, daddr;
        size_t l4off;
        if (parse_ipv6(pkt, len, &proto, &saddr, &daddr, &l4off) < 0) return;
        if (proto == 17) {
            handle_tun_udp(pkt, len, l4off, &saddr, &daddr);
        } else if (proto == 6) {
            handle_tun_tcp(pkt, len, l4off, &saddr, &daddr);
        } else if (proto == 58) {
            if (l4off == 40) handle_icmp6(pkt, len, &saddr, &daddr);
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
                    udp_sess_release(sess);
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
                udp_sess_release(garbage[i]);
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

        // 每輪結束：回收兩階段釋放（背景線程已結束）的 session
        tcp_graveyard_collect();
        udp_graveyard_collect();
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

    // 排空並 join handshake worker，確保之後 free session 不會有 worker 仍在用
    hs_pool_stop();

    // 線程已全部結束（thread_done 皆已設定）：清空兩階段釋放清單
    tcp_graveyard_collect();
    udp_graveyard_collect();

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

    // 關閉所有 TCP session（thread 已 join，無並發）。
    // 注意：不可先清空 hash 再釋放——tcp_session_destroy 會回查 hash 做 unlink，
    // 預先清空會造成「不在 hash」誤判（fd 也沒關，重啟累積 leak）。
    for (int b = 0; b < TCP_HASH_BUCKETS; b++) {
        while (g_tcp_hash[b]) {
            tcp_sess_t *s = g_tcp_hash[b];
            s->closed = 1;
            tcp_session_destroy(s);
        }
    }
    // 最後一次回收：等待後線程已結束的 session 在此釋放；
    // 5 秒等待超時的（極端情況）留在 graveyard，引擎已停止不再回收
    tcp_graveyard_collect();

    if (g_epoll_fd >= 0) { close(g_epoll_fd); g_epoll_fd = -1; }
    jni_detach_thread();
    return NULL;
}

// ---------- 對外介面 ----------

// 流量統計（供 JNI 通知列顯示）：payload bytes 累計 + 目前 session 數
void tun_socks_get_stats(unsigned long long *to_server, unsigned long long *from_server,
                         int *tcp_sessions, int *udp_sessions) {
    if (to_server) *to_server = atomic_load(&g_bytes_to_server);
    if (from_server) *from_server = atomic_load(&g_bytes_from_server);
    if (tcp_sessions) *tcp_sessions = atomic_load(&g_tcp_session_count);
    if (udp_sessions) *udp_sessions = atomic_load(&g_udp_session_count);
}

int tun_socks_start(int tun_fd, const char *host, int port, const char *user, const char *pass, int udp_in_tcp, int remote_dns) {
    if (g_running) return -1;

    g_tun_fd = tun_fd;
    strncpy(g_srv_host, host, sizeof(g_srv_host) - 1);
    g_srv_host[sizeof(g_srv_host) - 1] = '\0';
    g_srv_port = port;
    g_auth_enabled = (user && user[0]) || (pass && pass[0]);
    strncpy(g_auth_user, user ? user : "", sizeof(g_auth_user) - 1);
    strncpy(g_auth_pass, pass ? pass : "", sizeof(g_auth_pass) - 1);
    g_udp_in_tcp = udp_in_tcp ? 1 : 0;
    g_remote_dns = remote_dns ? 1 : 0;

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

    hs_pool_start();
    g_running = 1;
    if (pthread_create(&g_engine_thread, NULL, engine_loop, NULL) != 0) {
        g_running = 0;
        hs_pool_stop();
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
    hs_pool_stop();   // 安全網：引擎關閉路徑已 join，此為 idempotent no-op
    if (g_shutdown_pipe[0] != -1) { close(g_shutdown_pipe[0]); g_shutdown_pipe[0] = -1; }
    if (g_shutdown_pipe[1] != -1) { close(g_shutdown_pipe[1]); g_shutdown_pipe[1] = -1; }
    if (g_kick_pipe[0] != -1) { close(g_kick_pipe[0]); g_kick_pipe[0] = -1; }
    if (g_kick_pipe[1] != -1) { close(g_kick_pipe[1]); g_kick_pipe[1] = -1; }
    LOGI("tunnel stopped");
}
