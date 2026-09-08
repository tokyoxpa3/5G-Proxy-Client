#ifndef ENGINE_H
#define ENGINE_H

// engine.h — 引擎共用型別、常數與 session 模組介面。
// 由 tun_socks.c（分派 + epoll 迴圈 + 生命週期）、tcp_sess.c、udp_sess.c、
// hs_pool.c、engine_util.c 共用。單一引擎實例（單一隧道），狀態收在 engine_ctx_t g。

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "ip_parse.h"
#include "fake_dns.h"
#include "udp_tcp.h"
#include "jni_bridge.h"
#include <android/log.h>

#define LOG_TAG "TunSocks"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ---- 常數 ----
#define MAX_PACKET_SIZE 4160
#define MAX_EVENTS 256
// 須與 Java Config.TUN_MTU 保持一致（VpnService.Builder.setMtu），改動需同步兩側
#define TUN_MTU 4096
#define HANDSHAKE_TIMEOUT_SEC 10
#define UDP_HASH_BUCKETS 256
#define MAX_UDP_SESSIONS 512
#define TCP_HASH_BUCKETS 256
#define MAX_TCP_SESSIONS 512
#define TCP_APP_BUF_CAP (4 * 1024 * 1024)
#define TCP_SRV_BUF_CAP (1024 * 1024)
#define TCP_READ_CHUNK (64 * 1024)
#define HS_POOL_WORKERS 16

// ---- TCP 會話 ----
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
    unsigned char *dns_rx_buf; size_t dns_rx_len, dns_rx_cap;  // DNS-over-TCP 攔截：inbound 串流緩衝
    int dns_tcp;                 // 1 = DNS-over-TCP 攔截（port 53，本機合成 fake 回覆）
    time_t last_active;
    struct tcp_sess *next;  // hash chain
} tcp_sess_t;

// ---- UDP 會話 ----
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
    udp_tcp_stream_t rx_stream;  // frame 串流解析狀態（純邏輯在 udp_tcp.c）
    atomic_int thread_done;     // handshake 線程結束標記（釋放前檢查）
    struct udp_sess *next;  // hash chain
} udp_sess_t;

// ---- handshake job ----
typedef struct hs_job {
    void *(*fn)(void *);
    void *arg;
    struct hs_job *next;
} hs_job_t;

// ---- 引擎 context ----
typedef struct {
    // lifecycle / config
    int tun_fd;
    int shutdown_pipe[2];
    volatile int running;
    int epoll_fd;
    char srv_host[256];
    int srv_port;
    char auth_user[128];
    char auth_pass[128];
    int auth_enabled;
    int udp_in_tcp;    // 1 = UDP relay 走 TCP frame（cmd=0x04 擴充）
    int remote_dns;    // 1 = Remote DNS（fakedns）：攔截 DNS、以網域撥號

    // 流量統計（payload bytes 累計，供通知列即時顯示）
    atomic_ullong bytes_to_server;    // App → SOCKS5 伺服器
    atomic_ullong bytes_from_server;  // SOCKS5 伺服器 → App
    atomic_int udp_session_count;
    atomic_int handshake_inflight;

    // TCP
    tcp_sess_t *tcp_hash[TCP_HASH_BUCKETS];
    atomic_int tcp_session_count;
    int kick_pipe[2];
    int tun_want_out;
    uint32_t isn_counter;
    tcp_sess_t *tcp_graveyard;

    // UDP
    udp_sess_t *udp_hash[UDP_HASH_BUCKETS];
    udp_sess_t *udp_graveyard;

    // Remote DNS（fakedns）——純邏輯與狀態表在 fake_dns.c，引擎以 mutex 同步
    fake_dns_table_t fake_dns;

    // handshake 執行緒池
    pthread_t hs_workers[HS_POOL_WORKERS];
    int hs_worker_count;
    hs_job_t *hs_head;
    hs_job_t *hs_tail;
    int hs_running;
} engine_ctx_t;

// 單一引擎實例（單一隧道），定義於 tun_socks.c。
extern engine_ctx_t g;

// ---- 共用 helper（engine_util.c） ----
void ip_to_str(const ip_addr_t *a, char *out, size_t n);
unsigned tcp_hash_idx(const ip_addr_t *ip, uint16_t port);
unsigned udp_hash_idx(const ip_addr_t *ip, uint16_t port);
uint32_t next_tcp_isn(void);
void srv_snapshot(char *host_out, size_t host_len, int *port_out);
uint32_t fd_alloc(const char *domain, unsigned char ip6_out[16]);
int fd_lookup(uint32_t fake_ip, char *domain, size_t dn);
uint32_t fd_find_domain(const char *domain);
int fd_lookup6(const unsigned char ip6[16], char *domain, size_t dn);
void set_nonblocking(int fd);
int send_all(int fd, const unsigned char *buf, size_t len);
int recv_all(int fd, unsigned char *buf, size_t len);
int socks5_greet_auth(int fd,
                      int (*send_fn)(int, const unsigned char *, size_t),
                      int (*recv_fn)(int, unsigned char *, size_t),
                      unsigned char *buf, size_t cap);
int net_send_all(int fd, const unsigned char *buf, size_t len);
int net_recv_all(int fd, unsigned char *buf, size_t len);
// 解析並合成單一 DNS query（A/AAAA/HTTPS）的 fake 回覆，不寫 TUN。
// always_answer=0（UDP）：僅 A/AAAA/HTTPS 攔截，其餘回 0 放行走 relay。
// always_answer=1（TCP）：任何合法 query 都產生回覆（A/AAAA fake、其餘 NOERROR 空答）。
// 回傳 1 = reply/rlen 有效；0 = 放行（UDP）或解析失敗。
int dns_build_reply(const unsigned char *q, size_t qlen, int always_answer,
                    unsigned char *reply, size_t *rlen);
// 加鎖重置 fake DNS 表（engine_soft_reset / engine_ctx_reset 共用）。
void engine_fake_dns_reset(void);
// 加鎖更新伺服器 host（tun_socks_reconnect 用）。
void engine_srv_host_update(const char *new_host);

// ---- handshake 執行緒池（hs_pool.c） ----
void hs_pool_start(void);
void hs_pool_stop(void);
int hs_submit(void *(*fn)(void *), void *arg);

// ---- UDP session（udp_sess.c） ----
void udp_handle_packet(const unsigned char *pkt, size_t len, size_t t,
                       const ip_addr_t *src_ip, const ip_addr_t *dst_ip);
void udp_handle_event(udp_sess_t *sess, uint32_t ev, time_t now, int is_relay);
void udp_soft_reset(void);
void udp_shutdown_collect(void);
void udp_idle_gc(time_t now);
void udp_graveyard_collect(void);

// ---- TCP session（tcp_sess.c） ----
void tcp_handle_packet(const unsigned char *pkt, size_t len, size_t t,
                       const ip_addr_t *src_ip, const ip_addr_t *dst_ip);
void tcp_handle_event(tcp_sess_t *sess, uint32_t ev, time_t now);
void tcp_flush_all(void);
void tcp_sweep(void);
void tcp_soft_reset(void);
void tcp_shutdown_collect(void);
void tcp_idle_gc(time_t now);
void tcp_graveyard_collect(void);

#endif
