// engine_util.c — 引擎共用 helper（抽離自 tun_socks.c）
// 位址格式化、會話 hash、TCP ISN、伺服器位址快照、fakedns 薄封裝、
// 非阻塞 fd 設定、SOCKS5 握手、阻塞/非阻塞 I/O。函式本體原封不動，僅改作用域。
#include "engine.h"
#include "ip_hash.h"
#include "tcp_state.h"
#include "socks5_codec.h"
#include "dns_query.h"
#include "dns_synth.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>

// 保護 g.srv_host / g.srv_port 的並行讀寫：soft-reconnect 會更新 srv_host，
// 而各 handshake 執行緒在建立 socket 時會讀它；加鎖快照避免讀到撕裂字串。
static pthread_mutex_t g_srv_cfg_lock = PTHREAD_MUTEX_INITIALIZER;

// fake_dns.c 為純邏輯（無鎖、不取時間），鎖由引擎持有——引擎單執行緒與
// handshake 執行緒皆會存取 fake DNS 表。以下薄封裝補上 mutex 與 time(NULL)。
static pthread_mutex_t g_fake_dns_lock = PTHREAD_MUTEX_INITIALIZER;

void ip_to_str(const ip_addr_t *a, char *out, size_t n) {
    if (a->family == AF_INET6) inet_ntop(AF_INET6, a->ip, out, n);
    else inet_ntop(AF_INET, a->ip, out, n);
}

unsigned tcp_hash_idx(const ip_addr_t *ip, uint16_t port) {
    return ip_hash_bucket(ip, port, TCP_HASH_BUCKETS);
}

unsigned udp_hash_idx(const ip_addr_t *ip, uint16_t port) {
    return ip_hash_bucket(ip, port, UDP_HASH_BUCKETS);
}

uint32_t next_tcp_isn(void) {
    return tcp_isn_generate((uint32_t)time(NULL), &g.isn_counter);
}

// 加鎖快照伺服器位址／埠，供 handshake 執行緒安全讀取。
void srv_snapshot(char *host_out, size_t host_len, int *port_out) {
    pthread_mutex_lock(&g_srv_cfg_lock);
    strncpy(host_out, g.srv_host, host_len - 1);
    host_out[host_len - 1] = '\0';
    *port_out = g.srv_port;
    pthread_mutex_unlock(&g_srv_cfg_lock);
}

uint32_t fd_alloc(const char *domain, unsigned char ip6_out[16]) {
    pthread_mutex_lock(&g_fake_dns_lock);
    uint32_t r = fake_dns_alloc(&g.fake_dns, domain, time(NULL), ip6_out);
    pthread_mutex_unlock(&g_fake_dns_lock);
    return r;
}

int fd_lookup(uint32_t fake_ip, char *domain, size_t dn) {
    pthread_mutex_lock(&g_fake_dns_lock);
    int r = fake_dns_lookup(&g.fake_dns, fake_ip, time(NULL), domain, dn);
    pthread_mutex_unlock(&g_fake_dns_lock);
    return r;
}

uint32_t fd_find_domain(const char *domain) {
    pthread_mutex_lock(&g_fake_dns_lock);
    uint32_t r = fake_dns_find_domain(&g.fake_dns, domain, time(NULL));
    pthread_mutex_unlock(&g_fake_dns_lock);
    return r;
}

int fd_lookup6(const unsigned char ip6[16], char *domain, size_t dn) {
    pthread_mutex_lock(&g_fake_dns_lock);
    int r = fake_dns_lookup6(&g.fake_dns, ip6, time(NULL), domain, dn);
    pthread_mutex_unlock(&g_fake_dns_lock);
    return r;
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int send_all(int fd, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

int recv_all(int fd, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

// SOCKS5 greeting + 選擇性 RFC 1929 認證（TCP CONNECT 與 UDP ASSOCIATE 共用）。
// send_fn / recv_fn 抽象底層 I/O 差異：TCP 用 net_send_all/net_recv_all（非阻塞 + poll），
// UDP 用 send_all/recv_all（阻塞）。成功回 0，失敗回對應的 SE_EVENT_* 分類碼，
// 呼叫端可直接指派給 fail_code 後 goto fail。
int socks5_greet_auth(int fd,
                      int (*send_fn)(int, const unsigned char *, size_t),
                      int (*recv_fn)(int, unsigned char *, size_t),
                      unsigned char *buf, size_t cap) {
    int n = socks5_build_hello(g.auth_user, g.auth_pass, buf, cap);
    if (n < 0 || send_fn(fd, buf, (size_t)n) < 0) return SE_EVENT_NETWORK_FAIL;
    if (recv_fn(fd, buf, 2) < 0) return SE_EVENT_NETWORK_FAIL;
    s5_greet_class_t cls = socks5_classify_greet_reply(buf);
    if (cls == S5_ERR_NOT_SOCKS5) return SE_EVENT_PROTOCOL_FAIL;   // 對方不是 SOCKS5
    if (cls == S5_ERR_NO_METHOD) return SE_EVENT_AUTH_FAIL;        // 伺服器拒絕認證方式
    if (cls == S5_GREET_NEED_AUTH) {
        // RFC 1929 認證
        n = socks5_build_auth(g.auth_user, g.auth_pass, buf, cap);
        if (n < 0 || send_fn(fd, buf, (size_t)n) < 0) return SE_EVENT_NETWORK_FAIL;
        if (recv_fn(fd, buf, 2) < 0) return SE_EVENT_NETWORK_FAIL;
        if (!socks5_auth_reply_ok(buf)) return SE_EVENT_AUTH_FAIL;   // 認證被拒
    }
    return 0;   // 握手成功
}

static int wait_fd(int fd, short events, int timeout_ms) {
    int waited = 0;
    while (waited < timeout_ms) {
        struct pollfd p = { fd, events, 0 };
        int r = poll(&p, 1, 100);
        if (r > 0) return 0;
        if (r < 0) return -1;
        waited += 100;
        if (!g.running) return -1;
    }
    return -1;
}

int net_send_all(int fd, const unsigned char *buf, size_t len) {
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

int net_recv_all(int fd, unsigned char *buf, size_t len) {
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

// 解析並合成單一 DNS query（A/AAAA/HTTPS）的 fake 回覆，不寫 TUN。
// always_answer=0（UDP）：僅 A/AAAA/HTTPS 攔截，其餘回 0 放行走 relay。
// always_answer=1（TCP）：任何合法 query 都產生回覆（A/AAAA fake、其餘 NOERROR 空答）。
int dns_build_reply(const unsigned char *q, size_t qlen, int always_answer,
                    unsigned char *reply, size_t *rlen) {
    char name[256];
    uint16_t qtype;
    int supported;
    if (!dns_query_parse(q, qlen, name, sizeof(name), &qtype, NULL, &supported, NULL))
        return 0;
    if (!supported && !always_answer) return 0;

    unsigned char fake6[16];
    uint32_t fake = 0;
    if (qtype == 1 || qtype == 28) {
        fake = fd_alloc(name, fake6);
        if (!fake) return 0;
    }

    // 委派給純函式合成回覆（dns_synth.c，golden 測試覆蓋）
    return dns_build_reply_pure(q, qlen, fake, fake6, always_answer, reply, rlen);
}

// 加鎖重置 fake DNS 表（engine_soft_reset / engine_ctx_reset 共用）。
void engine_fake_dns_reset(void) {
    pthread_mutex_lock(&g_fake_dns_lock);
    fake_dns_reset(&g.fake_dns);
    pthread_mutex_unlock(&g_fake_dns_lock);
}

// 加鎖更新伺服器 host（tun_socks_reconnect 用）。
void engine_srv_host_update(const char *new_host) {
    pthread_mutex_lock(&g_srv_cfg_lock);
    strncpy(g.srv_host, new_host, sizeof(g.srv_host) - 1);
    g.srv_host[sizeof(g.srv_host) - 1] = '\0';
    pthread_mutex_unlock(&g_srv_cfg_lock);
}
