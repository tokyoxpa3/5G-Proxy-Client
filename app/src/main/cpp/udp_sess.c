// udp_sess.c — UDP session 管理（抽離自 tun_socks.c）
// SOCKS5 UDP ASSOCIATE relay、UDP-in-TCP frame 串流、會話生命週期與兩階段釋放。
// 函式本體原封不動，僅改作用域；epoll 事件入口為 udp_handle_event。
#include "engine.h"
#include "tcp_packet.h"
#include "udp_state.h"
#include "socks5_codec.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static pthread_mutex_t g_udp_hash_lock = PTHREAD_MUTEX_INITIALIZER;

static void udp_sess_free_bufs(udp_sess_t *sess);
static void handle_relay_udp(udp_sess_t *sess, const unsigned char *buf, ssize_t len);
static void *udp_session_thread(void *arg);

// ---------- relay 回應 → TUN 封包 ----------

static void write_ipv4_udp_to_tun_ex(const ip_addr_t *app_ip, uint16_t app_port,
                                     const ip_addr_t *remote, uint16_t remote_port,
                                     const unsigned char *payload, size_t plen) {
    unsigned char pkt[TUN_MTU];
    ssize_t total = udp_build_packet(remote->ip, app_ip->ip, AF_INET,
                                     remote_port, app_port,
                                     payload, plen, pkt, sizeof pkt);
    if (total < 0) return;
    ssize_t w = write(g.tun_fd, pkt, (size_t)total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun failed: %s", strerror(errno));
}

static void write_ipv6_udp_to_tun_ex(const ip_addr_t *app_ip, uint16_t app_port,
                                     const ip_addr_t *remote, uint16_t remote_port,
                                     const unsigned char *payload, size_t plen) {
    unsigned char pkt[TUN_MTU];
    ssize_t total = udp_build_packet(remote->ip, app_ip->ip, AF_INET6,
                                     remote_port, app_port,
                                     payload, plen, pkt, sizeof pkt);
    if (total < 0) return;
    ssize_t w = write(g.tun_fd, pkt, (size_t)total);
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
    atomic_fetch_add(&g.bytes_from_server, (unsigned long long)plen);
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

// ---------- UDP-in-TCP：frame 串流收發 ----------

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
        if (epoll_ctl(g.epoll_fd, EPOLL_CTL_MOD, sess->control_fd, &ev) == 0) sess->tx_armed = 1;
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
            if (epoll_ctl(g.epoll_fd, EPOLL_CTL_MOD, sess->control_fd, &ev) == 0) sess->tx_armed = 0;
        }
    }
    return 0;
}

// udp_tcp_consume 的 frame 回呼：把解析出的 payload 交給 handle_relay_udp。
static void udp_tcp_on_frame(void *ctx, const unsigned char *payload, size_t payload_len) {
    handle_relay_udp((udp_sess_t *)ctx, payload, (ssize_t)payload_len);
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
    // 2. 解析 frames（純 length-prefixed 解析在 udp_tcp.c，golden/fuzz 覆蓋）
    long consumed = udp_tcp_consume(&sess->rx_stream, sess->rx_buf + sess->rx_off,
                                    sess->rx_len, sess->rx_cap, udp_tcp_on_frame, sess);
    if (consumed < 0) return -1;
    sess->rx_off += (size_t)consumed;
    sess->rx_len -= (size_t)consumed;
    if (sess->rx_len == 0) sess->rx_off = 0;
    return 0;
}

static void forward_udp_to_server(udp_sess_t *sess, const ip_addr_t *dst, uint16_t dst_port, const unsigned char *payload, size_t plen) {
    unsigned char frame[2 + 262 + MAX_PACKET_SIZE];
    if (plen > MAX_PACKET_SIZE) plen = MAX_PACKET_SIZE;
    char dom[256];
    const char *domain = NULL;
    if (g.remote_dns && dst->family == AF_INET) {
        if (fd_lookup(fake_dns_key(dst), dom, sizeof dom)) domain = dom;
    } else if (g.remote_dns && dst->family == AF_INET6) {
        // fake IPv6 → 以網域撥號（Remote DNS 的 AAAA 路徑）
        if (fd_lookup6(dst->ip, dom, sizeof dom)) domain = dom;
    }
    int flen = socks5_build_udp_frame(dst->ip, dst->family, dst_port, domain,
                                      payload, plen, frame, sizeof frame);
    if (flen < 0) { LOGE("udp frame 建構失敗"); return; }
    atomic_fetch_add(&g.bytes_to_server, (unsigned long long)plen);

    if (sess->udp_tcp) {
        // UDP-in-TCP：frame 直接進控制連線的送出佇列
        udp_tcp_append(sess, frame, (size_t)flen);
    } else {
        ssize_t sent = sendto(sess->relay_fd, frame + 2, (size_t)(flen - 2), MSG_NOSIGNAL,
                              (struct sockaddr *)&sess->relay_addr, sess->relay_len);
        if (sent < 0) LOGE("relay sendto 失敗: %s", strerror(errno));
    }
}

// UDP 路徑：攔截 DNS 查詢並以 fake IP 回覆；回傳 1=已處理，0=放行走 relay。
static int dns_try_intercept(const unsigned char *q, size_t qlen,
                             const ip_addr_t *src_ip, const ip_addr_t *dst_ip,
                             uint16_t sport, uint16_t dport) {
    unsigned char reply[512];
    size_t rlen = 0;
    if (!dns_build_reply(q, qlen, 0, reply, &rlen)) return 0;
    write_udp_reply_to_tun(src_ip, sport, dst_ip, dport, reply, rlen);
    return 1;
}

// ---------- 入口：TUN UDP 封包 ----------

void udp_handle_packet(const unsigned char *pkt, size_t len, size_t t, const ip_addr_t *src_ip, const ip_addr_t *dst_ip) {
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
    if (g.remote_dns && ntohs(dport) == 53) {
        if (dns_try_intercept(pkt + u + 8, payload_len, src_ip, dst_ip, sport, dport)) return;
    }

    // 以 App 的 (src_ip, src_port) 作為會話鍵（一個 ASSOCIATE 可對多個目標）
    unsigned idx = udp_hash_idx(src_ip, sport);
    udp_sess_t *sess = NULL;
    int created = 0;
    pthread_mutex_lock(&g_udp_hash_lock);
    for (udp_sess_t *s = g.udp_hash[idx]; s; s = s->next) {
        if (ip_addr_eq(&s->src_ip, src_ip) && s->src_port == sport && !s->closed) { sess = s; break; }
    }
    if (!sess && atomic_load(&g.udp_session_count) < MAX_UDP_SESSIONS) {
        sess = calloc(1, sizeof(udp_sess_t));
        if (sess) {
            sess->src_ip = *src_ip;
            sess->src_port = sport;
            sess->control_fd = -1;
            sess->relay_fd = -1;
            sess->last_active = time(NULL);
            sess->next = g.udp_hash[idx];
            g.udp_hash[idx] = sess;
            atomic_fetch_add(&g.udp_session_count, 1);
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
        if (udp_should_buffer_first_pkt(payload_len)) {
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
            udp_sess_t **pp = &g.udp_hash[idx];
            while (*pp && *pp != sess) pp = &(*pp)->next;
            if (*pp) {
                *pp = sess->next;
                sess->closed = 1;
                pthread_mutex_unlock(&g_udp_hash_lock);
                udp_sess_free_bufs(sess);
                free(sess);
                atomic_fetch_sub(&g.udp_session_count, 1);
            } else {
                pthread_mutex_unlock(&g_udp_hash_lock);
            }
        }
        return;
    }

    if (sess->state == 0) {
        // handshake 進行中：若尚未緩衝首包則緩衝，完成後由線程轉發
        pthread_mutex_lock(&g_udp_hash_lock);
        if (sess->state == 0 && !sess->pend_data && udp_should_buffer_first_pkt(payload_len)) {
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

// ---------- 釋放 helper ----------

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
    int fail_code = SE_EVENT_NETWORK_FAIL;   // 事件分類碼（同 tcp_connect_thread）
    char srv_host[256]; int srv_port;
    srv_snapshot(srv_host, sizeof srv_host, &srv_port);

    // 1. TCP 控制連線（Java 已 connect + protect）
    cfd = request_java_socket(srv_host, srv_port, 0);
    if (cfd < 0) goto fail;
    if (!g.running) { fail_code = SE_EVENT_NONE; goto fail; }
    struct timeval tv = {HANDSHAKE_TIMEOUT_SEC, 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    // 2. SOCKS5 握手（greeting + 選擇性 RFC 1929 認證，與 TCP CONNECT 共用 helper）
    int hs = socks5_greet_auth(cfd, send_all, recv_all, buf, sizeof buf);
    if (hs != 0) { fail_code = hs; goto fail; }

    // 3. UDP ASSOCIATE
    unsigned char req[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    int udp_tcp = 0;
    if (g.udp_in_tcp) {
        // 先嘗試 UDP-in-TCP（自訂擴充指令 0x04）
        req[1] = 0x04;
        if (send_all(cfd, req, 10) < 0) goto fail;
        if (recv_all(cfd, buf, 4) < 0) goto fail;
        if (buf[0] != 0x05) { fail_code = SE_EVENT_PROTOCOL_FAIL; goto fail; }
        if (buf[1] == 0x00) {
            // 伺服器支援：relay 就是這條 TCP 連線，吃掉 BND.ADDR/PORT 即可
            int atyp_r = buf[3];
            int bnd_len = socks5_atyp_bnd_len(atyp_r);
            if (bnd_len < 0) {   // 0x03 變長或未知 ATYP：UDP-in-TCP 不支援網域 relay
                fail_code = SE_EVENT_PROTOCOL_FAIL;
                goto fail;
            }
            if (recv_all(cfd, buf, bnd_len) < 0) goto fail;
            udp_tcp = 1;
        } else {
            // 伺服器不支援 0x04：同一連線退回標準 UDP ASSOCIATE（0x03）。
            // 失敗回覆仍含 BND.ADDR/PORT，須完整吃掉，否則殘留位元組會污染下一筆 0x03 的回覆。
            LOGI("伺服器不支援 UDP-in-TCP (REP=%d)，退回 UDP-in-UDP", buf[1]);
            int atyp_r = buf[3];
            int bnd_len = socks5_atyp_bnd_len(atyp_r);
            if (bnd_len == -2) {   // 0x03 變長：先讀 1-byte 長度再讀 len+2
                unsigned char al;
                if (recv_all(cfd, &al, 1) < 0) goto fail;
                if (recv_all(cfd, buf, (size_t)al + 2) < 0) goto fail;
            } else if (bnd_len > 0) {
                if (recv_all(cfd, buf, (size_t)bnd_len) < 0) goto fail;
            }
            req[1] = 0x03;
            if (send_all(cfd, req, 10) < 0) goto fail;
            if (recv_all(cfd, buf, 4) < 0) goto fail;
            if (buf[0] != 0x05 || buf[1] != 0x00) { fail_code = SE_EVENT_PROTOCOL_FAIL; goto fail; }
        }
    } else {
        if (send_all(cfd, req, 10) < 0) goto fail;
        if (recv_all(cfd, buf, 4) < 0) goto fail;
        if (buf[0] != 0x05 || buf[1] != 0x00) { fail_code = SE_EVENT_PROTOCOL_FAIL; goto fail; }
    }

    if (!udp_tcp) {
        int atyp = buf[3];
        int bnd_len = socks5_atyp_bnd_len(atyp);
        if (bnd_len < 0) {
            // 不支援其他 ATYP（0x03 網域 relay 位址極少見，且此處無法解析）
            LOGE("UDP ASSOCIATE 回覆 ATYP=%d 不支援", atyp);
            fail_code = SE_EVENT_PROTOCOL_FAIL;
            goto fail;
        }
        if (recv_all(cfd, buf, bnd_len) < 0) goto fail;
        if (atyp == 0x01) {
            struct sockaddr_in *r4 = (struct sockaddr_in *)&relay;
            r4->sin_family = AF_INET;
            memcpy(&r4->sin_addr, buf, 4);
            memcpy(&r4->sin_port, buf + 4, 2);
            relay_len = sizeof(struct sockaddr_in);
        } else {   // atyp == 0x04
            struct sockaddr_in6 *r6 = (struct sockaddr_in6 *)&relay;
            r6->sin6_family = AF_INET6;
            memcpy(&r6->sin6_addr, buf, 16);
            memcpy(&r6->sin6_port, buf + 16, 2);
            relay_len = sizeof(struct sockaddr_in6);
        }

        // 4. UDP relay socket（Java protect，未 connect，由 sendto 指定目標）
        rfd = request_java_socket(srv_host, srv_port, 1);
        if (rfd < 0) goto fail;
        if (!g.running) { fail_code = SE_EVENT_NONE; goto fail; }
        set_nonblocking(rfd);
    } else {
        // UDP-in-TCP：初始化 frame 串流的收發緩衝
        sess->udp_tcp = 1;
        sess->tx_cap = 65536;
        sess->tx_buf = malloc(sess->tx_cap);
        sess->rx_cap = 8192;
        sess->rx_buf = malloc(sess->rx_cap);
        udp_tcp_stream_init(&sess->rx_stream);
        if (!sess->tx_buf || !sess->rx_buf) goto fail;
    }

    if (!g.running) goto fail;
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
        if (epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
    } else {
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR; ev.data.ptr = sess;
        if (epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) goto fail;
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP; ev.data.ptr = (udp_sess_t *)((uintptr_t)sess | 1);
        if (epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, rfd, &ev) < 0) { epoll_ctl(g.epoll_fd, EPOLL_CTL_DEL, cfd, NULL); goto fail; }
    }

    atomic_store(&sess->thread_done, 1);   // 先標記，engine 才可安全 free（shutdown 等 inflight==0）
    atomic_fetch_sub(&g.handshake_inflight, 1);
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
    notify_server_event(SE_EVENT_OK);
    return NULL;

fail:
    {
        char b1[64];
        ip_to_str(&sess->src_ip, b1, sizeof b1);
        LOGI("udp handshake 失敗 (src=%s:%d)", b1, ntohs(sess->src_port));
    }
    if (fail_code != SE_EVENT_NONE) notify_server_event(fail_code);
    if (cfd >= 0) { release_java_socket(cfd); sess->control_fd = -1; }
    if (rfd >= 0) { release_java_socket(rfd); sess->relay_fd = -1; }
    // 從 hash 移除；記憶體保留至線程結束（thread_done=1）後由 graveyard collect 釋放，
    // 避免 engine（udp_handle_packet）在 unlock 後仍使用 sess 造成 UAF
    pthread_mutex_lock(&g_udp_hash_lock);
    unsigned idx = udp_hash_idx(&sess->src_ip, sess->src_port);
    udp_sess_t **pp = &g.udp_hash[idx];
    while (*pp && *pp != sess) pp = &(*pp)->next;
    if (*pp && !sess->closed) {
        *pp = sess->next;
        sess->closed = 1;
        sess->next = g.udp_graveyard;
        g.udp_graveyard = sess;
    }
    pthread_mutex_unlock(&g_udp_hash_lock);
    atomic_store(&sess->thread_done, 1);
    atomic_fetch_sub(&g.handshake_inflight, 1);
    return NULL;
}

// relay 回應 → 還原成 IP 封包寫回 TUN
static void handle_relay_udp(udp_sess_t *sess, const unsigned char *buf, ssize_t len) {
    if (len < 4) return;
    unsigned char ip[16] = {0};
    int fam = 0;
    uint16_t rport = 0;
    char dom[256];
    const unsigned char *payload = NULL;
    size_t plen = 0;
    // 委派給純函式解析回應表頭（socks5_codec.c，fuzz/golden 覆蓋）
    if (socks5_parse_udp_datagram(buf, (size_t)len, ip, &fam, &rport,
                                  dom, sizeof dom, &payload, &plen) < 0)
        return;
    ip_addr_t remote;
    memset(remote.ip, 0, sizeof(remote.ip));
    if (fam == AF_INET || fam == AF_INET6) {
        remote.family = fam;
        memcpy(remote.ip, ip, 16);
    } else if (fam == -1) {
        // 伺服器以網域回應：改以該網域的 fake IP 作為來源，App 才認得
        uint32_t fake = fd_find_domain(dom);
        if (!fake) return;   // 無映射（非 Remote DNS 流量）→ 丟棄
        remote.family = AF_INET;
        memcpy(remote.ip, &fake, 4);
    } else {
        return;   // 其他 ATYP 回應丟棄
    }
    write_udp_to_tun(sess, &remote, rport, payload, plen);
}

static void close_session_fds(udp_sess_t *sess) {
    if (sess->control_fd >= 0) {
        if (g.epoll_fd >= 0) epoll_ctl(g.epoll_fd, EPOLL_CTL_DEL, sess->control_fd, NULL);
        // fd 由 Java 端（activeSockets）唯一 close：native 只移除 epoll 註冊並交還，
        // 避免 detachFd 後 Java Socket 與 native 對同一 fd 雙重 close（fd 可能已被重用）。
        release_java_socket(sess->control_fd);
        sess->control_fd = -1;
    }
    if (sess->relay_fd >= 0) {
        if (g.epoll_fd >= 0) epoll_ctl(g.epoll_fd, EPOLL_CTL_DEL, sess->relay_fd, NULL);
        release_java_socket(sess->relay_fd);
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
    sess->next = g.udp_graveyard;
    g.udp_graveyard = sess;
    pthread_mutex_unlock(&g_udp_hash_lock);
}

void udp_graveyard_collect(void) {
    pthread_mutex_lock(&g_udp_hash_lock);
    udp_sess_t **pp = &g.udp_graveyard;
    while (*pp) {
        udp_sess_t *s = *pp;
        if (atomic_load(&s->thread_done)) {
            *pp = s->next;
            pthread_mutex_unlock(&g_udp_hash_lock);
            close_session_fds(s);
            udp_sess_free_bufs(s);
            free(s);
            atomic_fetch_sub(&g.udp_session_count, 1);
            pthread_mutex_lock(&g_udp_hash_lock);
        } else {
            pp = &s->next;
        }
    }
    pthread_mutex_unlock(&g_udp_hash_lock);
}

// ---------- 入口：epoll 事件 ----------

void udp_handle_event(udp_sess_t *sess, uint32_t ev, time_t now, int is_relay) {
    if (sess->closed) return;
    sess->last_active = now;

    int fatal = 0;
    if (ev & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) fatal = 1;

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
            udp_sess_t **pp = &g.udp_hash[idx];
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

// ---------- 入口：soft reset / shutdown / idle GC ----------

void udp_soft_reset(void) {
    pthread_mutex_lock(&g_udp_hash_lock);
    for (int b = 0; b < UDP_HASH_BUCKETS; b++) {
        udp_sess_t *s = g.udp_hash[b];
        g.udp_hash[b] = NULL;
        while (s) {
            udp_sess_t *n = s->next;
            s->closed = 1;
            s->next = g.udp_graveyard;
            g.udp_graveyard = s;
            s = n;
        }
    }
    pthread_mutex_unlock(&g_udp_hash_lock);
    udp_graveyard_collect();
}

void udp_shutdown_collect(void) {
    udp_graveyard_collect();
    udp_sess_t *to_close = NULL;
    pthread_mutex_lock(&g_udp_hash_lock);
    for (int b = 0; b < UDP_HASH_BUCKETS; b++) {
        udp_sess_t *s = g.udp_hash[b];
        g.udp_hash[b] = NULL;
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
}

void udp_idle_gc(time_t now) {
    udp_sess_t *garbage[MAX_EVENTS];
    int gc = 0;
    pthread_mutex_lock(&g_udp_hash_lock);
    for (int b = 0; b < UDP_HASH_BUCKETS; b++) {
        udp_sess_t **pp = &g.udp_hash[b];
        while (*pp) {
            udp_sess_t *s = *pp;
            // 垃圾桶滿了就跳過該 session，下一輪再收
            if (udp_is_idle(now, s->last_active) && gc < MAX_EVENTS) {
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
}
