// tcp_sess.c — TCP session 管理（抽離自 tun_socks.c）
// 內建 TCP 狀態機：SYN/SYN-ACK、序號追蹤、Window Scale 流量控制、回壓、
// SOCKS5 CONNECT 背景握手、DNS-over-TCP 攔截、兩階段釋放。
// 函式本體原封不動，僅改作用域；epoll 事件入口為 tcp_handle_event。
#include "engine.h"
#include "tcp_packet.h"
#include "tcp_state.h"
#include "tcp_buf.h"
#include "socks5_codec.h"
#include "dns_tcp.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

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

// 送出 TCP 封包給 App（以 App 觀點：saddr/daddr 為 IP 位址，sport/dport 為埠）
// seq/ack 以 host byte order 傳入，內部轉網路序寫出
static ssize_t write_tcp_to_tun(const ip_addr_t *saddr, const ip_addr_t *daddr,
                                uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const unsigned char *payload, size_t plen,
                                uint16_t win) {
    unsigned char pkt[TUN_MTU];
    ssize_t total = tcp_build_segment(saddr->ip, daddr->ip, saddr->family,
                                      sport, dport, seq, ack, flags,
                                      payload, plen, win, pkt, sizeof pkt);
    if (total < 0) return -1;
    ssize_t w = write(g.tun_fd, pkt, (size_t)total);
    atomic_fetch_add(&g.tun_write_total, 1);
    if (w < 0) {
        // 靜默丟棄＝App 永遠等不到這個 ACK/資料 → 只能靠 RTO 重傳（診斷：量它有多大）
        if (errno == EAGAIN || errno == EWOULDBLOCK) atomic_fetch_add(&g.tun_write_eagain, 1);
        else LOGE("write tun tcp failed: %s", strerror(errno));
    }
    return w;
}

static void send_tcp_synack(tcp_sess_t *sess) {
    if (g.tun_fd < 0) return;
    int is6 = (sess->src_ip.family == AF_INET6);
    unsigned char pkt[TUN_MTU];
    uint16_t mss = (uint16_t)(TUN_MTU - (is6 ? 60 : 40));
    uint16_t win = (uint16_t)(TCP_APP_BUF_CAP >> 10);
    ssize_t total = tcp_build_synack(sess->dst_ip.ip, sess->src_ip.ip, sess->src_ip.family,
                                     sess->dst_port, sess->src_port,
                                     sess->srv_isn, sess->app_next,
                                     win, mss, 10,
                                     pkt, sizeof pkt);
    if (total < 0) { LOGE("synack build failed"); return; }
    ssize_t w = write(g.tun_fd, pkt, (size_t)total);
    if (w < 0) LOGE("write tun SYN-ACK failed: %s (errno=%d)", strerror(errno), errno);
    else if (w != total) LOGI("write tun SYN-ACK partial %zd/%zd", w, total);
}

// 引擎對 App 通告的接收 window：app_buf 還能收多少（SYNACK 協商 shift=10，單位 1KB）
// 用 app_len（尚未送出的位元組）而非 app_off+app_len（含已送出前綴的佔用率）：
// app_buf_reserve 需要時會 compaction 回收前綴，故真正可用空間是 cap-app_len。
// 用佔用率會讓「已部分排空」仍通告 0（off 不減、len 減，和可能不變）→ App 卡在零窗。
static uint16_t tcp_win_field(const tcp_sess_t *sess) {
    return tcp_win_field_pure(sess->app_len, TCP_APP_BUF_CAP);
}

static void send_tcp_ack(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x10, NULL, 0, tcp_win_field(sess));
}

static void send_tcp_fin(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x11, NULL, 0, tcp_win_field(sess));
}

// RST 的 seq 必須是「伺服器下一個序號」（＝ App 的 RCV.NXT），與 send_tcp_fin/send_tcp_ack 一致。
// ⚠️ 這裡曾寫死 0：App 的 TCP 堆疊依 RFC 5961 §3.2 只對「seq == RCV.NXT」的 RST 重置連線，
// 其餘一律回 challenge ACK 並丟棄 → App 完全收不到「連線已斷」的通知，只能等自己的 RTO
// （實測 DoT 長連線要 3 分 38 秒）。2026-09-28 由 tun_engine_test 的
// 「soft reconnect RST seq = srv_next」斷言抓到（之前只驗 RST 旗標，沒驗 seq）。
static void send_session_rst(tcp_sess_t *sess) {
    write_tcp_to_tun(&sess->dst_ip, &sess->src_ip, sess->dst_port, sess->src_port,
                     sess->srv_next, sess->app_next, 0x14, NULL, 0, 0);
}

// engine 單一執行緒呼叫（唯一釋放 session 之處，background 線程不碰 hash）
// 兩階段釋放：若背景 connect 線程尚未結束（thread_done==0），先移入 graveyard，
// 由 engine_loop 每輪結尾的 tcp_graveyard_collect() 在 thread_done==1 後真正 free。
static void tcp_session_destroy(tcp_sess_t *sess) {
    unsigned idx = tcp_hash_idx(&sess->src_ip, sess->src_port);
    tcp_sess_t **pp = &g.tcp_hash[idx];
    while (*pp && *pp != sess) pp = &(*pp)->next;
    if (!*pp) {
        // 已不在 hash（可能已進 graveyard）→ 防止 double free
        LOGE("tcp_session_destroy: session 不在 hash，跳過釋放");
        return;
    }
    *pp = sess->next;
    // 一律移入 graveyard，由 tcp_graveyard_collect()（每批 epoll 事件處理完）統一 free。
    // 若 thread_done==1 時立即 free，本批事件中殘留的同 session 事件會讀到已釋放記憶體（UAF）。
    // srv_fd 不在這裡關閉：背景 connect 線程可能在 session 停放後才 store srv_fd / epoll ADD，
    // 提前 release 會造成 fd 重用 UAF；改由 tcp_graveyard_collect()（thread_done==1 後）統一關閉。
    sess->next = g.tcp_graveyard;
    g.tcp_graveyard = sess;
}

void tcp_graveyard_collect(void) {
    tcp_sess_t **pp = &g.tcp_graveyard;
    while (*pp) {
        tcp_sess_t *s = *pp;
        if (atomic_load(&s->thread_done)) {
            *pp = s->next;
            // 背景 connect 線程已結束：此處才安全關閉 srv_fd（可能於停放後才 store）
            int fd = atomic_load(&s->srv_fd);
            if (fd >= 0) {
                if (g.epoll_fd >= 0) epoll_ctl(g.epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                release_java_socket(fd);
                atomic_store(&s->srv_fd, -1);
            }
            free(s->app_buf);
            free(s->srv_buf);
            free(s->dns_rx_buf);
            free(s);
            atomic_fetch_sub(&g.tcp_session_count, 1);
        } else {
            pp = &s->next;
        }
    }
}

// engine 單一執行緒呼叫（唯一釋放 session 之處，background 線程不碰 hash）
static void close_tcp_session(tcp_sess_t *sess, int send_rst) {
    if (sess->closed) return;
    sess->closed = 1;
    // 一併印出送出的 RST seq：這正是能抓到「rst_seq 寫死 0」缺陷的觀測點。
    LOGI("tcp session 關閉 app_bytes=%u srv_bytes=%u rst=%d rst_seq=%u max_app_len=%zu ooo=%u full_events=%d tun_wr=%llu/%llu",
         (uint32_t)(sess->app_next - sess->app_isn - 1),
         (uint32_t)(sess->srv_next - sess->srv_isn - 1), send_rst, sess->srv_next,
         sess->app_max_len, sess->app_ooo_segs, atomic_load(&g.tcp_app_buf_full_events),
         (unsigned long long)atomic_load(&g.tun_write_eagain),
         (unsigned long long)atomic_load(&g.tun_write_total));
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
    epoll_ctl(g.epoll_fd, EPOLL_CTL_MOD, fd, &ev);
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
    if (g.tun_want_out == enable || g.tun_fd < 0 || g.epoll_fd < 0) return;
    g.tun_want_out = enable;
    struct epoll_event ev;
    ev.events = EPOLLIN | (enable ? EPOLLOUT : 0);
    ev.data.fd = g.tun_fd;
    epoll_ctl(g.epoll_fd, EPOLL_CTL_MOD, g.tun_fd, &ev);
}

// server→App：把緩衝的資料切成 TCP segment 寫回 TUN
static void flush_tcp_srv_buf(tcp_sess_t *sess) {
    while (sess->srv_len > 0) {
        size_t seg_max = (sess->src_ip.family == AF_INET6) ? (TUN_MTU - 60) : (TUN_MTU - 40);
        size_t chunk = sess->srv_len;
        if (chunk > seg_max) chunk = seg_max;
        // 流量控制：App 通告 window 已滿 → 暫停送出，等 App ACK 開窗
        if (tcp_flow_window_full(sess->srv_next, sess->app_acked, sess->app_win)) break;
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
    if (tcp_buf_should_compact_half(sess->srv_off, TCP_SRV_BUF_CAP)) {
        memmove(sess->srv_buf, sess->srv_buf + sess->srv_off, sess->srv_len);
        sess->srv_off = 0;
    }
    if (sess->srv_in_off && sess->srv_len < TCP_SRV_BUF_CAP / 2) set_srv_in(sess, 1);
    if (tcp_srv_should_send_fin(sess->srv_eof, sess->srv_len, sess->srv_fin_sent)) {
        sess->srv_fin_sent = 1;
        send_tcp_fin(sess);
    }
}

// 零視窗狀態解除（app_buf 已有空間）：清旗標並留一行 log。
// 實機診斷靠這一行確認「回壓真的發生過、而且真的結束了」（配對的進入點是 app_buf_accept）。
static void app_buf_clear_full(tcp_sess_t *sess) {
    if (!sess->app_buf_full) return;
    sess->app_buf_full = 0;
    LOGI("app_buf 已排空，零視窗解除 (len=%zu full_events=%d)",
         sess->app_len, atomic_load(&g.tcp_app_buf_full_events));
}

// App→server：把緩衝的資料寫到 srv_fd（fatal 只標記 closed，不釋放）
static void flush_tcp_app_buf(tcp_sess_t *sess) {
    int fd = atomic_load(&sess->srv_fd);
    if (fd < 0) return;
    size_t before = sess->app_len;
    while (sess->app_len > 0) {
        ssize_t n = send(fd, sess->app_buf + sess->app_off, sess->app_len, MSG_NOSIGNAL);
        if (n > 0) {
            atomic_fetch_add(&g.bytes_to_server, (unsigned long long)n);
            sess->app_off += (size_t)n;
            sess->app_len -= (size_t)n;
            if (sess->app_len == 0) sess->app_off = 0;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // srv socket 暫時寫不動：註冊 EPOLLOUT，可寫時再續送。
            // 不可只靠後續的 TUN/kick 事件喚醒 —— App 收到零視窗後不會再送資料，
            // 少了這個註冊就會永遠停在「有資料待送、卻沒有任何事件」的狀態。
            set_srv_out(sess, 1);
            break;
        } else {
            sess->closed = 1;
            return;
        }
    }
    if (sess->app_len == 0) {
        set_srv_out(sess, 0);
        if (tcp_app_can_shutdown_write(sess->app_fin, sess->app_len)) shutdown(fd, SHUT_WR);
    }
    // 排空後重開 window：主動送 window-update ACK，避免 App 停在縮小的窗上死鎖。
    // （window 由 app_len 推算，故排空必然讓 window 變大；這裡保證一定送出那個更新）
    if (sess->app_len < before && !sess->closed && atomic_load(&sess->state) == 1) {
        if (tcp_win_field(sess) > 0) app_buf_clear_full(sess);
        send_tcp_ack(sess);
    }
}

// 在 app_buf 尾部保留 need 位元組空間（不足時先 compact）；回傳寫入位置或 NULL
static unsigned char *app_buf_reserve(tcp_sess_t *sess, size_t need) {
    if (sess->app_buf == NULL) sess->app_buf = malloc(TCP_APP_BUF_CAP);
    if (!sess->app_buf) return NULL;
    // 攤銷 compaction（與 srv 方向一致）：已送出前綴過半才搬移。
    // 舊版用 tcp_buf_reserve_should_compact（off>0 就搬）＝每個上傳封包都 memmove
    // 整個待送緩衝（最大 4 MiB），上傳專屬的額外開銷。
    if (tcp_buf_should_compact_half(sess->app_off, TCP_APP_BUF_CAP)) {
        memmove(sess->app_buf, sess->app_buf + sess->app_off, sess->app_len);
        sess->app_off = 0;
    }
    // 攤銷門檻未到但尾端放不下 → 立即搬一次（前綴非空時），
    // 否則會把「前面有空間」誤報成「緩衝滿」而白白通告零視窗。
    if (!tcp_buf_reserve_fits(sess->app_off, sess->app_len, TCP_APP_BUF_CAP, need) &&
        tcp_buf_reserve_should_compact(sess->app_off, sess->app_len)) {
        memmove(sess->app_buf, sess->app_buf + sess->app_off, sess->app_len);
        sess->app_off = 0;
    }
    if (!tcp_buf_reserve_fits(sess->app_off, sess->app_len, TCP_APP_BUF_CAP, need)) return NULL;
    return sess->app_buf + sess->app_off + sess->app_len;
}

// 收下一個 App→server 的 payload 進入 app_buf。
// 緩衝真的滿時仍然送出 ACK，通告目前（可能為 0）的接收視窗 —— 讓 App 看到的是
// 「流控」而不是「封包遺失」。舊版在此完全不 ACK，App 只能靠 RTO 重傳，
// cwnd 被砍到 1，上傳吞吐反覆掉回慢啟動爬升期（上傳卡死的主因）。
static void app_buf_accept(tcp_sess_t *sess, const unsigned char *payload, size_t payload_len) {
    unsigned char *dst = app_buf_reserve(sess, payload_len);
    if (!dst) {
        flush_tcp_app_buf(sess);
        if (sess->closed) return;
        dst = app_buf_reserve(sess, payload_len);
    }
    if (dst) {
        memcpy(dst, payload, payload_len);
        sess->app_len += payload_len;
        if (sess->app_len > sess->app_max_len) sess->app_max_len = sess->app_len;  // 診斷
        sess->app_next += (uint32_t)payload_len;
        send_tcp_ack(sess);
        if (atomic_load(&sess->state) == 1) set_srv_out(sess, 1);
    } else {
        // 真的滿：ACK（不推進 app_next）並帶目前 window（0）＝零視窗回壓。
        atomic_fetch_add(&g.tcp_app_buf_full_events, 1);
        if (!sess->app_buf_full) {
            sess->app_buf_full = 1;
            LOGI("app_buf 滿 (cap=%d)，通告零視窗等待排空", TCP_APP_BUF_CAP);
        }
        send_tcp_ack(sess);
    }
}

void tcp_flush_all(void) {
    int any_pending = 0;
    for (int b = 0; b < TCP_HASH_BUCKETS; b++) {
        tcp_sess_t *s = g.tcp_hash[b];
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
void tcp_sweep(void) {
    tcp_sess_t *garbage[128];
    int gc = 0;
    for (int b = 0; b < TCP_HASH_BUCKETS && gc < 128; b++) {
        for (tcp_sess_t *s = g.tcp_hash[b]; s && gc < 128; s = s->next) {
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
    int fail_code = SE_EVENT_NETWORK_FAIL;   // 事件分類碼：明確拒絕（auth/REP≠0/非 SOCKS5）時改為對應碼，不觸發看門狗

    char srv_host[256]; int srv_port;
    srv_snapshot(srv_host, sizeof srv_host, &srv_port);
    sfd = request_java_socket(srv_host, srv_port, 0);
    if (sfd < 0) goto fail;
    if (!g.running) { fail_code = SE_EVENT_NONE; goto fail; }
    set_nonblocking(sfd);

    // SOCKS5 greeting + 選擇性 RFC 1929 認證（與 UDP ASSOCIATE 共用 helper）
    int hs = socks5_greet_auth(sfd, net_send_all, net_recv_all, buf, sizeof buf);
    if (hs != 0) { fail_code = hs; goto fail; }

    unsigned char req[300];
    int req_len = socks5_build_connect_request(
        sess->dst_ip.ip, sess->dst_ip.family, sess->dst_port,
        sess->dst_domain[0] ? sess->dst_domain : NULL,
        req, sizeof req);
    if (req_len < 0) { fail_code = SE_EVENT_PROTOCOL_FAIL; goto fail; }
    if (net_send_all(sfd, req, (size_t)req_len) < 0) goto fail;
    if (net_recv_all(sfd, buf, 4) < 0) goto fail;
    if (buf[0] != 0x05 || buf[1] != 0x00) { fail_code = SE_EVENT_PROTOCOL_FAIL; goto fail; }   // REP≠0：伺服器端結果，非網路斷線
    int atyp = buf[3];
    int bnd_len = socks5_atyp_bnd_len(atyp);
    if (bnd_len == -2) {
        // 0x03 變長網域：先讀 1-byte 長度，再讀 len+2
        unsigned char al;
        if (net_recv_all(sfd, buf, 1) < 0) goto fail;
        al = buf[0];
        if (net_recv_all(sfd, buf, al + 2) < 0) goto fail;
    } else if (bnd_len > 0) {
        if (net_recv_all(sfd, buf, bnd_len) < 0) goto fail;
    } else {   // -1：未知 ATYP
        fail_code = SE_EVENT_PROTOCOL_FAIL;
        goto fail;
    }

    atomic_store(&sess->srv_fd, sfd);
    fd_stored = 1;
    atomic_store(&sess->state, 1);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
    ev.data.ptr = (tcp_sess_t *)((uintptr_t)sess | 3);
    if (epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
        // fd 已交予 engine（srv_fd=sfd），engine 銷毀時會關閉，線程不再 close
        atomic_store(&sess->handshake_failed, 1);
        if (g.kick_pipe[1] >= 0) { char k = 1; write(g.kick_pipe[1], &k, 1); }
        goto done;
    }
    if (g.kick_pipe[1] >= 0) { char k = 1; write(g.kick_pipe[1], &k, 1); }
    char b1[64];
    ip_to_str(&sess->dst_ip, b1, sizeof b1);
    LOGI("tcp connect 完成 -> %s:%d", b1, ntohs(sess->dst_port));
    notify_server_event(SE_EVENT_OK);
    goto done;

fail:
    ip_to_str(&sess->dst_ip, b1, sizeof b1);
    LOGI("tcp connect 失敗 -> %s:%d", b1, ntohs(sess->dst_port));
    if (fail_code != SE_EVENT_NONE) notify_server_event(fail_code);
    // 只有 store 前（fd_stored==0）的失敗才由線程 close；store 後 fd 屬 engine 所有
    if (sfd >= 0 && !fd_stored) { release_java_socket(sfd); }
    if (g.tun_fd >= 0) send_session_rst(sess);
    atomic_store(&sess->handshake_failed, 1);
    if (g.kick_pipe[1] >= 0) { char k = 1; write(g.kick_pipe[1], &k, 1); }

done:
    atomic_store(&sess->thread_done, 1);   // 先標記，engine 才可安全 free（shutdown 等 inflight==0）
    atomic_fetch_sub(&g.handshake_inflight, 1);
    return NULL;
}

// DNS-over-TCP：把 [2-byte 長度前綴 + DNS 回覆] 排入 srv_buf（server→app 緩衝）
static void dns_tcp_emit(tcp_sess_t *sess, const unsigned char *reply, size_t rlen) {
    size_t total = 2 + rlen;
    if (sess->srv_buf == NULL) sess->srv_buf = malloc(TCP_SRV_BUF_CAP);
    if (!sess->srv_buf) { close_tcp_session(sess, 1); return; }
    if (sess->srv_off > 0 && sess->srv_len > 0) {
        memmove(sess->srv_buf, sess->srv_buf + sess->srv_off, sess->srv_len);
        sess->srv_off = 0;
    }
    if (sess->srv_off + sess->srv_len + total > TCP_SRV_BUF_CAP) {
        close_tcp_session(sess, 1);   // DNS 回覆極小，緩衝滿視為異常
        return;
    }
    unsigned char *dst = sess->srv_buf + sess->srv_off + sess->srv_len;
    dst[0] = (unsigned char)(rlen >> 8);
    dst[1] = (unsigned char)(rlen & 0xFF);
    memcpy(dst + 2, reply, rlen);
    sess->srv_len += total;
}

// 處理 DNS-over-TCP 的 inbound 串流（[2-byte 長度 + DNS message] 重複）：
// 對每個完整 query 合成 fake 回覆並排入 srv_buf；全部回覆後送 FIN 關閉。
static void dns_tcp_ingest(tcp_sess_t *sess, const unsigned char *data, size_t len) {
    // 1. 追加到累積緩衝
    size_t need = sess->dns_rx_len + len;
    if (need > sess->dns_rx_cap) {
        size_t ncap = sess->dns_rx_cap ? sess->dns_rx_cap * 2 : 1024;
        while (ncap < need) ncap *= 2;
        unsigned char *nb = realloc(sess->dns_rx_buf, ncap);
        if (!nb) { close_tcp_session(sess, 1); return; }
        sess->dns_rx_buf = nb;
        sess->dns_rx_cap = ncap;
    }
    memcpy(sess->dns_rx_buf + sess->dns_rx_len, data, len);
    sess->dns_rx_len = need;

    // 2. 掃描完整 frame（純長度解析在 dns_tcp.c），再逐一合成回覆
    size_t off = dns_tcp_scan_frames(sess->dns_rx_buf, sess->dns_rx_len);
    size_t p = 0;
    while (p + 2 <= off) {
        size_t mlen = dns_tcp_frame_len(sess->dns_rx_buf + p);
        unsigned char reply[512];
        size_t rlen = 0;
        if (dns_build_reply(sess->dns_rx_buf + p + 2, mlen, 1, reply, &rlen))
            dns_tcp_emit(sess, reply, rlen);
        p += 2 + mlen;
    }
    // 3. 移除已處理的前綴
    if (off > 0) {
        memmove(sess->dns_rx_buf, sess->dns_rx_buf + off, sess->dns_rx_len - off);
        sess->dns_rx_len -= off;
    }

    // 4. ACK 收到的資料；若已無殘留 query，回覆排空後送 FIN
    sess->app_next += (uint32_t)len;
    send_tcp_ack(sess);
    if (sess->dns_rx_len == 0) sess->srv_eof = 1;
}

// 處理來自 TUN 的 TCP 封包（P2 TCP 狀態機）
void tcp_handle_packet(const unsigned char *pkt, size_t len, size_t t,
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
    for (tcp_sess_t *s = g.tcp_hash[idx]; s; s = s->next) {
        if (ip_addr_eq(&s->src_ip, src_ip) && s->src_port == sport && !s->closed) { sess = s; break; }
    }

    if (!sess) {
        if (!(flags & 0x02) || (flags & 0x10)) return;   // 僅 SYN 可建立（SYN+ACK 忽略）
        if (atomic_load(&g.tcp_session_count) >= MAX_TCP_SESSIONS) {
            send_tcp_rst(src_ip, dst_ip, pkt + t, len - t);   // 滿載 → RST
            return;
        }
        sess = calloc(1, sizeof(tcp_sess_t));
        if (!sess) return;
        sess->src_ip = *src_ip; sess->src_port = sport;
        sess->dst_ip = *dst_ip; sess->dst_port = dport;
        if (g.remote_dns) {
            // fake IP（v4/v6）→ 記錄網域，connect 線程以 ATYP=0x03 撥號（由伺服器端解析）
            if (dst_ip->family == AF_INET) {
                fd_lookup(fake_dns_key(dst_ip), sess->dst_domain, sizeof(sess->dst_domain));
            } else if (dst_ip->family == AF_INET6) {
                fd_lookup6(dst_ip->ip, sess->dst_domain, sizeof(sess->dst_domain));
            }
        }
        atomic_store(&sess->srv_fd, -1);
        sess->app_isn = seq_host;
        sess->app_next = seq_host + 1;
        sess->srv_isn = next_tcp_isn();
        sess->srv_next = sess->srv_isn + 1;
        sess->app_acked = sess->srv_isn + 1;
        sess->app_win = 0x3FFFFFFF;          // 未知前不限制
        // 解析 App SYN 的 window scale（選項區 = 固定 20B 表頭之後，長度 = tcp_hlen-20）
        sess->app_ws = tcp_parse_window_scale(pkt + t + 20, (size_t)tcp_hlen - 20);
        sess->last_active = time(NULL);
        sess->next = g.tcp_hash[idx];
        g.tcp_hash[idx] = sess;
        atomic_fetch_add(&g.tcp_session_count, 1);

        char b1[64], b2[64];
        ip_to_str(src_ip, b1, sizeof b1);
        ip_to_str(dst_ip, b2, sizeof b2);
        LOGI("tcp session 建立 src=%s:%d -> dst=%s:%d",
             b1, ntohs(sport), b2, ntohs(dport));
        send_tcp_synack(sess);

        // Remote DNS：攔截 DNS-over-TCP（連到 DNS 伺服器 literal IP 的 53/tcp），
        // 由本機合成 fake 回覆，不建立 SOCKS5 連線，避免網域洩漏到真實 DNS。
        if (g.remote_dns && ntohs(dport) == 53 && sess->dst_domain[0] == 0) {
            sess->dns_tcp = 1;
            atomic_store(&sess->state, 1);
            return;
        }
        if (hs_submit(tcp_connect_thread, sess) != 0) close_tcp_session(sess, 1);
        return;
    }

    if (atomic_load(&sess->handshake_failed)) {
        if ((flags & 0x02) && !(flags & 0x10)) {
            close_tcp_session(sess, 0);                    // 取代失敗的舊會話
            tcp_handle_packet(pkt, len, t, src_ip, dst_ip);
        }
        return;
    }

    sess->last_active = time(NULL);

    // 更新 App 通告的 window（乘 WS）與 ack，供 srv→App 流量控制
    uint16_t win_field;
    memcpy(&win_field, pkt + t + 14, 2);
    sess->app_win = tcp_win_scaled(ntohs(win_field), sess->app_ws);
    // 迴繞安全比較（RFC1323 式）：單一連線傳輸超過 4GB 後序號迴繞，
    // 普通大小比較會拒絕更新 ack → app_acked 凍結 → 流控誤判窗口耗盡而卡死
    if (tcp_seq_gt(ack_host, sess->app_acked)) sess->app_acked = ack_host;

    switch (tcp_classify_in(flags, seq_host, sess->app_next, payload_len, sess->srv_fin_sent)) {
    case TCP_IN_SYN_ONLY:                                  // SYN 重傳
        if (atomic_load(&sess->state) == 0) send_tcp_synack(sess);
        return;
    case TCP_IN_RST: {                                     // RST
        char b1[64];
        ip_to_str(src_ip, b1, sizeof b1);
        LOGI("tcp RST from app state=%d %s:%d", atomic_load(&sess->state),
             b1, ntohs(sport));
        close_tcp_session(sess, 0);
        return;
    }
    case TCP_IN_OUT_OF_ORDER: {                            // 亂序 / 重傳 → 重複 ACK
        sess->app_ooo_segs++;                              // 診斷：App 端重傳／亂序段數
        send_tcp_ack(sess);
        if (sess->srv_len > 0) flush_tcp_srv_buf(sess);    // dup-ACK 仍可能開窗
        return;
    }
    case TCP_IN_POST_FIN: {                                // 我方已送 FIN
        close_tcp_session(sess, tcp_post_fin_send_rst(payload_len));
        return;
    }
    case TCP_IN_PURE_ACK: {                                // 純 ACK（FIN 需先送進 FIN 分支處理）
        if (sess->srv_len > 0) flush_tcp_srv_buf(sess);    // ACK 開窗 → 續送
        return;
    }
    case TCP_IN_FALLTHROUGH:
        break;
    }

    if (payload_len > 0) {
        if (sess->dns_tcp) {
            dns_tcp_ingest(sess, pkt + t + (size_t)tcp_hlen, payload_len);
            flush_tcp_srv_buf(sess);
            return;
        }
        if (atomic_load(&sess->state) == 1) {
            int sfd = atomic_load(&sess->srv_fd);
            if (sfd < 0) return;
        }
        // 一律先入 app_buf 再 flush：直接 send 遇到 partial 時，App 重傳餘數會被重複接受。
        // CONNECT 中（state=0）同樣先緩衝，建立後由 kick 觸發 flush；
        // 兩種狀態下緩衝滿都改為回零視窗 ACK（見 app_buf_accept），不再沉默不 ACK。
        app_buf_accept(sess, pkt + t + (size_t)tcp_hlen, payload_len);
    }

    if (flags & 0x01) {                                    // FIN
        LOGI("tcp FIN from app (app_next=%u srv_next=%u)", sess->app_next, sess->srv_next);
        sess->app_next += 1;
        sess->app_fin = 1;
        send_tcp_ack(sess);
        if (sess->srv_fin_sent) { close_tcp_session(sess, 0); return; }
        if (tcp_app_can_shutdown_write(sess->app_fin, sess->app_len)) {
            int sfd = atomic_load(&sess->srv_fd);
            if (sfd >= 0) shutdown(sfd, SHUT_WR);
        }
        if (tcp_server_drained(sess->srv_eof, sess->srv_len)) close_tcp_session(sess, 0);
    }

    if (sess->srv_len > 0) {                               // App ACK/開窗 → 續送
        flush_tcp_srv_buf(sess);
    }
}

// srv_fd 事件：server→App 資料 / EOF / 可寫
void tcp_handle_event(tcp_sess_t *sess, uint32_t ev, time_t now) {
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
        // EPOLLHUP 常伴隨「本端已 SHUT_WR、對端完整關閉」的收尾出現（半關後的全關）。
        // 若在此直接 RST 會丟掉 EOF 訊號，使 App 收不到對側 FIN；交由下方 recv 迴圈
        // 分辨：recv==0 為乾淨 EOF（srv_eof→送 FIN），recv<0 且非 EAGAIN 才是真錯誤。
        if (ev & EPOLLERR) { close_tcp_session(sess, 1); return; }
        for (;;) {
            if (sess->srv_buf == NULL) sess->srv_buf = malloc(TCP_SRV_BUF_CAP);
            if (!sess->srv_buf) { close_tcp_session(sess, 1); return; }
            // 前綴已送出超過一半 → 搬移回收空間（分攤成本）
            if (tcp_buf_should_compact_half(sess->srv_off, TCP_SRV_BUF_CAP)) {
                memmove(sess->srv_buf, sess->srv_buf + sess->srv_off, sess->srv_len);
                sess->srv_off = 0;
            }
            size_t used = sess->srv_off + sess->srv_len;
            if (tcp_buf_full(sess->srv_off, sess->srv_len, TCP_SRV_BUF_CAP)) {
                // 緩衝滿：暫停讀取，等 App 消化後（flush 內）再續，靠 relay TCP 回壓
                if (tcp_recv_full_should_close(sess->srv_len)) { close_tcp_session(sess, 1); return; }
                set_srv_in(sess, 0);
                break;
            }
            size_t want = tcp_buf_recv_want(sess->srv_off, sess->srv_len, TCP_SRV_BUF_CAP, TCP_READ_CHUNK);
            ssize_t r = recv(sfd, sess->srv_buf + used, want, 0);
            if (r > 0) {
                atomic_fetch_add(&g.bytes_from_server, (unsigned long long)r);
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

// ---------- 入口：soft reset / shutdown / idle GC ----------

// soft-reset：不拆 TUN，但**必須對 App 送 RST**。
// ⚠️ 這裡曾直接 `s->closed = 1; tcp_session_destroy(s);` —— 等於把 App 的連線「無聲切斷」：
// App 的 TCP 堆疊仍以為連線活著（實例：Android 私人 DNS 的 DoT 長連線），會繼續把查詢送
// 進黑洞，只能等自己的 RTO 超時才重撥。2026-09-28 實測：Wi-Fi 開關後 DoT 整整 3 分 38 秒
// 沒有重撥（引擎連 SYN 都沒收到）→ 整台機 DNS 全死、IP 直連卻正常；而「重建隧道」之所以
// 有效，正是因為換掉 tun fd 讓 App 立刻察覺介面消失。
// 走 close_tcp_session(s, 1) 才會送 RST，並沿用既有的兩階段釋放。
void tcp_soft_reset(void) {
    int rst_sent = 0;
    for (int b = 0; b < TCP_HASH_BUCKETS; b++) {
        while (g.tcp_hash[b]) {
            tcp_sess_t *s = g.tcp_hash[b];
            // 已 closed 者不再送 RST（close_tcp_session 會 early-return，留在 hash 裡
            // 會造成無限迴圈），直接回收即可。
            if (s->closed) {
                tcp_session_destroy(s);
            } else {
                close_tcp_session(s, 1);
                rst_sent++;
            }
        }
    }
    tcp_graveyard_collect();
    // 觀測點：soft reset 過去完全靜默（正是缺陷 2 的成因）。印出送了幾條 RST，
    // 才能在實機上區分「送 RST 的新版」與「無聲切斷的舊版」。
    LOGI("soft reset 完成：對 %d 條 App 連線送 RST", rst_sent);
}

void tcp_shutdown_collect(void) {
    tcp_graveyard_collect();
    // 關閉所有 TCP session（thread 已 join，無並發）。
    // 注意：不可先清空 hash 再釋放——tcp_session_destroy 會回查 hash 做 unlink，
    // 預先清空會造成「不在 hash」誤判（fd 也沒關，重啟累積 leak）。
    for (int b = 0; b < TCP_HASH_BUCKETS; b++) {
        while (g.tcp_hash[b]) {
            tcp_sess_t *s = g.tcp_hash[b];
            s->closed = 1;
            tcp_session_destroy(s);
        }
    }
    // 最後一次回收：等待後線程已結束的 session 在此釋放；
    // 5 秒等待超時的（極端情況）留在 graveyard，引擎已停止不再回收
    tcp_graveyard_collect();
}

void tcp_idle_gc(time_t now) {
    tcp_sess_t *tcp_garbage[MAX_EVENTS];
    int tgc = 0;
    for (int b = 0; b < TCP_HASH_BUCKETS && tgc < MAX_EVENTS; b++) {
        for (tcp_sess_t *s = g.tcp_hash[b]; s && tgc < MAX_EVENTS; s = s->next) {
            int idle = !s->closed && tcp_is_idle(atomic_load(&s->state), now, s->last_active);
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
