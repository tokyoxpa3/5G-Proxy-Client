// tun_socks.c — 客戶端 TUN → SOCKS5 引擎
// 流量路徑:
//   [App] --TUN--> 本引擎解析封包 --SOCKS5--> [SOCKS5 伺服器] --> [目標]
//   UDP/DNS/QUIC：SOCKS5 UDP ASSOCIATE relay
//   TCP：內建 TCP 狀態機，經 SOCKS5 CONNECT 轉發
//
// 本檔只保留：TUN 讀寫與封包分派、epoll 主迴圈、ICMP/ICMPv6 本機回應、
// IP 分片重組 glue、engine 生命週期與 JNI 對外介面。
// TCP/UDP session 管理在 tcp_sess.c / udp_sess.c，handshake 執行緒池在 hs_pool.c，
// 共用 helper 在 engine_util.c，型別與常數在 engine.h。
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "engine.h"
#include "reasm.h"
#include "icmp_packet.h"

static pthread_t g_engine_thread;
static atomic_int g_reset_requested = 0;

// 單一引擎實例（單一隧道）。
engine_ctx_t g;

// ---------- IP 分片重組 glue（stateful 重組表在 reasm.c） ----------
static reasm_table_t g_reasm;

static void handle_tun_packet(const unsigned char *pkt, size_t len);

static void reasm_emit(const unsigned char *out, size_t outlen, void *ctx) {
    (void)ctx;
    handle_tun_packet(out, outlen);
}

static void reasm_dispatch(uint8_t family, const ip_addr_t *src, const ip_addr_t *dst,
                           uint8_t proto, uint32_t id,
                           size_t offset, const unsigned char *data, size_t dlen, int mf,
                           const unsigned char *ip_hdr, size_t ip_hdr_len, size_t patch_off) {
    reasm_table_insert(&g_reasm, family, src, dst, proto, id,
                       offset, data, dlen, mf,
                       ip_hdr, ip_hdr_len, patch_off,
                       time(NULL), reasm_emit, NULL);
}

static void reasm_gc(time_t now) {
    reasm_table_gc(&g_reasm, now);
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
    ssize_t total = icmp4_build_echo_reply(pkt, len, ihl, daddr->ip, saddr->ip, reply, sizeof reply);
    if (total < 0) return;
    ssize_t w = write(g.tun_fd, reply, (size_t)total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun icmp4 failed: %s", strerror(errno));
}

// IPv6 ICMPv6 echo request → 本機回 echo reply
static void handle_icmp6(const unsigned char *pkt, size_t len,
                         const ip_addr_t *saddr, const ip_addr_t *daddr) {
    if (len < 48 || len > TUN_MTU) return;
    if (pkt[40] != 128 || pkt[41] != 0) return;   // 僅處理 echo request
    unsigned char reply[TUN_MTU];
    ssize_t total = icmp6_build_echo_reply(pkt, len, daddr->ip, saddr->ip, reply, sizeof reply);
    if (total < 0) return;
    ssize_t w = write(g.tun_fd, reply, (size_t)total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun icmp6 failed: %s", strerror(errno));
}

// ICMPv6 Neighbor Solicitation → 回 Neighbor Advertisement（type 135→136）。
// TUN 為 point-to-point，但部分裝置仍會對 fd00::/8 做 NDP 解析；
// 對 fd00::/8 的 NS 宣告擁有權，讓雙棧 App 以 fake IPv6 連線時不卡在解析。
static void handle_icmp6_ns(const unsigned char *pkt, size_t len, const ip_addr_t *saddr) {
    if (len < 64) return;
    if (pkt[40] != 135 || pkt[41] != 0) return;
    // DAD（來源為 ::）不回覆
    int unspec = 1;
    for (int i = 0; i < 16; i++) if (saddr->ip[i]) { unspec = 0; break; }
    if (unspec) return;
    const unsigned char *target = pkt + 48;
    if (target[0] != 0xFD) return;   // 僅回應隧道空間 fd00::/8

    unsigned char reply[64];
    ssize_t total = icmp6_build_na(target, saddr->ip, reply, sizeof reply);
    if (total < 0) return;
    ssize_t w = write(g.tun_fd, reply, (size_t)total);
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) LOGE("write tun icmp6 NA failed: %s", strerror(errno));
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
        // 分片：MF 或 offset != 0 → 交重組（常見於大型 UDP）
        {
            uint16_t ff = (uint16_t)((pkt[6] << 8) | pkt[7]);
            uint16_t off = ff & 0x1FFF;
            int mf = (ff & 0x2000) != 0;
            if (off != 0 || mf) {
                uint32_t id = (uint16_t)((pkt[4] << 8) | pkt[5]);
                reasm_dispatch(AF_INET, &saddr, &daddr, proto, id,
                               (size_t)off * 8, pkt + ihl, len - (size_t)ihl, mf,
                               pkt, (size_t)ihl, 0);
                return;
            }
        }
        if (proto == 17) {
            udp_handle_packet(pkt, len, (size_t)ihl, &saddr, &daddr);
        } else if (proto == 6) {
            tcp_handle_packet(pkt, len, (size_t)ihl, &saddr, &daddr);
        } else if (proto == 1) {
            handle_icmp4(pkt, len, ihl, &saddr, &daddr);
        }
        return;
    }
    if (ver == 6) {
        uint8_t fnh; size_t foff; int fmf; uint32_t fid;
        size_t fdata_off, pre_len, patch_off;
        int fr = ipv6_find_fragment(pkt, len, &fnh, &foff, &fmf, &fid,
                                    &fdata_off, &pre_len, &patch_off);
        if (fr == 1) {
            ip_addr_t saddr, daddr;
            saddr.family = AF_INET6; memcpy(saddr.ip, pkt + 8, 16);
            daddr.family = AF_INET6; memcpy(daddr.ip, pkt + 24, 16);
            reasm_dispatch(AF_INET6, &saddr, &daddr, fnh, fid, foff,
                           pkt + fdata_off, len - fdata_off, fmf, pkt, pre_len, patch_off);
            return;
        }
        uint8_t proto;
        ip_addr_t saddr, daddr;
        size_t l4off;
        if (parse_ipv6(pkt, len, &proto, &saddr, &daddr, &l4off) < 0) return;
        if (proto == 17) {
            udp_handle_packet(pkt, len, l4off, &saddr, &daddr);
        } else if (proto == 6) {
            tcp_handle_packet(pkt, len, l4off, &saddr, &daddr);
        } else if (proto == 58) {
            if (l4off == 40) {
                handle_icmp6(pkt, len, &saddr, &daddr);
                handle_icmp6_ns(pkt, len, &saddr);
            }
        }
        return;
    }
}

static void read_tun_packets(void) {
    unsigned char pkt[MAX_PACKET_SIZE];
    for (;;) {
        ssize_t n = read(g.tun_fd, pkt, sizeof pkt);
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

// soft-reconnect：不拆 TUN/VPN 介面，在引擎執行緒內重置所有連線狀態。
// 所有 TCP/UDP session 標記關閉並停放 graveyard，交由既有的兩階段釋放
//（thread_done==1 後才 close fds / free）回收；背景 connect/handshake 線程結束時
// 自行遞減 handshake_inflight，故此處不得清零 session count / handshake_inflight。
static void engine_soft_reset(void) {
    tcp_soft_reset();
    udp_soft_reset();

    // 重設統計與快取（沿用 engine_ctx_reset 語意，但「不」清 session count / handshake_inflight）
    atomic_store(&g.bytes_to_server, 0);
    atomic_store(&g.bytes_from_server, 0);
    g.isn_counter = 0;
    engine_fake_dns_reset();
    reasm_table_clear(&g_reasm);

    LOGI("soft reconnect: 已重置所有 session（保留 TUN/epoll/執行緒）");
}

static void *engine_loop(void *arg) {
    jni_attach_thread();
    struct epoll_event events[MAX_EVENTS];
    time_t last_gc = time(NULL);
    int unexpected_exit = 0;   // 非停止路徑（epoll 錯誤）退出時設 1，shutdown 完成後通知 Java

    while (g.running) {
        // soft-reconnect 要求：重置連線狀態後繼續（TUN/epoll/pipes/執行緒不動）
        if (atomic_exchange(&g_reset_requested, 0)) {
            engine_soft_reset();
        }

        int nfds = epoll_wait(g.epoll_fd, events, MAX_EVENTS, 2000);
        time_t now = time(NULL);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            unexpected_exit = 1;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == g.shutdown_pipe[0]) goto shutdown;
            if (events[i].data.fd == g.tun_fd) { read_tun_packets(); tcp_flush_all(); continue; }
            if (events[i].data.fd == g.kick_pipe[0]) {
                char d[64];
                while (read(g.kick_pipe[0], d, sizeof d) > 0) {}
                tcp_sweep();
                tcp_flush_all();
                continue;
            }

            uintptr_t raw = (uintptr_t)events[i].data.ptr;
            int tag = (int)(raw & 3);
            if (tag == 3) {
                tcp_sess_t *ts = (tcp_sess_t *)(raw & ~(uintptr_t)3);
                if (!ts->closed) tcp_handle_event(ts, events[i].events, now);
                continue;
            }

            udp_sess_t *sess = (udp_sess_t *)(raw & ~(uintptr_t)1);
            udp_handle_event(sess, events[i].events, now, (tag & 1) != 0);
        }

        // 閒置 GC（每 5 秒）
        if (now - last_gc >= 5) {
            last_gc = now;
            reasm_gc(now);
            udp_idle_gc(now);
            tcp_idle_gc(now);
        }

        // 每輪結束：回收兩階段釋放（背景線程已結束）的 session
        tcp_graveyard_collect();
        udp_graveyard_collect();
    }

shutdown:
    // 意外退出（epoll 錯誤等非停止路徑）：清 running，否則 g.running / g_tunnel_running
    // 卡住會讓 Java isRunning 永不歸零、之後無法重啟。正常停止路徑 g.running 已由
    // tun_socks_stop 清為 0，此處只處理意外路徑。
    if (unexpected_exit) g.running = 0;
    // 先關 TUN：VPN 立刻拆除，網路馬上還原（fd 由 native 全權關閉）
    if (g.tun_fd >= 0) { close(g.tun_fd); g.tun_fd = -1; }

    // 等待 handshake 線程結束，避免釋放仍在使用的 session（最多等 5 秒）
    {
        int waited_ms = 0;
        while (atomic_load(&g.handshake_inflight) > 0 && waited_ms < 5000) {
            usleep(100000);
            waited_ms += 100;
        }
    }

    // 排空並 join handshake worker，確保之後 free session 不會有 worker 仍在用
    hs_pool_stop();

    tcp_shutdown_collect();
    udp_shutdown_collect();

    if (g.epoll_fd >= 0) { close(g.epoll_fd); g.epoll_fd = -1; }
    // 清理完成後才通知：此時所有 session fd 已 release_java_socket（Java activeSockets 已清空）
    if (unexpected_exit) notify_engine_stopped(1);
    jni_detach_thread();
    return NULL;
}

// ---------- 對外介面 ----------

// 流量統計（供 JNI 通知列顯示）：payload bytes 累計 + 目前 session 數
void tun_socks_get_stats(unsigned long long *to_server, unsigned long long *from_server,
                         int *tcp_sessions, int *udp_sessions) {
    if (to_server) *to_server = atomic_load(&g.bytes_to_server);
    if (from_server) *from_server = atomic_load(&g.bytes_from_server);
    if (tcp_sessions) *tcp_sessions = atomic_load(&g.tcp_session_count);
    if (udp_sessions) *udp_sessions = atomic_load(&g.udp_session_count);
}

// 每次啟動前重置隨 session 而生的計數/快取，避免上一次 session 的殘留值帶入本次
//（例如通知列 ↑/↓ bytes 若不清零會跨 session 持續累加）。
static void engine_ctx_reset(void) {
    atomic_store(&g.bytes_to_server, 0);
    atomic_store(&g.bytes_from_server, 0);
    atomic_store(&g.udp_session_count, 0);
    atomic_store(&g.tcp_session_count, 0);
    atomic_store(&g.handshake_inflight, 0);
    g.isn_counter = 0;
    engine_fake_dns_reset();
    reasm_table_clear(&g_reasm);
}

int tun_socks_start(int tun_fd, const char *host, int port, const char *user, const char *pass, int udp_in_tcp, int remote_dns) {
    if (g.running) return -1;
    engine_ctx_reset();

    g.tun_fd = tun_fd;
    strncpy(g.srv_host, host, sizeof(g.srv_host) - 1);
    g.srv_host[sizeof(g.srv_host) - 1] = '\0';
    g.srv_port = port;
    g.auth_enabled = (user && user[0]) || (pass && pass[0]);
    strncpy(g.auth_user, user ? user : "", sizeof(g.auth_user) - 1);
    strncpy(g.auth_pass, pass ? pass : "", sizeof(g.auth_pass) - 1);
    g.udp_in_tcp = udp_in_tcp ? 1 : 0;
    g.remote_dns = remote_dns ? 1 : 0;

    set_nonblocking(g.tun_fd);

    if (pipe(g.shutdown_pipe) < 0) return -1;
    set_nonblocking(g.shutdown_pipe[0]);
    set_nonblocking(g.shutdown_pipe[1]);

    if (pipe(g.kick_pipe) < 0) {
        close(g.shutdown_pipe[0]); close(g.shutdown_pipe[1]);
        g.shutdown_pipe[0] = g.shutdown_pipe[1] = -1;
        return -1;
    }
    set_nonblocking(g.kick_pipe[0]);
    set_nonblocking(g.kick_pipe[1]);

    g.epoll_fd = epoll_create1(0);
    if (g.epoll_fd < 0) {
        close(g.shutdown_pipe[0]); close(g.shutdown_pipe[1]);
        close(g.kick_pipe[0]); close(g.kick_pipe[1]);
        g.shutdown_pipe[0] = g.shutdown_pipe[1] = -1;
        g.kick_pipe[0] = g.kick_pipe[1] = -1;
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.fd = g.shutdown_pipe[0];
    epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, g.shutdown_pipe[0], &ev);
    ev.events = EPOLLIN; ev.data.fd = g.kick_pipe[0];
    epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, g.kick_pipe[0], &ev);
    ev.events = EPOLLIN; ev.data.fd = g.tun_fd;
    epoll_ctl(g.epoll_fd, EPOLL_CTL_ADD, g.tun_fd, &ev);

    hs_pool_start();
    g.running = 1;
    if (pthread_create(&g_engine_thread, NULL, engine_loop, NULL) != 0) {
        g.running = 0;
        hs_pool_stop();
        if (g.epoll_fd >= 0) { close(g.epoll_fd); g.epoll_fd = -1; }
        if (g.shutdown_pipe[0] != -1) { close(g.shutdown_pipe[0]); g.shutdown_pipe[0] = -1; }
        if (g.shutdown_pipe[1] != -1) { close(g.shutdown_pipe[1]); g.shutdown_pipe[1] = -1; }
        if (g.kick_pipe[0] != -1) { close(g.kick_pipe[0]); g.kick_pipe[0] = -1; }
        if (g.kick_pipe[1] != -1) { close(g.kick_pipe[1]); g.kick_pipe[1] = -1; }
        if (g.tun_fd >= 0) { close(g.tun_fd); g.tun_fd = -1; }
        return -1;
    }
    LOGI("tunnel started: server=%s:%d auth=%d", g.srv_host, g.srv_port, g.auth_enabled);
    return 0;
}

void tun_socks_stop(void) {
    if (!g.running) return;
    g.running = 0;
    if (g.shutdown_pipe[1] != -1) {
        char stop_sig = 1;
        for (int k = 0; k < 10; k++) write(g.shutdown_pipe[1], &stop_sig, 1);
    }
    pthread_join(g_engine_thread, NULL);
    hs_pool_stop();   // 安全網：引擎關閉路徑已 join，此為 idempotent no-op
    if (g.shutdown_pipe[0] != -1) { close(g.shutdown_pipe[0]); g.shutdown_pipe[0] = -1; }
    if (g.shutdown_pipe[1] != -1) { close(g.shutdown_pipe[1]); g.shutdown_pipe[1] = -1; }
    if (g.kick_pipe[0] != -1) { close(g.kick_pipe[0]); g.kick_pipe[0] = -1; }
    if (g.kick_pipe[1] != -1) { close(g.kick_pipe[1]); g.kick_pipe[1] = -1; }
    LOGI("tunnel stopped");
}

// 供 JNI 層確認引擎是否「實際」仍在執行：g_tunnel_running 在引擎意外退出後
// 可能殘留為 1，但 g.running 已於 shutdown 清為 0，故以此為準判斷存活。
int tun_socks_is_running(void) {
    return g.running;
}

// soft-reconnect：要求引擎執行緒重置連線狀態（保留 TUN / VPN 介面）。
// new_host 非空時，先更新 g.srv_host（DDNS／IP 變動場景重新解析後的位址）；
// new_host == NULL 時沿用舊 host。更新與重置皆為任何執行緒可安全呼叫的旗標／鎖操作，
// 實際重置由 engine_loop 在引擎執行緒內執行（engine_soft_reset）。
void tun_socks_reconnect(const char *new_host) {
    if (!g.running) return;
    if (new_host && new_host[0]) {
        engine_srv_host_update(new_host);
    }
    atomic_store(&g_reset_requested, 1);
    if (g.kick_pipe[1] != -1) {
        char c = 1;
        write(g.kick_pipe[1], &c, 1);
    }
}
