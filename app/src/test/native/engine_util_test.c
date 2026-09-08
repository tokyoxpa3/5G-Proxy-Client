// engine_util_test.c — socks5_greet_auth 純編排測試（host gcc 可編譯）
// 以注入式 fake send/recv 驅動 greeting + 選擇性 RFC1929 認證的各分類分支，
// 不需真實 socket。覆蓋 tun_engine 整合測試未走過的認證（RFC 1929）路徑。
#include <stdio.h>
#include <string.h>
#include "engine.h"

// 引擎全域：engine_util.c 以 extern 引用（g.auth_user / g.auth_pass / g.running 等）
engine_ctx_t g;

static int g_fail = 0;
#define CHECK(name, cond) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); g_fail = 1; } \
} while (0)

// ---- 注入式 fake I/O ----
struct fake_io {
    int send_fail;
    int recv_fail;
    unsigned char sent[512];
    size_t sent_len;
    const unsigned char *script;   // recv 回應串流（依序餵回）
    size_t script_len;
    size_t script_off;
};
static struct fake_io *g_io;

static int fake_send(int fd, const unsigned char *buf, size_t len) {
    (void)fd;
    if (g_io->send_fail) return -1;
    if (len > sizeof g_io->sent) len = sizeof g_io->sent;
    memcpy(g_io->sent, buf, len);
    g_io->sent_len = len;
    return (int)len;
}

static int fake_recv(int fd, unsigned char *buf, size_t len) {
    (void)fd;
    if (g_io->recv_fail) return -1;
    size_t rem = g_io->script_len - g_io->script_off;
    size_t n = rem < len ? rem : len;
    memcpy(buf, g_io->script + g_io->script_off, n);
    g_io->script_off += n;
    return (int)n;
}

int main(void) {
    unsigned char buf[320];
    struct fake_io io;
    int rc;

    // 1. 無認證：greeting 回 no-auth → 0
    memset(&io, 0, sizeof io);
    static const unsigned char no_auth[] = {0x05, 0x00};
    io.script = no_auth; io.script_len = sizeof no_auth;
    g_io = &io;
    g.auth_user[0] = '\0'; g.auth_pass[0] = '\0';
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet no-auth 成功", rc == 0);
    CHECK("greet no-auth hello 3 bytes", io.sent_len == 3 && io.sent[0] == 0x05);

    // 2. 認證成功：need-auth → auth ok → 0，且 auth 訊息含帳密
    memset(&io, 0, sizeof io);
    static const unsigned char auth_ok[] = {0x05, 0x02, 0x01, 0x00};
    io.script = auth_ok; io.script_len = sizeof auth_ok;
    g_io = &io;
    strcpy(g.auth_user, "u");
    strcpy(g.auth_pass, "p");
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet 認證成功", rc == 0);
    {
        static const unsigned char exp[] = {0x01, 0x01, 'u', 0x01, 'p'};
        CHECK("greet 認證訊息含帳密",
              io.sent_len == sizeof exp && memcmp(io.sent, exp, sizeof exp) == 0);
    }

    // 3. 非 SOCKS5：ver != 5 → PROTOCOL_FAIL
    memset(&io, 0, sizeof io);
    static const unsigned char not_socks[] = {0x04, 0x00};
    io.script = not_socks; io.script_len = sizeof not_socks;
    g_io = &io;
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet 非 SOCKS5 → PROTOCOL_FAIL", rc == SE_EVENT_PROTOCOL_FAIL);

    // 4. 未選用方法（0xFF）→ AUTH_FAIL
    memset(&io, 0, sizeof io);
    static const unsigned char no_method[] = {0x05, 0xff};
    io.script = no_method; io.script_len = sizeof no_method;
    g_io = &io;
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet 未選用方法 → AUTH_FAIL", rc == SE_EVENT_AUTH_FAIL);

    // 5. 認證被拒：auth reply != 0 → AUTH_FAIL
    memset(&io, 0, sizeof io);
    static const unsigned char auth_rej[] = {0x05, 0x02, 0x01, 0x01};
    io.script = auth_rej; io.script_len = sizeof auth_rej;
    g_io = &io;
    strcpy(g.auth_user, "u");
    strcpy(g.auth_pass, "p");
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet 認證被拒 → AUTH_FAIL", rc == SE_EVENT_AUTH_FAIL);

    // 6. send 失敗 → NETWORK_FAIL
    memset(&io, 0, sizeof io);
    io.send_fail = 1;
    g_io = &io;
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet send 失敗 → NETWORK_FAIL", rc == SE_EVENT_NETWORK_FAIL);

    // 7. recv 失敗 → NETWORK_FAIL
    memset(&io, 0, sizeof io);
    io.recv_fail = 1;
    g_io = &io;
    rc = socks5_greet_auth(0, fake_send, fake_recv, buf, sizeof buf);
    CHECK("greet recv 失敗 → NETWORK_FAIL", rc == SE_EVENT_NETWORK_FAIL);

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
