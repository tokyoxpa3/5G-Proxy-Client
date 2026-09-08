// hs_pool_test.c — handshake 執行緒池生命週期測試（host gcc + pthread）
// 驗證 submit 在 start 前 / stop 後回 -1、in-flight 計數不洩漏、jobs 全數執行。
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "engine.h"

// 引擎全域：hs_pool.c 以 extern 引用（hs_running / hs_workers / handshake_inflight）
engine_ctx_t g;

// hs_worker 呼叫的 JNI 掛鉤（主機端 no-op，等同 host_jni_bridge.c 的實作）
void jni_attach_thread(void) {}
void jni_detach_thread(void) {}

static int g_fail = 0;
#define CHECK(name, cond) do { \
    if (cond) printf("PASS  %s\n", name); \
    else { printf("FAIL  %s\n", name); g_fail = 1; } \
} while (0)

static atomic_int g_completed = 0;

static void *job_fn(void *arg) {
    (void)arg;
    atomic_fetch_add(&g_completed, 1);
    atomic_fetch_sub(&g.handshake_inflight, 1);   // 對應 tcp_connect_thread 收尾時的遞減
    return NULL;
}

int main(void) {
    // 1. start 前 submit → -1，且 in-flight 不殘留
    CHECK("submit before start 回 -1", hs_submit(job_fn, NULL) == -1);
    CHECK("submit before start inflight 0", atomic_load(&g.handshake_inflight) == 0);

    // 2. start → 建立 HS_POOL_WORKERS 個 worker
    hs_pool_start();
    CHECK("pool start running", g.hs_running == 1);
    CHECK("pool start worker 數", g.hs_worker_count == HS_POOL_WORKERS);

    // 3. 提交 N 個 job，等全數完成，in-flight 歸零
    enum { N = 64 };
    atomic_store(&g_completed, 0);
    int submit_ok = 1;
    for (int i = 0; i < N; i++) {
        if (hs_submit(job_fn, NULL) != 0) { submit_ok = 0; break; }
    }
    CHECK("submit 64 個 job 全成功", submit_ok);
    for (int i = 0; i < 2000 && atomic_load(&g_completed) < N; i++) usleep(1000);
    CHECK("jobs 全數完成", atomic_load(&g_completed) == N);
    CHECK("in-flight 歸零", atomic_load(&g.handshake_inflight) == 0);

    // 4. stop 後 submit → -1，且 worker 回收
    hs_pool_stop();
    CHECK("pool stop not running", g.hs_running == 0);
    CHECK("pool stop worker 清零", g.hs_worker_count == 0);
    CHECK("submit after stop 回 -1", hs_submit(job_fn, NULL) == -1);

    printf(g_fail ? "\nRESULT: FAIL\n" : "\nRESULT: PASS\n");
    return g_fail;
}
