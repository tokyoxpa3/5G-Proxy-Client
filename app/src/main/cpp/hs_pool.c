// hs_pool.c — handshake 執行緒池（抽離自 tun_socks.c）
// 以固定 worker 數取代 per-session detached thread，避免連線尖峰時大量建立執行緒。
// submit 遞增 g.handshake_inflight、job 結尾遞減；關閉時確定性排空並 join worker。
#include "engine.h"
#include <stdlib.h>

static pthread_mutex_t g_hs_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_hs_cond = PTHREAD_COND_INITIALIZER;

static void *hs_worker(void *arg) {
    (void)arg;
    jni_attach_thread();
    for (;;) {
        pthread_mutex_lock(&g_hs_lock);
        while (g.hs_running && !g.hs_head)
            pthread_cond_wait(&g_hs_cond, &g_hs_lock);
        if (!g.hs_running && !g.hs_head) {
            pthread_mutex_unlock(&g_hs_lock);
            break;
        }
        hs_job_t *job = g.hs_head;
        g.hs_head = job->next;
        if (!g.hs_head) g.hs_tail = NULL;
        pthread_mutex_unlock(&g_hs_lock);
        job->fn(job->arg);
        free(job);
    }
    jni_detach_thread();
    return NULL;
}

void hs_pool_start(void) {
    if (g.hs_running) return;
    g.hs_running = 1;
    g.hs_worker_count = 0;
    for (int i = 0; i < HS_POOL_WORKERS; i++) {
        if (pthread_create(&g.hs_workers[g.hs_worker_count], NULL, hs_worker, NULL) == 0)
            g.hs_worker_count++;
    }
}

void hs_pool_stop(void) {
    if (!g.hs_running) return;
    pthread_mutex_lock(&g_hs_lock);
    g.hs_running = 0;
    pthread_cond_broadcast(&g_hs_cond);
    pthread_mutex_unlock(&g_hs_lock);
    for (int i = 0; i < g.hs_worker_count; i++)
        pthread_join(g.hs_workers[i], NULL);
    g.hs_worker_count = 0;
}

int hs_submit(void *(*fn)(void *), void *arg) {
    hs_job_t *job = malloc(sizeof(*job));
    if (!job) return -1;
    job->fn = fn;
    job->arg = arg;
    job->next = NULL;
    atomic_fetch_add(&g.handshake_inflight, 1);
    pthread_mutex_lock(&g_hs_lock);
    if (!g.hs_running) {
        pthread_mutex_unlock(&g_hs_lock);
        atomic_fetch_sub(&g.handshake_inflight, 1);
        free(job);
        return -1;
    }
    if (g.hs_tail) g.hs_tail->next = job;
    else g.hs_head = job;
    g.hs_tail = job;
    pthread_cond_signal(&g_hs_cond);
    pthread_mutex_unlock(&g_hs_lock);
    return 0;
}
