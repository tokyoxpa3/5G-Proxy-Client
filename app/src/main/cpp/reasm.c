// reasm.c — IP 分片重組的純演算法 + 重組表 stateful 模組（抽離自 tun_socks.c）
// 不依賴引擎全域狀態、epoll、POSIX、android/log，可於 host 端 gcc 編譯做單元測試。
// 重組表持有 entry、注入 time、完成時回呼送出重組後的封包（模組本身不加鎖不取時間）。
#include "reasm.h"
#include "ip_parse.h"
#include "checksum.h"
#include <stdlib.h>
#include <string.h>

// ---------- 純演算法 ----------

int reasm_insert_seg(size_t *soff, size_t *slen, int *nseg, unsigned char *buf,
                     size_t offset, const unsigned char *data, size_t len, int mf,
                     size_t *total_len, int *have_last) {
    if (offset + len > REASM_MAX_SIZE) return -1;          // 超出重組上限
    if (!mf) {
        size_t t = offset + len;
        if (*have_last && *total_len != t) return -1;     // 末片長度與先前不一致
        *total_len = t;
        *have_last = 1;
    }
    if (len > 0) {
        if (*nseg >= REASM_MAX_FRAGS) return -1;          // 分片數超上限
        // 重疊檢查（RFC 5722：重疊的分片一律丟棄）
        for (int i = 0; i < *nseg; i++) {
            size_t a = soff[i], b = a + slen[i];
            if (offset < b && a < offset + len) return -1;
        }
        soff[*nseg] = offset;
        slen[*nseg] = len;
        (*nseg)++;
        memcpy(buf + offset, data, len);
    }
    if (!*have_last) return 0;
    // 依 offset 排序 segment，確認 [0, total_len) 無間隙全覆蓋
    for (int i = 0; i < *nseg - 1; i++)
        for (int j = i + 1; j < *nseg; j++)
            if (soff[j] < soff[i]) {
                size_t t1 = soff[i], t2 = slen[i];
                soff[i] = soff[j]; slen[i] = slen[j];
                soff[j] = t1; slen[j] = t2;
            }
    size_t expected = 0;
    for (int i = 0; i < *nseg; i++) {
        if (soff[i] != expected) return 0;
        expected += slen[i];
    }
    return (expected == *total_len) ? 1 : 0;
}

// ---------- 重組表 ----------

void reasm_table_init(reasm_table_t *t) {
    memset(t, 0, sizeof(*t));
}

static void entry_clear(reasm_entry_t *e) {
    if (e->buf) { free(e->buf); e->buf = NULL; }
    memset(e, 0, sizeof(*e));
}

void reasm_table_clear(reasm_table_t *t) {
    for (int i = 0; i < REASM_MAX_ENTRIES; i++) entry_clear(&t->entries[i]);
}

// 逾時回收：釋放 last_active 超過 REASM_TIMEOUT_SEC 的 entry
void reasm_table_gc(reasm_table_t *t, time_t now) {
    for (int i = 0; i < REASM_MAX_ENTRIES; i++)
        if (t->entries[i].in_use && now - t->entries[i].last_active > REASM_TIMEOUT_SEC)
            entry_clear(&t->entries[i]);
}

// 依 (family, id, proto, src, dst) 找既有 entry；找不到回 -1
static int find_entry(reasm_table_t *t, uint8_t family, const ip_addr_t *src,
                      const ip_addr_t *dst, uint8_t proto, uint32_t id) {
    for (int i = 0; i < REASM_MAX_ENTRIES; i++) {
        reasm_entry_t *e = &t->entries[i];
        if (e->in_use && e->family == family && e->id == id && e->proto == proto &&
            ip_addr_eq(&e->src, src) && ip_addr_eq(&e->dst, dst))
            return i;
    }
    return -1;
}

// 分配（或重用）一個 entry；回傳 index 或 -1
static int alloc_entry(reasm_table_t *t, uint8_t family, const ip_addr_t *src,
                       const ip_addr_t *dst, uint8_t proto, uint32_t id, time_t now) {
    int idx = -1;
    for (int i = 0; i < REASM_MAX_ENTRIES; i++) {
        if (!t->entries[i].in_use || now - t->entries[i].last_active > REASM_TIMEOUT_SEC) { idx = i; break; }
    }
    if (idx < 0) {  // 全滿且未逾時 → LRU 淘汰最舊者
        idx = 0;
        for (int i = 1; i < REASM_MAX_ENTRIES; i++)
            if (t->entries[i].last_active < t->entries[idx].last_active) idx = i;
    }
    entry_clear(&t->entries[idx]);
    reasm_entry_t *e = &t->entries[idx];
    e->in_use = 1;
    e->family = family;
    e->src = *src;
    e->dst = *dst;
    e->proto = proto;
    e->id = id;
    e->last_active = now;
    e->buf = malloc(REASM_MAX_SIZE);
    if (!e->buf) { e->in_use = 0; return -1; }
    return idx;
}

void reasm_table_insert(reasm_table_t *t, uint8_t family,
                        const ip_addr_t *src, const ip_addr_t *dst,
                        uint8_t proto, uint32_t id,
                        size_t offset, const unsigned char *data, size_t dlen, int mf,
                        const unsigned char *ip_hdr, size_t ip_hdr_len, size_t patch_off,
                        time_t now,
                        void (*emit)(const unsigned char *out, size_t outlen, void *ctx),
                        void *ctx) {
    int idx = find_entry(t, family, src, dst, proto, id);
    if (idx < 0) idx = alloc_entry(t, family, src, dst, proto, id, now);
    if (idx < 0) return;

    reasm_entry_t *e = &t->entries[idx];
    // 首片（offset 0）記錄前置表頭，供重組完成後重建完整封包
    if (offset == 0 && ip_hdr_len <= sizeof(e->ip_hdr)) {
        memcpy(e->ip_hdr, ip_hdr, ip_hdr_len);
        e->ip_hdr_len = (uint16_t)ip_hdr_len;
        e->patch_off = patch_off;
    }
    e->last_active = now;

    int done = reasm_insert_seg(e->soff, e->slen, &e->nseg, e->buf,
                                offset, data, dlen, mf,
                                &e->total_len, &e->have_last);
    if (done <= 0) { if (done < 0) entry_clear(e); return; }

    unsigned char *out = malloc(e->ip_hdr_len + e->total_len);
    if (!out) { entry_clear(e); return; }
    if (family == AF_INET) {
        int outlen = ip4_reasm_rebuild(e->ip_hdr, e->ip_hdr_len,
                                       e->buf, e->total_len, out,
                                       e->ip_hdr_len + e->total_len);
        if (outlen > 0) emit(out, (size_t)outlen, ctx);
    } else {
        int outlen = ip6_reasm_rebuild(e->ip_hdr, e->ip_hdr_len, e->patch_off, e->proto,
                                       e->buf, e->total_len, out,
                                       e->ip_hdr_len + e->total_len);
        if (outlen > 0) emit(out, (size_t)outlen, ctx);
    }
    free(out);
    entry_clear(e);
}
