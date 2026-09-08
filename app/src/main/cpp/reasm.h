#ifndef REASM_H
#define REASM_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "ip_parse.h"

// 分片重組的常數——與 tun_socks.c 共用，避免兩側漂移。
#define REASM_MAX_FRAGS 16
#define REASM_MAX_SIZE 65535
// 重組表上限 / 逾時 / 前置表頭鏈上限（v4 IHL ≤ 60；v6 = base 40 + 前置 ext header）
#define REASM_MAX_ENTRIES 16
#define REASM_TIMEOUT_SEC 5
#define REASM_MAX_IPHDR 256

#ifdef __cplusplus
extern "C" {
#endif

// ---- 純演算法（reasm_insert_seg）----

// 在既有重組狀態上插入一片：回傳 1=重組完成、0=尚未完成、-1=需丟棄
//（重疊 / 末片長度不一致 / 分片數或總長超上限）。
//
// 純函式：所有可變狀態（分片表、緩衝、末片標記）由呼叫端提供，不擁有記憶體。
// buf 指向呼叫端配置的 REASM_MAX_SIZE 緩衝；重組完成後 [0, *total_len) 為完整 payload。
// *soff / *slen / *nseg 記錄已收分片的 (offset, len)，呼叫端需先歸零 *nseg 與 *have_last。
int reasm_insert_seg(size_t *soff, size_t *slen, int *nseg, unsigned char *buf,
                     size_t offset, const unsigned char *data, size_t len, int mf,
                     size_t *total_len, int *have_last);

// ---- 重組表（stateful 模組：持有表、注入 time、完成時回呼送出）----

// 單一重組中的分片集合（v4/v6 共用；v4 僅用 ip_hdr 前 ihl 位元組）
typedef struct {
    int in_use;
    uint8_t family;         // AF_INET / AF_INET6
    ip_addr_t src, dst;
    uint8_t proto;          // L4 協定（v4=IP proto；v6=Fragment 後的 next header）
    uint32_t id;            // v4 16-bit / v6 32-bit
    unsigned char *buf;     // malloc(REASM_MAX_SIZE)
    size_t total_len;       // 0 = 尚未收到末片
    int have_last;
    size_t soff[REASM_MAX_FRAGS];
    size_t slen[REASM_MAX_FRAGS];
    int nseg;
    unsigned char ip_hdr[REASM_MAX_IPHDR];
    uint16_t ip_hdr_len;
    size_t patch_off;       // v6：移除 Fragment 時需改寫的 next-header 欄位偏移（v4 恒 0）
    time_t last_active;
} reasm_entry_t;

// 重組表：可整體重置、由引擎持有。同步/時間由呼叫端負責，此模組不加鎖不取時間。
typedef struct {
    reasm_entry_t entries[REASM_MAX_ENTRIES];
} reasm_table_t;

// 全表歸零（供 stack/heap 配置的表初始化）
void reasm_table_init(reasm_table_t *t);

// 清空所有 entry 並釋放緩衝
void reasm_table_clear(reasm_table_t *t);

// 逾時回收：釋放 last_active 超過 REASM_TIMEOUT_SEC 的 entry
void reasm_table_gc(reasm_table_t *t, time_t now);

// 插入一片分片；重組完成時以 ip4/ip6_reasm_rebuild 重建並呼叫 emit(out, outlen, ctx)。
// ip_hdr 為前置表頭（v4=IP 頭；v6=Fragment 之前的表頭鏈），
// ip_hdr_len / patch_off 含義同 ip6_reasm_rebuild。找不到既有 entry 時自動分配（含 LRU 淘汰）。
void reasm_table_insert(reasm_table_t *t, uint8_t family,
                        const ip_addr_t *src, const ip_addr_t *dst,
                        uint8_t proto, uint32_t id,
                        size_t offset, const unsigned char *data, size_t dlen, int mf,
                        const unsigned char *ip_hdr, size_t ip_hdr_len, size_t patch_off,
                        time_t now,
                        void (*emit)(const unsigned char *out, size_t outlen, void *ctx),
                        void *ctx);

#ifdef __cplusplus
}
#endif
#endif
