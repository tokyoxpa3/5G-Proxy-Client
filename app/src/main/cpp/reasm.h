#ifndef REASM_H
#define REASM_H

#include <stddef.h>

// 分片重組的純演算法常數——與 tun_socks.c 共用，避免兩側漂移。
#define REASM_MAX_FRAGS 16
#define REASM_MAX_SIZE 65535

#ifdef __cplusplus
extern "C" {
#endif

// 在既有重組狀態上插入一片：回傳 1=重組完成、0=尚未完成、-1=需丟棄
//（重疊 / 末片長度不一致 / 分片數或總長超上限）。
//
// 純函式：所有可變狀態（分片表、緩衝、末片標記）由呼叫端提供，不擁有記憶體。
// buf 指向呼叫端配置的 REASM_MAX_SIZE 緩衝；重組完成後 [0, *total_len) 為完整 payload。
// *soff / *slen / *nseg 記錄已收分片的 (offset, len)，呼叫端需先歸零 *nseg 與 *have_last。
int reasm_insert_seg(size_t *soff, size_t *slen, int *nseg, unsigned char *buf,
                     size_t offset, const unsigned char *data, size_t len, int mf,
                     size_t *total_len, int *have_last);

#ifdef __cplusplus
}
#endif
#endif
