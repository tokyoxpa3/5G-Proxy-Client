#ifndef IP_HASH_H
#define IP_HASH_H
#include <stdint.h>
#include "ip_parse.h"

#ifdef __cplusplus
extern "C" {
#endif

// 位址 32-bit 純雜湊（FNV-1a），供 TCP/UDP 會話鍵計算使用。
// 與引擎共用同一實作，避免兩側演算法漂移。ip 以 16 位元組網路序位址雜湊，
// 末端 XOR family 使「同一組位址位元組 + 不同 family」散開到不同 bucket。
uint32_t ip_hash32(const ip_addr_t *ip);

// 會話 hash bucket 索引：(ip_hash32(ip) ^ port) % nbuckets。
// 供 TCP/UDP hash 表定位使用；nbuckets 由引擎依各自 bucket 陣列大小傳入。
uint32_t ip_hash_bucket(const ip_addr_t *ip, uint16_t port, uint32_t nbuckets);

#ifdef __cplusplus
}
#endif
#endif
