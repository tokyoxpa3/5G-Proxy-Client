#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#include <BaseTSD.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ICMP/ICMPv6 回覆封包建構（純函式：不寫 TUN、不碰全域、不取時間）。
// 位址以 raw const unsigned char* 傳入（v4=4 bytes，v6=16 bytes）。
// src/dst 為「回覆封包」的來源/目的位址（即原始封包的目的/來源，已交換）。

// IPv4 ICMP echo request → echo reply。req 為含 IP 表頭的完整封包、req_len 為總長、
// ihl 為 IP 表頭長度（bytes，含選項）。成功回傳總長（==req_len），
// ihl 非法或 req_len 超出輸出/上限時回 -1。
ssize_t icmp4_build_echo_reply(const unsigned char *req, size_t req_len, int ihl,
                               const unsigned char *src_ip4, const unsigned char *dst_ip4,
                               unsigned char *out, size_t out_cap);

// IPv6 ICMPv6 echo request → echo reply（req 為含 IPv6 表頭的完整封包，req_len ≥ 48）。
ssize_t icmp6_build_echo_reply(const unsigned char *req, size_t req_len,
                               const unsigned char *src_ip6, const unsigned char *dst_ip6,
                               unsigned char *out, size_t out_cap);

// ICMPv6 Neighbor Advertisement（type 136，固定 64 bytes）。
// target_ip6 為宣告目標，from_ip6 為 NS 來源（即回覆的目的位址）。
ssize_t icmp6_build_na(const unsigned char *target_ip6, const unsigned char *from_ip6,
                       unsigned char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
#endif
