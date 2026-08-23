#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

// 讓 checksum.c 可在純 host C 環境（無 POSIX sys/socket.h）編譯：
// Android/Linux 已定義時不受影響（#ifndef 防重定義）
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 累加 + 完成 checksum（RFC 1071 風格）
uint32_t accum_swapped(const unsigned char *data, size_t len, uint32_t sum);
uint16_t checksum_finish(uint32_t sum);
uint16_t checksum16(const unsigned char *data, size_t len);
uint16_t tcpudp_checksum4(const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len);
uint16_t tcpudp_checksum6(const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len);
uint16_t transport_checksum(int family, const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif