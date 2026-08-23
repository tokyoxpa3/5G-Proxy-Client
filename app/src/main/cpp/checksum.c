// checksum.c — 純函式 IP/TCP/UDP checksum（RFC 1071 風格）
// 獨立成檔以便 host 端編譯做單元測試；不依賴任何 POSIX/Android API。
#include <string.h>
#include "checksum.h"

// 以 32-bit 累加「byte-swapped 的 16-bit word」（大尾序資料以 little-endian 讀 4 bytes）
uint32_t accum_swapped(const unsigned char *data, size_t len, uint32_t sum) {
    while (len >= 4) {
        uint32_t w;
        memcpy(&w, data, 4);
        sum += (w & 0xFFFF) + (w >> 16);
        data += 4; len -= 4;
    }
    while (len > 1) { sum += (uint32_t)((data[1] << 8) | data[0]); data += 2; len -= 2; }
    if (len) sum += (uint32_t)data[0];
    return sum;
}

// 完成累加並 swap 回真值（~ 後交換高低位元組）
uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t res = (uint16_t)~sum;
    return (uint16_t)((res >> 8) | (res << 8));
}

uint16_t checksum16(const unsigned char *data, size_t len) {
    return checksum_finish(accum_swapped(data, len, 0));
}

uint16_t tcpudp_checksum4(const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len) {
    unsigned char ph[12];
    memcpy(ph, saddr, 4);
    memcpy(ph + 4, daddr, 4);
    ph[8] = 0; ph[9] = proto;
    // 長度欄以網路序（big-endian）寫入，避免依賴 arpa/inet.h
    ph[10] = (unsigned char)((len >> 8) & 0xFF);
    ph[11] = (unsigned char)(len & 0xFF);
    uint32_t sum = accum_swapped(ph, 12, 0);
    sum = accum_swapped(data, len, sum);
    return checksum_finish(sum);
}

uint16_t tcpudp_checksum6(const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len) {
    unsigned char ph[40];
    memcpy(ph, saddr, 16);
    memcpy(ph + 16, daddr, 16);
    ph[32] = (unsigned char)((len >> 24) & 0xFF);
    ph[33] = (unsigned char)((len >> 16) & 0xFF);
    ph[34] = (unsigned char)((len >> 8) & 0xFF);
    ph[35] = (unsigned char)(len & 0xFF);
    ph[36] = 0; ph[37] = 0; ph[38] = 0; ph[39] = proto;
    uint32_t sum = accum_swapped(ph, 40, 0);
    sum = accum_swapped(data, len, sum);
    return checksum_finish(sum);
}

uint16_t transport_checksum(int family, const unsigned char *saddr, const unsigned char *daddr, uint8_t proto, const unsigned char *data, size_t len) {
    if (family == AF_INET6) return tcpudp_checksum6(saddr, daddr, proto, data, len);
    return tcpudp_checksum4(saddr, daddr, proto, data, len);
}
