#ifndef DNS_QUERY_H
#define DNS_QUERY_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 解析單一 DNS QUERY 封包（不可信網路輸入）的 QNAME/QTYPE/QCLASS。
// 純函式：不取時間、不加鎖、不碰全域。所有位元組讀取皆以 qlen 為界。
//
// 成功回傳 1，並寫出：
//   name_out      以 '.' 分隔、NUL 終止的 QNAME（name_cap 為其容量，需 ≥ 254）
//   qtype_out     QTYPE（host 序）
//   qclass_out    QCLASS（host 序，本函式僅接受 IN=1）
//   supported_out 是否為攔截型別（A=1 / AAAA=28 / HTTPS=65）
//   qend_out      question 段落結束 offset（含 qtype/qclass，供原樣複製 question）
// 回傳 0 = 格式非法（截斷/QR 已設/opcode 非 0/qdcount≠1/壓縮指標/label 超長/
//          非法字元/空名或超長名/qclass 非 IN/question 段落越界）。
// 除 name_out 與 name_cap 外，其餘 out 參數可為 NULL（略過不回填）。
int dns_query_parse(const unsigned char *q, size_t qlen,
                    char *name_out, size_t name_cap,
                    uint16_t *qtype_out, uint16_t *qclass_out,
                    int *supported_out, size_t *qend_out);

#ifdef __cplusplus
}
#endif
#endif
