## v1.4.1 核心引擎測試覆蓋補齊

基於 v1.4.0，重點解決「核心引擎零覆蓋」風險，將最易回歸的 `tun_socks.c` 純邏輯抽離為可 host 編譯模組並補齊 golden 測試與 loopback 整合 harness，並在實機 192.168.1.192:44645 完成壓力驗證。

### 引擎重構 (`tun_socks.c`)
- **全域收攏 `engine_ctx_t g:206`**：將 `g_tun_fd/g_running/g_epoll_fd/g_srv_*` 等 20+ 全域收至單一 `struct`，`engine_ctx_reset:2530` 啟動重置、`tun_socks_start:2544`/`tun_socks_stop:2606` 生命週期清晰，為單元測試 harness 注入鋪路
- **DNS-over-TCP 攔截**：`tcp_sess_t.dns_tcp:97` + `dns_rx_buf:96` + `dns_tcp_emit:1702`/`dns_tcp_ingest:1724`，Remote DNS 下 `port 53/tcp` 直接合成 fake 回覆，避免網域洩漏至上游 DNS
- **資源釋放修復**：`close_session_fds:1183` / `tcp_session_destroy:1416` 改僅 `release_java_socket` 不再 `close(fd)`，避免 Java 與 native 雙重 close 導致 fd 重用 UAF（同批次控制+relay 事件）— 已通過 100 併發驗證

### 測試覆蓋（效仿 `checksum.c`）
抽離 3 個 host 可編譯純模組（`#include "checksum.h"` 風格，無 `android/log` 依賴）：

- **`socks5_codec.{h,c}`**：`socks5_build_udp_datagram:5` / `socks5_build_udp_frame:30` / `socks5_build_connect_request:47` / `socks5_parse_udp_datagram:88`（ATYP 0x01/0x03/0x04）
- **`dns_synth.{h,c}`**：`dns_build_reply_pure:13` + `dns_build_fake_ip6:5`（`fd00::5e:x`），覆蓋 A/AAAA/HTTPS(65) 空答
- **`tcp_packet.{h,c}`**：`tcp_build_segment:8` / `tcp_build_synack:54`（MSS/WS）/ `udp_build_packet:102`，含 `transport_checksum` 校驗

Golden tests（`gcc -std=c11 -Wall -Wextra -I app/src/main/cpp`）：
- `checksum_test.c` 7 項 — `0x126b` RFC1071 / `0x7e20` UDPv4 / `0x6875` UDPv6 — **PASS**
- `socks5_test.c` 11 項 — `hello/auth/CONNECT v4/v6/domain` / `UDP datagram/frame 00 14` — **PASS**
- `dns_synth_test.c` 9 項 — `A C6120001` / `AAAA fd00::` / `HTTPS empty` — **PASS**
- `tcp_packet_test.c` 7 組 — `tcp 0x0fa1` / `synack 0xe54b` / `seq wraparound (int32_t)(a-b)>0` / `window 4096` — **PASS**
- `tun_loopback_test.c` — in-process 假 SOCKS5（`HELLO 05 00` / `CONNECT 05 00 00 01` echo / `UDP ASSOCIATE 127.0.0.1:22222`）+ `socketpair` 模擬 TUN，驗證 `tcp_build_synack seq 5000 ack 1001` 回環 — **PASS**（Windows 跳過 POSIX，Linux 全量）

建置：`app/CMakeLists.txt:14` 新增 3 源，`ci.yml:47` 擴充 `native-unit-test` 至 4 binaries，`app/build.gradle:14` `versionCode 8->9` `v1.4.0->v1.4.1`

### 壓力測試 (192.168.1.192:44645, SM-G9810, SD865, 192.168.1.178:1080)
- Monkey `500` + `200` events throttle 120 — **100% 注入，無 ANR/tombstone for socksclient**
- TCP 併發 `60× curl`（example/hinet/google generate_204）— `tun0 rx +44k tx +12k` 穩定，`TunSocks` 僅正常 `tcp connect 完成` / `session 關閉`
- DNS flood `30× dns_q.bin via nc -u` + `fakedns` `198.18.0.x` — **100% 攔截**
- `chk_test` `bad=0`（`IPhdr ae78`），`VmRSS 158MB PSS 67MB` 30s idle 無洩漏，FD 256→512 正常

APK 已以 `release.keystore`（`storeFile=../release.keystore`, `apksigner verify v2 true`）簽署，支援 `arm64-v8a` / `armeabi-v7a` / `x86_64`，`max-page-size 16384` 對齊（Android 15+ 16KB）。

**Full Changelog**: https://github.com/tokyoxpa3/5G-Proxy-Client/compare/v1.4.0...v1.4.1
