# Android SOCKS5 TUN Tunnel Client

把整台裝置的網路流量透過 TUN 虛擬網卡導向遠端 SOCKS5 伺服器的 Android 客戶端。

- **TCP**：內建完整的 TCP 狀態機（於使用者空間實作），透過 SOCKS5 **CONNECT** 轉發
- **UDP / DNS / QUIC**：透過 SOCKS5 **UDP ASSOCIATE** relay，讓 DNS 與 HTTP/3（QUIC）都能穿透
  - 預設 **UDP-in-UDP**（RFC 1928），可切換 **UDP-in-TCP**（自訂擴充指令 0x04，relay 走同一條 TCP，不受 UDP 優先權/壅塞影響）
- **IPv4 + IPv6 雙棧**：TUN 同時配置 `10.8.0.2/32` 與 `fd00::2/128`，UDP/TCP 皆支援 v6
- **Per-App 排除**：可勾選指定 App 走手機本機網路（繞過隧道）
- 原生 C（epoll）引擎 + JNI + Kotlin UI + 前台 VpnService

---

## 架構

```
[App] --TUN(10.8.0.2 / fd00::2)--> [C 引擎: tun_socks.c] --SOCKS5--> [遠端 SOCKS5 伺服器] --> [目標網站]
                                    │
                                    └── 以 VpnService.protect() 建立通往伺服器的 socket
```

- `VpnService` 建立 TUN（`10.8.0.2/32` + `fd00::2/128`、MTU 4096、路由全走隧道、DNS 8.8.8.8/1.1.1.1）
- 原生引擎為單一 epoll 執行緒，直接讀寫 TUN fd 與 relay socket（`request_java_socket` 由 JNI 呼叫 Java 建立 **protected** socket，繞過隧道避免迴圈）
- TCP 於使用者空間實作：SYN/SYN-ACK、序號追蹤、**Window Scale（WS=10）**、依 App 通告 window 的**流量控制**、緩衝滿時**回壓**、handshake 期間**首包緩衝**（避免等 App 重傳造成 10 秒級延遲）
- UDP relay 為 **Fullcone 語意**：session 以（來源 IP, 來源 port）為鍵，單一映射對所有目標；伺服器端任何來源的回覆皆會送回 App 並保留原始來源位址

### 關鍵檔案

| 檔案 | 說明 |
|---|---|
| `app/src/main/cpp/tun_socks.c` | 核心引擎：TUN 讀寫、TCP/UDP 狀態機、SOCKS5 協定、流量控制、UDP-in-TCP frame 串流 |
| `app/src/main/cpp/jni_bridge.c` | JNI 橋接（socket 取得、引擎生命週期） |
| `app/src/main/java/.../TunSocksService.kt` | VpnService + 前台服務 + `protect()` + per-App 排除套用 |
| `app/src/main/java/.../NativeEngine.kt` | 原生引擎的 JNI 宣告 |
| `app/src/main/java/.../MainActivity.kt` | 設定頁面（伺服器 / 連接埠 / 認證 / UDP-in-TCP 開關） |
| `app/src/main/java/.../AppListActivity.kt` | 排除 App 選擇器（勾選 = 走本機網路） |

---

## 使用方式

1. 準備一個 **SOCKS5 伺服器**（任何標準 SOCKS5 伺服器皆可；開啟「UDP relay 走 TCP」時建議搭配配套的 5G-Proxy-Pro 伺服器，該專案支援擴充指令 0x04）
2. 安裝 APK 並開啟 App
3. 填入伺服器 IP 與連接埠（預設 `1080`），認證可留空；需要時勾選「UDP relay 走 TCP（UDP-in-TCP）」
4. 點「🚀 啟動隧道」並允許 VPN 權限
5. 裝置的所有流量即透過 SOCKS5 伺服器對外

> 伺服器位址會在建立 VPN 前解析，避免自己的 DNS 查詢被隧道捕捉。

---

## 建置

需求：

- Android SDK（`local.properties` 指定 `sdk.dir`）
- NDK `26.3.11579264`
- JDK 17

```bash
export JAVA_HOME=<JDK 17 路徑>
./gradlew assembleDebug
# 產出: app/build/outputs/apk/debug/app-debug.apk
```

- 支援 ABI：`arm64-v8a`、`armeabi-v7a`
- 原生碼以 `-O3` 編譯
- 正式簽名：於專案根目錄建立 `keystore.properties`（`storeFile`/`storePassword`/`keyAlias`/`keyPassword`）後即可 `assembleRelease`；未提供時 release 不簽名，供第三方自行簽署

---

## 流量路徑與機制

### TCP（SOCKS5 CONNECT）

- App 發出 SYN → 引擎建立 session、回 SYN-ACK（含 MSS + WS=10），背景執行緒向伺服器做 SOCKS5 CONNECT
- handshake 期間的 App 資料先緩衝，connect 完成後立即轉發（不需等 App 重傳）
- srv→App 依 App 通告的 window（含 WS 縮放）限制送出；緩衝滿時暫停讀取 relay，靠 relay 的 TCP 回壓反壓，不直接斷連

### UDP（SOCKS5 UDP ASSOCIATE）

- 每個（來源 IP, 來源 port）建立獨立 UDP session（**Fullcone 語意**：映射不隨目的地變化，任何來源的回覆皆可送達），與伺服器交換 relay 位址後互轉
- 首次封包於 handshake 期間緩衝，完成後立即送出——避免 DNS / QUIC Initial 被丟棄後等 App 指數退避重傳
- session 閒置 330 秒回收（比伺服器端 300 秒長，由伺服器先斷、客戶端被動收尾）

### UDP-in-TCP（可選，MainActivity 勾選）

- 握手改用自訂 SOCKS5 擴充指令 `0x04`；伺服器回覆成功後，**同一條 TCP 連線**以 frame 承載 UDP datagram
- frame 格式：`[2-byte 長度 (network order)] + [SOCKS5 UDP datagram]`，datagram = `RSV(2)=0 + FRAG(1)=0 + ATYP + ADDR + PORT(2) + DATA`（ATYP 0x01 → 表頭 10B；0x04 → 22B）
- 伺服器不支援 0x04（回覆 REP≠0）時，客戶端自動在同一條連線**退回標準 UDP ASSOCIATE（0x03）**，一般 SOCKS5 伺服器亦可直接使用
- 完整規格見配套伺服器專案（5G-Proxy-Pro）README

### Per-App 排除

- 「🚫 Excluded Apps」進入 App 選擇器，**勾選的 App 走手機本機網路**（`VpnService.Builder.addDisallowedApplication`），其餘流量仍走隧道
- 需要 `QUERY_ALL_PACKAGES`（Android 11+ 才能列出完整 App 清單），僅供旁載/個人使用

### IPv6

- TUN 同時配置 `fd00::2/128`；IPv6 封包解析、checksum（pseudo-header）、SOCKS5 ATYP=0x04（CONNECT 與 UDP 雙向）皆已支援
- 已知限制：不處理 IPv6 extension header；ICMP 不轉發