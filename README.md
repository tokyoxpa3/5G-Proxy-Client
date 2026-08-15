# Android SOCKS5 TUN Tunnel Client

把整台裝置的網路流量透過 TUN 虛擬網卡導向遠端 SOCKS5 伺服器的 Android 客戶端。

- **UDP / DNS / QUIC**：透過 SOCKS5 **UDP ASSOCIATE** relay，讓 DNS 與 HTTP/3（QUIC）都能穿透
- **TCP**：內建完整的 TCP 狀態機（於使用者空間實作），透過 SOCKS5 **CONNECT** 轉發
- 原生 C（epoll）引擎 + JNI + Kotlin UI + 前台 VpnService

---

## 架構

```
[App] --TUN(10.8.0.2)--> [C 引擎: tun_socks.c] --SOCKS5--> [遠端 SOCKS5 伺服器] --> [目標網站]
                                │
                                └── 以 VpnService.protect() 建立通往伺服器的 socket
```

- `VpnService` 建立 TUN（`10.8.0.2/32`、MTU 1500、路由全走隧道、DNS 8.8.8.8/1.1.1.1）
- 原生引擎為單一 epoll 執行緒，直接讀寫 TUN fd 與 relay socket（`request_java_socket` 由 JNI 呼叫 Java 建立 **protected** socket，繞過隧道避免迴圈）
- TCP 於使用者空間實作：SYN/SYN-ACK、序號追蹤、**Window Scale（WS=10）**、依 App 通告 window 的**流量控制**、緩衝滿時**回壓**、handshake 期間**首包緩衝**（避免等 App 重傳造成 10 秒級延遲）

### 關鍵檔案

| 檔案 | 說明 |
|---|---|
| `app/src/main/cpp/tun_socks.c` | 核心引擎：TUN 讀寫、TCP/UDP 狀態機、SOCKS5 協定、流量控制 |
| `app/src/main/cpp/jni_bridge.c` | JNI 橋接（socket 取得、引擎生命週期） |
| `app/src/main/java/.../TunSocksService.kt` | VpnService + 前台服務 + `protect()` |
| `app/src/main/java/.../NativeEngine.kt` | 原生引擎的 JNI 宣告 |
| `app/src/main/java/.../MainActivity.kt` | 設定頁面（伺服器 / 連接埠 / 認證） |

---

## 使用方式

1. 準備一個 **SOCKS5 伺服器**（任何標準 SOCKS5 伺服器皆可，本專案另有配套的簡易 Android 伺服器實作，位於獨立的 repository）
2. 安裝 APK 並開啟 App
3. 填入伺服器 IP 與連接埠（預設 `1080`），認證可留空
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

- 每個（來源 IP, 來源 port）建立獨立 UDP session，與伺服器交換 relay 位址後互轉
- 首次封包於 handshake 期間緩衝，完成後立即送出——避免 DNS / QUIC Initial 被丟棄後等 App 指數退避重傳
- session 閒置 120 秒回收