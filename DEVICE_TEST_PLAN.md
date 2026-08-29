# 實機測試清單（device test plan）

對應 `improve/device-hardening` 分支。此輪改動有兩處**行為變更**需重點驗證：
per-app 模式語意、IPv6 fragment offset 修正；其餘為等價重構（純邏輯抽離、key 統一、
jni 原子化），跑冒煙回歸即可。

## 前置

- 裝置連線並啟用 USB 偵錯：`adb devices` 應列出裝置。
- 安裝本次建置的 release APK：

  ```
  adb install -r app/build/outputs/apk/release/app-release.apk
  ```

- 準備一個可連的 SOCKS5 伺服器（host / port，選配 user / pass）。

## P1 — per-app 模式（行為變更，必測）

1. **空 ALLOWLIST 防呆**
   - 模式選「僅允許以下 App」→ 不勾選任何 App → 按啟動。
   - 預期：彈 Toast「僅允許模式尚未選擇任何 App…」，VPN 未建立、無常駐通知。
   - 對照：勾選至少一個 App 後應能正常啟動。

2. **三種模式逐一驗證**
   - GLOBAL：不進 App 清單；所有流量走隧道（瀏覽器查 `whatismyip` 顯示伺服器 IP）。
   - ALLOWLIST：只勾瀏覽器；瀏覽器走隧道、其他 App（如 termux `curl ifconfig.me`）不走。
   - EXCLUDE：勾瀏覽器；瀏覽器不走、其餘走。

3. **Profile 帶 App 清單**
   - 儲存 profile A（勾選 App X）→ 清空 App 清單 → 載入 profile A。
   - 預期：App 清單恢復為 X、模式一併套用（AppListActivity 勾選狀態與模式 radio 都變）。

## P2 — 回歸冒煙（確認引擎封包入口沒打壞）

4. **基本連通**：啟動後開 `https://www.google.com/generate_204` → 應 204。
5. **Remote DNS（fakedns）**：啟用後確認 DNS 被攔截（回 `198.18.0.x`）。
6. **啟動 / 停止 / 重連**：停止後常駐通知消失、`whatismyip` 回本機 IP；通知列「重新啟動」可恢復；斷開伺服器後 60 秒內看門狗觸發自動重連（狀態列顯示倒數）。
7. **開機自啟**（若啟用）：開機後隧道自動恢復；Samsung 裝置注意「閃一下」流程。

## P3 — IPv6 fragment（已知修正，難自然觸發）

- 修正 `ipv6_first_frag` 的 offset 取值（`(ff & 0x1FFF)` → `((ff >> 3) & 0x1FFF)`，RFC 8200）。
- 實務行動網路極少送 IPv6 分片，此修正由 RFC + unit test 背書；要裝置驗證需同網段合成 IPv6 分片流量打入 tun0，成本高、非必要。列為「已知修正」，release note 註明即可。

## 壓力測試（沿用 v1.4.1 方法）

- Monkey：`adb shell monkey -p com.tokyoxpa3.socksclient 500 --throttle 120`，再跑 `200 --throttle 120`，確認無 ANR / tombstone。
- TCP 併發：60× `curl` 穿透隧道（example.com / generate_204），觀察 `tun0` rx/tx 穩定。
- DNS flood：30× `dns_q.bin` 走 `nc -u` + fakedns，應 100% 攔截回 `198.18.0.x`。
- 資源：`chk_test` `bad=0`、30s idle 後 VmRSS / PSS 無成長、FD 數穩定。

## 判準

- P1 全過：per-app 語意正確。
- P2 全過：無回歸。
- 壓力測試：無 tombstone、無 FD 洩漏、記憶體穩定。
