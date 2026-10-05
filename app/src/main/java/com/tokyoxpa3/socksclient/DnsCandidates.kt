package com.tokyoxpa3.socksclient

/**
 * 決定軟重連時「用哪些 DNS 解析伺服器主機名、依什麼順序試」的純邏輯
 * （不碰 Android API，可在一般 JVM 上單元測試）。
 *
 * 排序原則：**能少洩漏主機名的先試**。
 * - 底層網路（非 VPN）的 DNS 本來就承載整個隧道流量，查它不會讓任何人多知道一件事，
 *   且與 `startTunnel()` 首次解析（系統解析器）走同一條路徑。
 * - 使用者設定值（預設 8.8.8.8 / 1.1.1.1）排在後面，只在底層解析不到時才用；
 *   用到時呼叫端會寫 log（`fallback = true`），不靜默。
 */
object DnsCandidates {

    /** 一個 DNS 候選。`fallback = true` 表示這是設定值而非底層網路 DNS。 */
    data class Candidate(val server: String, val fallback: Boolean)

    /**
     * 合併成嘗試順序：底層網路 DNS（`fallback = false`）優先，其次設定值（`fallback = true`）。
     * 兩段各自保序去重；設定值中已出現於底層者不再重複列入（同一個伺服器沒必要查兩遍、
     * 多等一個逾時）。
     */
    fun plan(underlying: List<String>, configured: List<String>): List<Candidate> {
        val underlyingIps = normalize(underlying)
        val seen = underlyingIps.toMutableSet()
        val result = ArrayList<Candidate>(underlyingIps.size + configured.size)
        underlyingIps.forEach { result.add(Candidate(it, fallback = false)) }
        normalize(configured).forEach { ip ->
            if (seen.add(ip)) result.add(Candidate(ip, fallback = true))
        }
        return result
    }

    /**
     * 正規化：去前後空白、去 IPv6 zone id（`fe80::1%wlan0` → `fe80::1`）、
     * 丟掉非數字 IP（DNS 查詢只允許數字位址，避免遞迴解析）與連結本地 IPv6，並保序去重。
     */
    fun normalize(servers: List<String>): List<String> {
        val out = LinkedHashSet<String>()
        servers.forEach { raw ->
            val ip = raw.trim().substringBefore('%')
            if (ip.isEmpty() || !Config.isLiteralIp(ip)) return@forEach
            if (isLinkLocalV6(ip)) return@forEach
            out.add(ip)
        }
        return out.toList()
    }

    /**
     * 單一伺服器經 `normalize` 後的字串（被過濾則為 null）。
     *
     * 給「位址 → 來源網路」的對照表當 key 用：那個表必須與 `plan()` 實際吐出的字串**逐字**
     * 一致，否則查詢 socket 就綁不回它來源的網路 —— 而且是**靜默**退回預設路由。
     * 所以兩邊共用同一套正規化，並由 `normalizeOneMatchesWhatPlanEmits` 把這個契約鎖住。
     */
    fun normalizeOne(server: String): String? = normalize(listOf(server)).firstOrNull()

    /**
     * 連結本地 IPv6（`fe80::/10`）在**去掉 zone id 之後就送不出去** —— 沒有 scope 就不知道
     * 要走哪個介面，`DatagramPacket` 會直接拋錯。而 `LinkProperties.dnsServers` 給的正是
     * 帶 zone id 的形式（`fe80::1%wlan0`），所以留在候選裡只會白等一個 3 秒逾時
     * （實測本機 Wi-Fi 的第一個 DNS 就是這種）。直接排除。
     *
     * ⚠️ 必須比對第一個 hextet 的**數值**，不能比對文字。`fe8::1` 省略前導零，實際是
     * `0fe8::`（＝0000:1111:1110:1000），**不在** `fe80::/10`。舊版看「fe 之後的第一個
     * 字元是不是 8/9/a/b」，會把 `fe8::1`／`fe9::1`／`fea::1`／`feb::1`（0x0fe8–0x0feb）
     * 誤判成連結本地而丟掉（F-Droid 1.6.5 review 指出此 over-filtering，且既有測試把
     * 錯誤行為寫成了斷言）。
     */
    fun isLinkLocalV6(ip: String): Boolean {
        // 取第一個 hextet；呼叫端多半已去 zone id，這裡再保險一次
        val firstHextet = ip.substringBefore(':').substringBefore('%')
        // IPv6 的 hextet 最多 4 位十六進位；更長或非 hex 就不是合法位址，不判為連結本地
        if (firstHextet.isEmpty() || firstHextet.length > 4) return false
        val value = firstHextet.toIntOrNull(16) ?: return false
        // fe80::/10 = 1111 1110 10xx xxxx → 第一個 hextet 落在 0xfe80..0xfebf
        return value in 0xfe80..0xfebf
    }
}
