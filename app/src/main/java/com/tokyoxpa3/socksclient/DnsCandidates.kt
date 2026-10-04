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
     * 連結本地 IPv6（`fe80::/10`）在**去掉 zone id 之後就送不出去** —— 沒有 scope 就不知道
     * 要走哪個介面，`DatagramPacket` 會直接拋錯。而 `LinkProperties.dnsServers` 給的正是
     * 帶 zone id 的形式（`fe80::1%wlan0`），所以留在候選裡只會白等一個 3 秒逾時
     * （實測本機 Wi-Fi 的第一個 DNS 就是這種）。直接排除。
     */
    fun isLinkLocalV6(ip: String): Boolean {
        val lower = ip.lowercase()
        if (!lower.startsWith("fe")) return false
        // fe80::/10 = 1111 1110 10xx xxxx → 第二個 nibble 為 8/9/a/b
        return lower.removePrefix("fe").take(1) in listOf("8", "9", "a", "b")
    }
}
