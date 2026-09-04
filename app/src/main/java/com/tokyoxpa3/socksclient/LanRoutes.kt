package com.tokyoxpa3.socksclient

/**
 * LAN 繞過路由表（純邏輯）：只把「公網單播」導進 VPN 隧道，私網／link-local
 * ／loopback／multicast 一律不導，讓區網裝置（NAS、印表機、其他電腦）可直連。
 *
 * IPv4 排除：RFC1918（10/8、172.16/12、192.168/16）、link-local 169.254/16、
 * loopback 127/8、0/8、multicast 224/4 以上（含 reserved）。
 * IPv6 排除：link-local fe80::/10、ULA fc00::/7、multicast ff00::/8；
 * 僅保留全域單播 2000::/3 與 Remote DNS 的 fake IPv6 區段 fd00::/8。
 */
object LanRoutes {

    // 標準「全公網單播」CIDR 表：逐一覆蓋 0.0.0.0–223.255.255.255，
    // 挖掉 0/8、10/8、127/8、169.254/16、172.16/12、192.168/16 與 224/4+。
    // 每一筆為 (address, prefixLength)。順序無關，僅需完整且互不重疊。
    private val V4: List<Pair<String, Int>> = listOf(
        "1.0.0.0" to 8,       // 1.x
        "2.0.0.0" to 7,       // 2.x–3.x
        "4.0.0.0" to 6,       // 4.x–7.x
        "8.0.0.0" to 7,       // 8.x–9.x
        "11.0.0.0" to 8,      // 11.x
        "12.0.0.0" to 6,      // 12.x–15.x
        "16.0.0.0" to 4,      // 16.x–31.x
        "32.0.0.0" to 3,      // 32.x–63.x
        "64.0.0.0" to 3,      // 64.x–95.x
        "96.0.0.0" to 4,      // 96.x–111.x
        "112.0.0.0" to 5,     // 112.x–119.x
        "120.0.0.0" to 6,     // 120.x–123.x
        "124.0.0.0" to 7,     // 124.x–125.x
        "126.0.0.0" to 8,     // 126.x
        "128.0.0.0" to 3,     // 128.x–159.x
        "160.0.0.0" to 5,     // 160.x–167.x
        "168.0.0.0" to 8,     // 168.x
        "169.0.0.0" to 9,     // 169.0–169.127
        "169.128.0.0" to 10,  // 169.128–169.191
        "169.192.0.0" to 11,  // 169.192–169.223
        "169.224.0.0" to 12,  // 169.224–169.239
        "169.240.0.0" to 13,  // 169.240–169.247
        "169.248.0.0" to 14,  // 169.248–169.251
        "169.252.0.0" to 15,  // 169.252–169.253
        "169.255.0.0" to 16,  // 169.255.x
        "170.0.0.0" to 7,     // 170.x–171.x
        "172.0.0.0" to 12,    // 172.0–172.15
        "172.32.0.0" to 11,   // 172.32–172.63
        "172.64.0.0" to 10,   // 172.64–172.127
        "172.128.0.0" to 9,   // 172.128–172.255
        "173.0.0.0" to 8,     // 173.x
        "174.0.0.0" to 7,     // 174.x–175.x
        "176.0.0.0" to 4,     // 176.x–191.x
        "192.0.0.0" to 9,     // 192.0–192.127
        "192.128.0.0" to 11,  // 192.128–192.159
        "192.160.0.0" to 13,  // 192.160–192.167
        "192.169.0.0" to 16,  // 192.169.x
        "192.170.0.0" to 15,  // 192.170–192.171
        "192.172.0.0" to 14,  // 192.172–192.175
        "192.176.0.0" to 12,  // 192.176–192.191
        "192.192.0.0" to 10,  // 192.192–192.255
        "193.0.0.0" to 8,     // 193.x
        "194.0.0.0" to 7,     // 194.x–195.x
        "196.0.0.0" to 6,     // 196.x–199.x
        "200.0.0.0" to 5,     // 200.x–207.x
        "208.0.0.0" to 4      // 208.x–223.x
    )

    private val V6: List<Pair<String, Int>> = listOf(
        "2000::" to 3,   // 全域單播（排除 link-local / ULA / multicast）
        "fd00::" to 8    // Remote DNS fake IPv6 區段（fd00::5e00:x）
    )

    fun v4(): List<Pair<String, Int>> = V4

    fun v6(): List<Pair<String, Int>> = V6

    // 判斷某 IPv4 數字字串是否落在任一 v4 路由內（供測試與除錯）。
    fun containsV4(ipv4: String): Boolean {
        val parts = ipv4.split('.')
        if (parts.size != 4) return false
        val b = IntArray(4)
        for (i in 0 until 4) {
            b[i] = parts[i].toIntOrNull() ?: return false
            if (b[i] !in 0..255) return false
        }
        val addr = ((b[0] and 0xFF) shl 24) or ((b[1] and 0xFF) shl 16) or
            ((b[2] and 0xFF) shl 8) or (b[3] and 0xFF)
        for ((cidr, prefix) in V4) {
            val c = cidr.split('.')
            val base = ((c[0].toInt() and 0xFF) shl 24) or ((c[1].toInt() and 0xFF) shl 16) or
                ((c[2].toInt() and 0xFF) shl 8) or (c[3].toInt() and 0xFF)
            val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
            if ((addr and mask) == (base and mask)) return true
        }
        return false
    }
}
