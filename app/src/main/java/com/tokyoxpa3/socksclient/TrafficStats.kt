package com.tokyoxpa3.socksclient

import java.util.Locale

/**
 * 流量統計格式化的純邏輯（不依賴 Android，可用 JVM 單元測試）。
 *
 * 抽離動機：TunSocksService 原本的 formatBytes / statsText 內嵌於服務，
 * 是常駐通知唯一會改變顯示格式卻零測試的部分；抽成純函式後可鎖定顯示格式。
 */
object TrafficStats {

    /** 人類可讀位元組格式：B / KB / MB / GB（小數位隨量級收斂）。 */
    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
        return String.format(Locale.US, "%.2f GB", mb / 1024.0)
    }

    /**
     * 流量摘要（不含標題）：`↑tx ↓rx • TCP:n UDP:m`。
     * 原生 getStats 依序回傳 [txBytes, rxBytes, tcpSessions, udpSessions]，
     * 對不足長度的陣列以 0 補齊（防禦性，避免陣列越界）。
     */
    fun summary(stats: LongArray): String {
        val tx = stats.getOrElse(0) { 0L }
        val rx = stats.getOrElse(1) { 0L }
        val tcp = stats.getOrElse(2) { 0L }
        val udp = stats.getOrElse(3) { 0L }
        return "↑" + formatBytes(tx) + " ↓" + formatBytes(rx) + " • TCP:" + tcp + " UDP:" + udp
    }
}
