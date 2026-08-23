package com.tokyoxpa3.socksclient

import java.util.ArrayDeque

/**
 * 伺服器斷線偵測 + 自動重啟退避的純邏輯（不依賴 Android，可用 JVM 單元測試）。
 *
 * 語意（與 TunSocksService 原本內嵌版本一致）：
 *  - [onSuccess]：任一 CONNECT/ASSOCIATE 成功 → 清除失敗紀錄與退避計數
 *  - [onNetworkFailure]：網路層失敗（socket 建立逾時等）→ 滑動窗口累計；
 *    門檻到達且無排程中的重啟 → 回傳 [Decision.Restart]，延遲依次數遞增
 *    （base×次數，上限 maxDelayMs）。
 *  - [restartScheduled]：由外部在排程 Runnable 後設 true、觸發後設 false，
 *    防止同一窗口內重複排程。
 *  - 協定層錯誤（認證被拒、REP≠0、非 SOCKS5 伺服器）不應呼叫 [onNetworkFailure]，
 *    這由原生引擎的 network_fail 旗標決定。
 */
class ServerWatchdog(
    private val clock: () -> Long,
    private val failWindowMs: Long = 60_000L,
    private val failThreshold: Int = 3,
    private val baseDelayMs: Long = 10_000L,
    private val maxDelayMs: Long = 300_000L
) {
    sealed class Decision {
        /** 應在 delayMs 後自動重啟隧道 */
        data class Restart(val delayMs: Long) : Decision()

        /** 不需動作（未達門檻／已有排程／間隔太近） */
        object None : Decision()
    }

    private val failures = ArrayDeque<Long>()

    /** 已有排程中的自動重啟（外部配合 Runnable 同步維護） */
    var restartScheduled: Boolean = false
        internal set

    /** 連續自動重啟次數（未成功前遞增，退避 = base×次數） */
    var autoRestartCount: Int = 0
        private set

    // Long.MIN_VALUE = 「從未排程過」，避免首次排程被間隔下限誤擋
    private var lastScheduledAt = Long.MIN_VALUE

    /** 連線成功：清除失敗紀錄與退避計數 */
    fun onSuccess() {
        failures.clear()
        autoRestartCount = 0
        restartScheduled = false
        lastScheduledAt = Long.MIN_VALUE
    }

    /** 網路層失敗：回傳是否／多久後自動重啟 */
    fun onNetworkFailure(): Decision {
        val now = clock()
        failures.addLast(now)
        while (failures.isNotEmpty() && now - failures.first() > failWindowMs) {
            failures.removeFirst()
        }
        if (failures.size < failThreshold) return Decision.None
        if (restartScheduled) return Decision.None
        // 與上次排程至少間隔 baseDelayMs（Long.MIN_VALUE 表示從未排程過；
        // 不能直接相減——0 - MIN_VALUE 會溢位成負數誤擋首次排程）
        if (lastScheduledAt != Long.MIN_VALUE && now - lastScheduledAt < baseDelayMs) return Decision.None
        lastScheduledAt = now
        autoRestartCount++
        val delayMs = minOf(baseDelayMs * autoRestartCount, maxDelayMs)
        restartScheduled = true
        return Decision.Restart(delayMs)
    }

    /** 排程的 Runnable 已觸發（重啟執行中）→ 允許下一個窗口重新排程 */
    fun onRestartFired() {
        restartScheduled = false
    }

    /**
     * 取消排程並清除失敗紀錄，但**保留退避計數**。
     * 供 restartTunnel 內部的 stopEngineSync 使用——若連計數一起清，
     * 自動重啟會永遠停在最小延遲（這正是早期實作的 bug）。
     */
    fun clearFailures() {
        failures.clear()
        restartScheduled = false
    }

    /** 使用者停止／全新啟動成功：完全歸零 */
    fun reset() {
        failures.clear()
        autoRestartCount = 0
        restartScheduled = false
        lastScheduledAt = Long.MIN_VALUE
    }
}
