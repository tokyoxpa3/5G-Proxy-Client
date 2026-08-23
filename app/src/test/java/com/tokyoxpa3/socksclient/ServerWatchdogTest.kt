package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ServerWatchdog 純邏輯單元測試——用假時鐘推進時間，
 * 不需 Android 環境即可驗證窗口 / 門檻 / 退避 / 重置語意。
 */
class ServerWatchdogTest {

    private class FakeClock(var now: Long = 0L) {
        fun advance(ms: Long) {
            now += ms
        }
    }

    private fun watchdog(clock: FakeClock) = ServerWatchdog(
        clock = { clock.now },
        failWindowMs = 60_000L,
        failThreshold = 3,
        baseDelayMs = 10_000L,
        maxDelayMs = 300_000L
    )

    // 餵 N 次失敗，回傳最後一次的決策
    private fun failN(w: ServerWatchdog, n: Int): ServerWatchdog.Decision {
        var last: ServerWatchdog.Decision = ServerWatchdog.Decision.None
        repeat(n) { last = w.onNetworkFailure() }
        return last
    }

    @Test
    fun belowThreshold_noRestart() {
        val clock = FakeClock()
        val w = watchdog(clock)
        assertEquals(ServerWatchdog.Decision.None, w.onNetworkFailure())
        assertEquals(ServerWatchdog.Decision.None, w.onNetworkFailure())
        // 第 3 次才到門檻
        assertTrue(w.onNetworkFailure() is ServerWatchdog.Decision.Restart)
    }

    @Test
    fun thresholdDelay_usesBaseCount() {
        val clock = FakeClock(100_000L)
        val w = watchdog(clock)
        val d = failN(w, 3)
        // 退避 = 10s × 1
        assertTrue(d is ServerWatchdog.Decision.Restart)
        assertEquals(10_000L, (d as ServerWatchdog.Decision.Restart).delayMs)
        assertEquals(1, w.autoRestartCount)
    }

    @Test
    fun oldFailures_evictedFromWindow() {
        val clock = FakeClock()
        val w = watchdog(clock)
        w.onNetworkFailure()
        w.onNetworkFailure()
        clock.advance(61_000L)          // 前兩次掉出 60s 窗口
        w.onNetworkFailure()            // 窗口內僅 1 次
        assertEquals(ServerWatchdog.Decision.None, w.onNetworkFailure())
    }

    @Test
    fun backoff_escalatesAcrossCycles() {
        val clock = FakeClock(100_000L)
        val w = watchdog(clock)
        val delays = mutableListOf<Long>()
        // 第 1 輪：3 次失敗 → restart 10s
        delays.add((failN(w, 3) as ServerWatchdog.Decision.Restart).delayMs)
        // 重啟過程消耗一些時間
        w.onRestartFired()
        w.clearFailures()
        clock.advance(120_000L)
        // 第 2 輪
        delays.add((failN(w, 3) as ServerWatchdog.Decision.Restart).delayMs)
        // 第 3 輪
        w.onRestartFired()
        w.clearFailures()
        clock.advance(120_000L)
        delays.add((failN(w, 3) as ServerWatchdog.Decision.Restart).delayMs)

        assertEquals(listOf(10_000L, 20_000L, 30_000L), delays)
    }

    @Test
    fun backoff_capsAtMax() {
        val clock = FakeClock(100_000L)
        val w = ServerWatchdog(
            clock = { clock.now },
            failWindowMs = 60_000L,
            failThreshold = 1,          // 每次失敗都觸發，加速測試上限
            baseDelayMs = 10_000L,
            maxDelayMs = 25_000L
        )
        // 觸發多次重啟循環（每次重啟後推進時間）
        repeat(5) {
            w.onNetworkFailure()
            w.onRestartFired()
            w.clearFailures()
            clock.advance(120_000L)
        }
        val d = failN(w, 1)
        assertTrue(d is ServerWatchdog.Decision.Restart)
        assertEquals(25_000L, (d as ServerWatchdog.Decision.Restart).delayMs)
    }

    @Test
    fun success_resetsEverything() {
        val clock = FakeClock()
        val w = watchdog(clock)
        assertTrue(failN(w, 3) is ServerWatchdog.Decision.Restart)
        assertEquals(1, w.autoRestartCount)

        w.onSuccess()

        assertEquals(0, w.autoRestartCount)
        assertFalse(w.restartScheduled)
        // 成功後再次失敗，重新從最小退避開始
        val d = failN(w, 3)
        assertTrue(d is ServerWatchdog.Decision.Restart)
        assertEquals(10_000L, (d as ServerWatchdog.Decision.Restart).delayMs)
    }

    @Test
    fun scheduledRestart_blocksReschedule() {
        val clock = FakeClock()
        val w = watchdog(clock)
        assertTrue(failN(w, 3) is ServerWatchdog.Decision.Restart)
        // 尚未 onRestartFired：同一窗口不會再排程
        assertEquals(ServerWatchdog.Decision.None, w.onNetworkFailure())
        assertEquals(ServerWatchdog.Decision.None, w.onNetworkFailure())
    }

    @Test
    fun reset_clearsCountAndFailures() {
        val clock = FakeClock()
        val w = watchdog(clock)
        assertTrue(failN(w, 3) is ServerWatchdog.Decision.Restart)
        assertEquals(1, w.autoRestartCount)

        w.reset()

        assertEquals(0, w.autoRestartCount)
        assertFalse(w.restartScheduled)
        val d = failN(w, 3)
        assertTrue(d is ServerWatchdog.Decision.Restart)
        assertEquals(10_000L, (d as ServerWatchdog.Decision.Restart).delayMs)
    }
}
