package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundStartRetryTest {

    @Test
    fun retryIncrementsUntilMax() {
        val retry = BackgroundStartRetry(maxRetries = 3, flashAfterRetries = 2, retryDelayMs = 100L)

        val d1 = retry.onStartFailure(false) as BackgroundStartRetry.Decision.Retry
        assertEquals(1, d1.retryCount)
        assertEquals(100L, d1.delayMs)
        assertFalse(d1.launchFlash)

        val d2 = retry.onStartFailure(false) as BackgroundStartRetry.Decision.Retry
        assertEquals(2, d2.retryCount)

        val d3 = retry.onStartFailure(false) as BackgroundStartRetry.Decision.Retry
        assertEquals(3, d3.retryCount)

        assertTrue(retry.onStartFailure(false) is BackgroundStartRetry.Decision.Fail)
    }

    @Test
    fun flashLaunchesOnlyOnceForBoot() {
        val retry = BackgroundStartRetry(maxRetries = 10, flashAfterRetries = 3, retryDelayMs = 10L)

        // 非開機啟動：即使達門檻也不觸發閃前台
        assertFalse((retry.onStartFailure(false) as BackgroundStartRetry.Decision.Retry).launchFlash)
        assertFalse((retry.onStartFailure(false) as BackgroundStartRetry.Decision.Retry).launchFlash)

        // 開機啟動且達門檻：僅這次觸發
        assertTrue((retry.onStartFailure(true) as BackgroundStartRetry.Decision.Retry).launchFlash)

        // 之後不再重複觸發
        assertFalse((retry.onStartFailure(true) as BackgroundStartRetry.Decision.Retry).launchFlash)
    }

    @Test
    fun resetRestoresCountAndFlash() {
        val retry = BackgroundStartRetry(maxRetries = 3, flashAfterRetries = 2, retryDelayMs = 10L)
        retry.onStartFailure(true)
        retry.onStartFailure(true)

        retry.reset()

        val d = retry.onStartFailure(false) as BackgroundStartRetry.Decision.Retry
        assertEquals(1, d.retryCount)
        assertFalse(d.launchFlash)
    }
}
