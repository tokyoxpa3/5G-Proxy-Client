package com.tokyoxpa3.socksclient

/**
 * 背景啟動重試狀態機的純邏輯（不依賴 Android，可用 JVM 單元測試）。
 * 語意與 TunSocksService 原本內嵌的 backgroundFail 一致：
 *  - [onStartFailure]：累計重試次數；達上限回 [Decision.Fail]；
 *    否則回 [Decision.Retry]，並在「開機啟動且已達閃前台門檻」時附帶 launchFlash
 *    （僅觸發一次，避免每次重試都重複拉起 Activity）。
 *  - [reset]：使用者停止或全新啟動成功時完全歸零。
 * 副作用（postDelayed、launchAutoStartActivity、fail）留在呼叫端執行。
 */
class BackgroundStartRetry(
    private val maxRetries: Int = 30,
    private val flashAfterRetries: Int = 3,
    private val retryDelayMs: Long = 10_000L
) {
    sealed class Decision {
        data class Retry(val retryCount: Int, val launchFlash: Boolean, val delayMs: Long) : Decision()
        object Fail : Decision()
    }

    private var retryCount = 0
    private var flashLaunched = false

    fun onStartFailure(isBoot: Boolean): Decision {
        if (retryCount >= maxRetries) return Decision.Fail
        retryCount++
        val launchFlash = isBoot && !flashLaunched && retryCount >= flashAfterRetries
        if (launchFlash) flashLaunched = true
        return Decision.Retry(retryCount, launchFlash, retryDelayMs)
    }

    fun reset() {
        retryCount = 0
        flashLaunched = false
    }
}
