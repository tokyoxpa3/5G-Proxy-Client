package com.tokyoxpa3.socksclient

import android.util.Log

object NativeEngine {
    private const val TAG = "NativeEngine"
    private var libraryLoaded = false
    private var initialized = false

    // 這些回呼由原生 handshake / 引擎執行緒經 JNI 呼叫、主執行緒寫入，
    // 標 @Volatile 確保跨執行緒記憶體可見性。
    // 伺服器事件碼（與原生 jni_bridge.h 的 enum server_event 一致）
    const val EVENT_OK = 0
    const val EVENT_NETWORK_FAIL = 1
    const val EVENT_AUTH_FAIL = 2
    const val EVENT_PROTOCOL_FAIL = 3

    @Volatile var socketProvider: ((String, Int, Boolean) -> Int)? = null
    @Volatile var onSocketClosed: ((Int) -> Unit)? = null
    @Volatile var onServerEvent: ((Int) -> Unit)? = null
    @Volatile var onEngineStopped: ((Boolean) -> Unit)? = null

    init {
        try {
            Log.d(TAG, "Loading native library: socksclient")
            System.loadLibrary("socksclient")
            libraryLoaded = true
            Log.d(TAG, "Native library loaded successfully")
        } catch (e: Throwable) {
            // UnsatisfiedLinkError 是 Error 不是 Exception——不接住會直接閃退
            Log.e(TAG, "Failed to load native library: ${e.message}")
            libraryLoaded = false
        }
    }

    fun isLibraryLoaded(): Boolean = libraryLoaded

    fun registerInstance() {
        if (!initialized && socketProvider != null) {
            Log.d(TAG, "Registering NativeEngine instance with native layer")
            nativeRegisterInstance()
            initialized = true
        }
    }

    private external fun nativeRegisterInstance()

    fun createSocketFromNative(host: String, port: Int, isUdp: Boolean): Int {
        return socketProvider?.invoke(host, port, isUdp) ?: -1
    }

    fun notifySocketClosed(fd: Int) {
        onSocketClosed?.invoke(fd)
    }

    // 原生引擎回報伺服器連線事件：true=成功、false=網路層失敗
    fun notifyServerEvent(code: Int) {
        onServerEvent?.invoke(code)
    }

    // 原生引擎意外退出（非正常停止，例如 epoll 錯誤）→ 通知服務層清除 isRunning 等狀態
    fun notifyEngineStopped(unexpected: Boolean) {
        onEngineStopped?.invoke(unexpected)
    }

    external fun startTunnel(fd: Int, host: String, port: Int, user: String, pass: String, udpInTcp: Boolean, remoteDns: Boolean): String
    external fun stopTunnel(): String

    // soft-reconnect：不拆 TUN/VPN，重置引擎連線狀態（回傳 null=成功，字串=失敗原因）
    external fun reconnect(): String?

    // [txBytes(→server), rxBytes(←server), tcpSessions, udpSessions]
    external fun getStats(): LongArray
}
