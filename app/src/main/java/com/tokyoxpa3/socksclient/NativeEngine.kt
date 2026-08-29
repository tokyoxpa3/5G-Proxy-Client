package com.tokyoxpa3.socksclient

import android.util.Log

object NativeEngine {
    private const val TAG = "NativeEngine"
    private var libraryLoaded = false
    private var initialized = false

    var socketProvider: ((String, Int, Boolean) -> Int)? = null
    var onSocketClosed: ((Int) -> Unit)? = null
    var onServerEvent: ((Boolean) -> Unit)? = null

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
    fun notifyServerEvent(ok: Boolean) {
        onServerEvent?.invoke(ok)
    }

    external fun startTunnel(fd: Int, host: String, port: Int, user: String, pass: String, udpInTcp: Boolean, remoteDns: Boolean): String
    external fun stopTunnel(): String

    // soft-reconnect：不拆 TUN/VPN，重置引擎連線狀態（回傳 null=成功，字串=失敗原因）
    external fun reconnect(): String?

    // [txBytes(→server), rxBytes(←server), tcpSessions, udpSessions]
    external fun getStats(): LongArray
}
