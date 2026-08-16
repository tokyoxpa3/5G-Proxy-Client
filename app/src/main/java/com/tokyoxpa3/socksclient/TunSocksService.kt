package com.tokyoxpa3.socksclient

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class TunSocksService : VpnService() {

    companion object {
        const val TAG = "TunSocksService"
        const val NOTIFICATION_ID = 2001
        const val CHANNEL_ID = "tun_socks_channel"

        const val ACTION_START = "com.tokyoxpa3.socksclient.START"
        const val ACTION_STOP = "com.tokyoxpa3.socksclient.STOP"
        const val ACTION_STATUS = "com.tokyoxpa3.socksclient.STATUS"

        // 5G 高頻寬×高延遲（BDP 常 >1MB），relay socket buffer 太小會卡住吞吐量。
        // 在 connect 前設定，讓 kernel 直接以較大 window 協商。
        const val SOCKET_BUFFER_SIZE = 1 * 1024 * 1024

        const val EXTRA_HOST = "TUNNEL_HOST"
        const val EXTRA_PORT = "TUNNEL_PORT"
        const val EXTRA_USER = "TUNNEL_USER"
        const val EXTRA_PASS = "TUNNEL_PASS"
        const val EXTRA_UDP_IN_TCP = "TUNNEL_UDP_IN_TCP"

        @Volatile
        var isRunning = false

        @Volatile
        var lastStatus = ""
    }

    private val activeSockets = ConcurrentHashMap<Int, Any>()
    private val serviceScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob()
    )

    override fun onCreate() {
        super.onCreate()
        isRunning = false
        DebugLog.init(this)
        lastStatus = getString(R.string.status_not_started)
        createNotificationChannel()
        NativeEngine.onSocketClosed = { fd ->
            val socket = activeSockets.remove(fd)
            if (socket is AutoCloseable) {
                try {
                    socket.close()
                } catch (e: Exception) {
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopTunnel()
            else -> startTunnel(intent)
        }
        return START_STICKY
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.w(TAG, "VPN revoked by system, stopping tunnel")
        stopTunnel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startTunnel(intent: Intent?) {
        if (isRunning) return
        val host = intent?.getStringExtra(EXTRA_HOST)?.trim().orEmpty()
        val port = intent?.getIntExtra(EXTRA_PORT, 1080) ?: 1080
        val user = intent?.getStringExtra(EXTRA_USER)?.trim().orEmpty()
        val pass = intent?.getStringExtra(EXTRA_PASS)?.trim().orEmpty()
        val udpInTcp = intent?.getBooleanExtra(EXTRA_UDP_IN_TCP, false) ?: false
        if (host.isEmpty() || port <= 0 || port > 65535) {
            fail(getString(R.string.err_bad_params))
            return
        }
        Log.i(TAG, "startTunnel called: host=$host port=$port user=$user udpInTcp=$udpInTcp")

        try {
            // 一進服務就進入前台，避免 startForegroundService 5 秒限制
            startForeground(
                NOTIFICATION_ID,
                createNotification(getString(R.string.notification_connecting)),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )

            publishStatus(getString(R.string.status_resolving))
            // 必須在 VPN 建立前解析，避免自己的 DNS 查詢被隧道捕捉
            val serverIp = try {
                InetAddress.getByName(host).hostAddress
            } catch (e: Exception) {
                fail(getString(R.string.err_resolve_host, e.message))
                return
            }
            if (serverIp == null) {
                fail(getString(R.string.err_resolve_host, host))
                return
            }
            Log.d(TAG, "Server resolved to $serverIp")

            val builder = Builder()
            builder.setSession(getString(R.string.app_name))
            builder.setMtu(4096)
            builder.addAddress("10.8.0.2", 32)
            builder.addAddress("fd00::2", 128)
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
            builder.addDnsServer("8.8.8.8")
            builder.addDnsServer("1.1.1.1")

            // Per-App 模式：被勾選的 App 走手機本機網路（繞過隧道）
            getSharedPreferences("tunnel_config", MODE_PRIVATE)
                .getStringSet(AppListActivity.KEY_EXCLUDED, emptySet())
                ?.forEach { pkg ->
                    if (pkg.isNotBlank()) {
                        try {
                            builder.addDisallowedApplication(pkg)
                            Log.d(TAG, "Excluding app from tunnel: $pkg")
                        } catch (e: Exception) {
                            Log.w(TAG, "addDisallowedApplication($pkg) failed: ${e.message}")
                        }
                    }
                }

            val tunFd = builder.establish()
            if (tunFd == null) {
                fail(getString(R.string.err_vpn_establish))
                return
            }

            NativeEngine.socketProvider = { h, p, isUdp -> createProtectedSocket(h, p, isUdp) }
            NativeEngine.registerInstance()
            Log.d(TAG, "Calling native startTunnel")
            val result = NativeEngine.startTunnel(tunFd.detachFd(), serverIp, port, user, pass, udpInTcp)
            Log.d(TAG, "native startTunnel result: $result")

            isRunning = true
            publishStatus(getString(R.string.status_tunnel_active, host, port))
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(NOTIFICATION_ID, createNotification(getString(R.string.notification_running)))
        } catch (e: Exception) {
            Log.e(TAG, "startTunnel failed", e)
            val msg = getString(R.string.err_start, e.message)
            DebugLog.recordError(msg)
            fail(msg)
        }
    }

    private fun fail(msg: String) {
        DebugLog.recordError(msg)
        publishStatus(msg)
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) {}
        stopSelf()
    }

    private fun stopTunnel() {
        publishStatus(getString(R.string.status_stopping))
        serviceScope.launch {
            try {
                NativeEngine.stopTunnel()
            } catch (e: Exception) {
                Log.e(TAG, "stopTunnel error", e)
            }
            activeSockets.values.forEach {
                if (it is AutoCloseable) {
                    try {
                        it.close()
                    } catch (e: Exception) {
                    }
                }
            }
            activeSockets.clear()
            isRunning = false
            publishStatus(getString(R.string.status_stopped))
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) {}
            stopSelf()
        }
    }

    /**
     * 建立通往 SOCKS5 伺服器的 socket，並以 protect() 繞過 VPN 隧道，
     * 避免自己的控制流量被 TUN 捕捉造成迴圈。
     *
     * 注意：new Socket() 在 Android 上不會立即建立底層 fd，直接 protect(Socket)
     * 會因為拿不到 fd 而靜默失敗；因此先 bind(0) 強制建立 fd 再 protect。
     */
    private fun createProtectedSocket(host: String, port: Int, isUdp: Boolean): Int {
        return try {
            if (isUdp) {
                val ds = DatagramSocket()
                ds.receiveBufferSize = SOCKET_BUFFER_SIZE
                ds.sendBufferSize = SOCKET_BUFFER_SIZE
                val ok = protect(ds)
                if (!ok) {
                    Log.e(TAG, "protect(DatagramSocket) 失敗")
                    ds.close()
                    return -1
                }
                val pfd = ParcelFileDescriptor.fromDatagramSocket(ds)
                val fd = pfd.detachFd()
                activeSockets[fd] = ds
                fd
            } else {
                val socket = Socket()
                socket.setReceiveBufferSize(SOCKET_BUFFER_SIZE)
                socket.setSendBufferSize(SOCKET_BUFFER_SIZE)
                socket.bind(InetSocketAddress(0)) // 強制建立 fd（綁定暫存埠）
                val ok = protect(socket)
                if (!ok) {
                    Log.e(TAG, "protect(Socket) 失敗")
                    socket.close()
                    return -1
                }
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(host, port), 5000)
                val pfd = ParcelFileDescriptor.fromSocket(socket)
                val fd = pfd.detachFd()
                activeSockets[fd] = socket
                fd
            }
        } catch (e: Exception) {
            Log.e(TAG, "createProtectedSocket failed ($host:$port udp=$isUdp): ${e.message}")
            -1
        }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        )
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun createNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun publishStatus(text: String) {
        lastStatus = text
        Log.i(TAG, "Status: $text")
        sendBroadcast(Intent(ACTION_STATUS).putExtra("status", text))
    }

    override fun onDestroy() {
        serviceScope.cancel()
        isRunning = false
        super.onDestroy()
    }
}
