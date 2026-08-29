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
import android.os.Handler
import android.os.IBinder
import android.os.Looper
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
        const val CHANNEL_ID = "tun_socks_channel_v2"
        const val FLASH_CHANNEL_ID = "tun_socks_flash_channel_v2"

        const val ACTION_START = "com.tokyoxpa3.socksclient.START"
        const val ACTION_STOP = "com.tokyoxpa3.socksclient.STOP"
        const val ACTION_RESTART = "com.tokyoxpa3.socksclient.RESTART"
        const val ACTION_STATUS = "com.tokyoxpa3.socksclient.STATUS"

        // 5G 高頻寬×高延遲（BDP 常 >1MB），relay socket buffer 太小會卡住吞吐量。
        // 在 connect 前設定，讓 kernel 直接以較大 window 協商。
        const val SOCKET_BUFFER_SIZE = 1 * 1024 * 1024

        const val EXTRA_HOST = "TUNNEL_HOST"
        const val EXTRA_PORT = "TUNNEL_PORT"
        const val EXTRA_USER = "TUNNEL_USER"
        const val EXTRA_PASS = "TUNNEL_PASS"
        const val EXTRA_UDP_IN_TCP = "TUNNEL_UDP_IN_TCP"
        const val EXTRA_REMOTE_DNS = "TUNNEL_REMOTE_DNS"
        const val EXTRA_BOOT_START = "TUNNEL_BOOT_START"

        private const val BACKGROUND_RETRY_DELAY_MS = 10_000L
        private const val MAX_BACKGROUND_RETRIES = 30

        // 自動重連看門狗：60 秒內 ≥3 次網路層連線失敗 → 判定伺服器斷線，
        // 以遞增延遲（10s×次數，上限 5 分鐘）自動重啟隧道；任一次成功即重置。
        private const val SERVER_FAIL_WINDOW_MS = 60_000L
        private const val SERVER_FAIL_THRESHOLD = 3
        private const val AUTO_RESTART_BASE_DELAY_MS = 10_000L
        private const val AUTO_RESTART_MAX_DELAY_MS = 300_000L

        // 常駐通知流量統計更新間隔
        private const val STATS_UPDATE_INTERVAL_MS = 3_000L
        // Samsung 開機後 establish() 需要該 App 至少一次在前台成功建立 VPN 才會放行背景呼叫；
        // 背景重試失敗幾次後，自動開啟 MainActivity（前台建立）再自動關閉
        private const val BOOT_FLASH_AFTER_RETRIES = 3

        @Volatile
        var isRunning = false

        @Volatile
        var lastStatus = ""
    }

    private val activeSockets = ConcurrentHashMap<Int, Any>()
    private val serviceScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.Dispatchers.IO + kotlinx.coroutines.SupervisorJob()
    )
    private val mainHandler = Handler(Looper.getMainLooper())

    // 開機自啟 / 磁貼 / START_STICKY 重建等背景啟動：網路與 DNS 在開機當下可能尚未就緒，
    // 失敗後定時重試（有界），避免隧道永遠起不來。
    private val backgroundStartRetry = object : Runnable {
        override fun run() { startTunnel(null) }
    }
    private var backgroundRetryCount = 0
    private var bootContext = false
    private var flashLaunched = false

    // 啟動進行中標記：DNS 解析移到背景執行緒後，防止「解析期間按下停止／重啟」
    // 後舊的啟動流程又回頭完成 VPN 建立（stop/restart 會清除此旗標使流程失效）
    @Volatile
    private var startPending = false

    // 自動重連看門狗（純邏輯，可獨立測試）
    private val serverWatchdog = ServerWatchdog(
        clock = { android.os.SystemClock.elapsedRealtime() },
        failWindowMs = SERVER_FAIL_WINDOW_MS,
        failThreshold = SERVER_FAIL_THRESHOLD,
        baseDelayMs = AUTO_RESTART_BASE_DELAY_MS,
        maxDelayMs = AUTO_RESTART_MAX_DELAY_MS
    )
    private val serverEventLock = Any()
    private var autoRestartRunnable: Runnable? = null

    // 自動重啟進行中標記：讓「看門狗觸發的重啟」不重置退避計數（僅使用者/開機的全新啟動才重置）
    @Volatile
    private var autoRestartInProgress = false

    // 常駐通知流量統計更新協程
    private var statsJob: kotlinx.coroutines.Job? = null

    // 上次已顯示的流量摘要：數值未變時略過 notify，避免常駐通知每 3 秒無謂重建
    @Volatile
    private var lastStatsText: String? = null

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
        NativeEngine.onServerEvent = { ok -> onServerEvent(ok) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopTunnel()
            ACTION_RESTART -> restartTunnel()
            // ACTION_START、null（START_STICKY 被系統重建）→ 啟動（無 extras 時讀取已儲存設定）
            else -> startTunnel(intent)
        }
        return START_STICKY
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.w(TAG, "VPN revoked by system, stopping tunnel")
        mainHandler.removeCallbacks(backgroundStartRetry)
        backgroundRetryCount = 0
        stopTunnel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startTunnel(intent: Intent?) {
        if (isRunning) {
            Log.i(TAG, "already running, ignore start")
            return
        }
        // 只在明確的開機 intent 更新 bootContext；重試（null intent）時保留原值
        if (intent?.hasExtra(EXTRA_BOOT_START) == true) {
            bootContext = intent.getBooleanExtra(EXTRA_BOOT_START, false)
        }
        val backgroundStart = intent == null || !intent.hasExtra(EXTRA_HOST)
        val prefs = Config.prefs(this)
        // 優先取 extras；無 extras（開機自啟 / 磁貼 / START_STICKY 重建）→ 讀取已儲存設定
        var host = intent?.getStringExtra(EXTRA_HOST)?.trim().orEmpty()
        var port = intent?.getIntExtra(EXTRA_PORT, 1080) ?: 1080
        var user = intent?.getStringExtra(EXTRA_USER)?.trim().orEmpty()
        var pass = intent?.getStringExtra(EXTRA_PASS)?.trim().orEmpty()
        var udpInTcp = intent?.getBooleanExtra(EXTRA_UDP_IN_TCP, false) ?: false
        var remoteDns = intent?.getBooleanExtra(EXTRA_REMOTE_DNS, false) ?: false
        if (host.isEmpty()) {
            host = prefs.getString(Config.KEY_HOST, "") ?: ""
            port = prefs.getString(Config.KEY_PORT, "1080")?.toIntOrNull() ?: 1080
            user = prefs.getString(Config.KEY_USER, "") ?: ""
            pass = prefs.getString(Config.KEY_PASS, "") ?: ""
            udpInTcp = prefs.getBoolean(Config.KEY_UDP_IN_TCP, false)
            remoteDns = prefs.getBoolean(Config.KEY_REMOTE_DNS, false)
            Log.i(TAG, "Using saved config: host=$host port=$port")
        }
        if (host.isEmpty() || port <= 0 || port > 65535) {
            fail(getString(R.string.err_bad_params))
            return
        }

        // 回寫有效設定，確保開機自啟 / 磁貼使用最新設定
        prefs.edit()
            .putString(Config.KEY_HOST, host)
            .putString(Config.KEY_PORT, port.toString())
            .putString(Config.KEY_USER, user)
            .putString(Config.KEY_PASS, pass)
            .putBoolean(Config.KEY_UDP_IN_TCP, udpInTcp)
            .putBoolean(Config.KEY_REMOTE_DNS, remoteDns)
            .apply()

        Log.i(TAG, "startTunnel: host=$host port=$port user=$user udpInTcp=$udpInTcp remoteDns=$remoteDns")

        try {
            // 一進服務就進入前台，避免 startForegroundService 5 秒限制
            startForeground(
                NOTIFICATION_ID,
                createNotification(getString(R.string.notification_connecting)),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )

            publishStatus(getString(R.string.status_resolving))
            // 必須在 VPN 建立前解析，避免自己的 DNS 查詢被隧道捕捉。
            // DNS 解析是網路操作，移到 IO 執行緒避免主執行緒 ANR；完成後回主執行緒續建
            startPending = true
            serviceScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                var resolved: String? = null
                var resolveErrMsg: String? = null
                try {
                    resolved = InetAddress.getByName(host).hostAddress
                } catch (e: Exception) {
                    resolveErrMsg = e.message
                }
                mainHandler.post { continueStartTunnel(resolved, resolveErrMsg, backgroundStart) }
            }
        } catch (e: Exception) {
            startPending = false
            Log.e(TAG, "startTunnel failed", e)
            val msg = getString(R.string.err_start, e.message)
            DebugLog.recordError(msg)
            if (backgroundStart) backgroundFail(msg) else fail(msg)
        }
    }

    // DNS 解析完成後於主執行緒接手：建立 TUN、套用 per-App、啟動原生引擎。
    // 有效設定已回寫 prefs，此處統一從 prefs 讀取。
    private fun continueStartTunnel(serverIp: String?, resolveErr: String?, backgroundStart: Boolean) {
        if (!startPending) return   // 解析期間已停止／重啟 → 放棄本次啟動
        val prefs = Config.prefs(this)
        val host = prefs.getString(Config.KEY_HOST, "") ?: ""
        val port = prefs.getString(Config.KEY_PORT, "1080")?.toIntOrNull() ?: 1080
        val user = prefs.getString(Config.KEY_USER, "") ?: ""
        val pass = prefs.getString(Config.KEY_PASS, "") ?: ""
        val udpInTcp = prefs.getBoolean(Config.KEY_UDP_IN_TCP, false)
        val remoteDns = prefs.getBoolean(Config.KEY_REMOTE_DNS, false)
        try {
            if (serverIp == null) {
                startPending = false
                val msg = getString(R.string.err_resolve_host, resolveErr ?: host)
                if (backgroundStart) backgroundFail(msg) else fail(msg)
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

            // DNS 伺服器（使用者可自訂；先驗數字 IP 格式，避免對 hostname 觸發 DNS 查詢）
            val dnsList = Config.dnsServers(this)
            if (dnsList.isEmpty()) {
                builder.addDnsServer("8.8.8.8")
                builder.addDnsServer("1.1.1.1")
            } else {
                dnsList.forEach { dns ->
                    try {
                        if (Config.isLiteralIp(dns) && InetAddress.getByName(dns).hostAddress != null) {
                            builder.addDnsServer(dns)
                            Log.d(TAG, "DNS server added: $dns")
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Invalid DNS $dns: ${e.message}")
                    }
                }
            }

            applyPerAppMode(builder, prefs)

            val tunFd = builder.establish()
            if (tunFd == null) {
                startPending = false
                if (backgroundStart) {
                    backgroundFail(getString(R.string.err_vpn_establish))
                } else {
                    fail(getString(R.string.err_vpn_establish))
                }
                return
            }

            // native lib 載入失敗（如 16KB page 裝置未對齊）時，直接報錯而不是崩潰
            if (!NativeEngine.isLibraryLoaded()) {
                startPending = false
                if (backgroundStart) {
                    backgroundFail(getString(R.string.err_native_lib))
                } else {
                    fail(getString(R.string.err_native_lib))
                }
                return
            }

            NativeEngine.socketProvider = { h, p, isUdp -> createProtectedSocket(h, p, isUdp) }
            NativeEngine.registerInstance()
            Log.d(TAG, "Calling native startTunnel")
            val result = NativeEngine.startTunnel(tunFd.detachFd(), serverIp, port, user, pass, udpInTcp, remoteDns)
            Log.d(TAG, "native startTunnel result: $result")

            startPending = false
            isRunning = true
            backgroundRetryCount = 0
            val wasAutoRestart = synchronized(serverEventLock) {
                val w = autoRestartInProgress
                autoRestartInProgress = false
                w
            }
            if (!wasAutoRestart) {
                // 使用者／開機／磁貼的全新啟動成功：自動重連退避歸零。
                // 看門狗自己的重啟不重置，否則退避永遠停在最小延遲。
                synchronized(serverEventLock) { serverWatchdog.reset() }
            }
            publishStatus(getString(R.string.status_tunnel_active, host, port))
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(NOTIFICATION_ID, createNotification(getString(R.string.notification_running)))

            // 流量統計：每 3 秒更新常駐通知（↑ App→伺服器、↓ 伺服器→App • session 數）
            statsJob?.cancel()
            lastStatsText = null
            statsJob = serviceScope.launch {
                while (isRunning) {
                    try {
                        val st = NativeEngine.getStats()
                        val text = statsText(st)
                        if (text != lastStatsText) {
                            lastStatsText = text
                            getSystemService(NotificationManager::class.java)?.notify(
                                NOTIFICATION_ID,
                                createNotification(text)
                            )
                        }
                    } catch (e: Exception) {
                    }
                    kotlinx.coroutines.delay(STATS_UPDATE_INTERVAL_MS)
                }
            }
        } catch (e: Exception) {
            startPending = false
            Log.e(TAG, "startTunnel failed", e)
            val msg = getString(R.string.err_start, e.message)
            DebugLog.recordError(msg)
            if (backgroundStart) backgroundFail(msg) else fail(msg)
        }
    }

    /**
     * Per-App 模式：
     *  - GLOBAL   ：所有 App 走隧道
     *  - ALLOWLIST：只有勾選的 App 走隧道（其餘走本機網路）
     *  - EXCLUDE  ：勾選的 App 走本機網路（其餘走隧道）
     */
    private fun applyPerAppMode(builder: Builder, prefs: android.content.SharedPreferences) {
        val mode = prefs.getInt(Config.KEY_MODE, Config.MODE_GLOBAL)
        val selected = (prefs.getStringSet(AppListActivity.KEY_APPS, emptySet())
            ?: emptySet()).filter { it.isNotBlank() }.toSet()

        // 僅 ALLOWLIST + API<30 需要完整已安裝清單（把未勾選者全部設為繞過隧道）
        val installed: Collection<String> =
            if (mode == Config.MODE_ALLOWLIST && Build.VERSION.SDK_INT < PerAppMode.API_ADD_ALLOWED) {
                packageManager.getInstalledApplications(0).map { it.packageName }
            } else {
                emptyList()
            }

        val plan = PerAppMode.compute(mode, selected, installed, Build.VERSION.SDK_INT)

        plan.disallowed.forEach { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
                Log.d(TAG, "Excluding app from tunnel: $pkg")
            } catch (e: Exception) {
                Log.w(TAG, "addDisallowedApplication($pkg) failed: ${e.message}")
            }
        }
        plan.allowed.forEach { pkg ->
            try {
                builder.addAllowedApplication(pkg)
                Log.d(TAG, "Allowlisted app: $pkg")
            } catch (e: Exception) {
                Log.w(TAG, "addAllowedApplication($pkg) failed: ${e.message}")
            }
        }
    }

    private fun fail(msg: String) {
        DebugLog.recordError(msg)
        publishStatus(msg)
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) {}
        stopSelf()
    }

    private fun backgroundFail(msg: String) {
        if (backgroundRetryCount >= MAX_BACKGROUND_RETRIES) {
            Log.e(TAG, "Background start retries exhausted: $msg")
            fail(getString(R.string.err_start_retry_exhausted))
            return
        }
        backgroundRetryCount++
        Log.i(TAG, "Background start failed ($msg), retry $backgroundRetryCount/$MAX_BACKGROUND_RETRIES")
        publishStatus(getString(R.string.status_start_retrying, backgroundRetryCount))
        if (bootContext && !flashLaunched && backgroundRetryCount >= BOOT_FLASH_AFTER_RETRIES) {
            flashLaunched = true
            launchAutoStartActivity()
        }
        mainHandler.postDelayed(backgroundStartRetry, BACKGROUND_RETRY_DELAY_MS)
    }

    /**
     * Samsung 開機後背景 establish() 會被拒絕（需該 App 至少一次前台成功建立 VPN），
     * 且直接 startActivity 會被背景啟動限制（BAL）擋下，即使有前台服務。
     * 改用 full-screen intent 通知：螢幕關閉時系統直接開啟 Activity（前台建立），
     * 建立成功後 Activity 會自動關閉。
     */
    private fun launchAutoStartActivity() {
        Log.i(TAG, "Boot start still failing, launching MainActivity via full-screen intent")
        try {
            val i = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(MainActivity.EXTRA_AUTO_START, true)
            }
            val pi = PendingIntent.getActivity(
                this, 3, i,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(
                NOTIFICATION_ID + 1,
                Notification.Builder(this, FLASH_CHANNEL_ID)
                    .setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.notification_connecting))
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setFullScreenIntent(pi, true)
                    .setAutoCancel(true)
                    .build()
            )
        } catch (e: Exception) {
            Log.e(TAG, "launchAutoStartActivity failed: ${e.message}")
            try {
                startActivity(
                    Intent(this, MainActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        putExtra(MainActivity.EXTRA_AUTO_START, true)
                    }
                )
            } catch (e2: Exception) {
                Log.e(TAG, "launchAutoStartActivity fallback failed: ${e2.message}")
            }
        }
    }

    private fun stopTunnel() {
        mainHandler.removeCallbacks(backgroundStartRetry)
        backgroundRetryCount = 0
        bootContext = false
        flashLaunched = false
        startPending = false   // 使仍在途中的啟動流程（背景 DNS 解析）失效
        // 使用者明確停止：自動重連退避一併歸零
        autoRestartInProgress = false
        synchronized(serverEventLock) { serverWatchdog.reset() }
        publishStatus(getString(R.string.status_stopping))
        serviceScope.launch {
            stopEngineSync()
            publishStatus(getString(R.string.status_stopped))
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (e: Exception) {}
            stopSelf()
        }
    }

    private fun restartTunnel() {
        publishStatus(getString(R.string.status_restarting))
        serviceScope.launch {
            stopEngineSync()
            mainHandler.post {
                startPending = false   // 使仍在途中的舊啟動流程失效，再以最新設定重啟
                startTunnel(null)
            }
        }
    }

    // 軟重連：不拆 TUN / VPN 介面，只重置引擎連線狀態。
    // 原生沿用啟動時已解析的 g.srv_host（IP）重新撥號，伺服器恢復即自動重連。
    // 不呼叫 stopEngineSync()、不清 activeSockets、isRunning 維持 true——
    // 被關閉的 session fd 由原生經 notifySocketClosed 回呼逐一從 activeSockets 移除。
    private fun softRestart() {
        try {
            val err = NativeEngine.reconnect()
            if (err != null) Log.w(TAG, "soft reconnect failed: $err")
        } catch (e: Exception) {
            Log.w(TAG, "soft reconnect error", e)
        }
        synchronized(serverEventLock) { autoRestartInProgress = false }
    }

    // 同步停止原生引擎並釋放 socket（在 IO 執行緒呼叫）
    private fun stopEngineSync() {
        statsJob?.cancel()
        statsJob = null
        resetServerWatchdog()
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
    }

    /**
     * 來自原生引擎的伺服器連線事件（背景 handshake 線程呼叫）：
     *  - ok=true ：任一 CONNECT/ASSOCIATE 成功 → 清除失敗紀錄與退避計數
     *  - ok=false：網路層失敗（socket 建立逾時等）→ 由 ServerWatchdog 滑動窗口累計，
     *              達門檻即排程自動重啟（遞增延遲，避免對已下線伺服器瘋狂重試）
     */
    private fun onServerEvent(ok: Boolean) {
        if (!isRunning) return
        val decision = synchronized(serverEventLock) {
            if (ok) {
                serverWatchdog.onSuccess()
                ServerWatchdog.Decision.None
            } else {
                serverWatchdog.onNetworkFailure()
            }
        }
        val r = decision as? ServerWatchdog.Decision.Restart ?: return
        Log.w(TAG, "Server unreachable, auto-restart in ${r.delayMs}ms")
        publishStatus(getString(R.string.status_auto_reconnect, r.delayMs / 1000))
        val runnable = Runnable {
            autoRestartRunnable = null
            synchronized(serverEventLock) { serverWatchdog.onRestartFired() }
            if (isRunning && !startPending) {
                autoRestartInProgress = true
                softRestart()
            }
        }
        autoRestartRunnable = runnable
        mainHandler.postDelayed(runnable, r.delayMs)
    }

    private fun resetServerWatchdog() {
        autoRestartRunnable?.let { mainHandler.removeCallbacks(it) }
        autoRestartRunnable = null
        synchronized(serverEventLock) {
            // 只清失敗與排程，保留退避計數（restartTunnel 內部也會呼叫本函式，
            // 若連計數一起清，自動重啟會永遠停在最小延遲）
            serverWatchdog.clearFailures()
        }
    }

    private fun statsText(st: LongArray): String =
        getString(R.string.notification_running) + " • " + TrafficStats.summary(st)

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
        // 常駐隧道通知不顯示桌面角標數字（Samsung 桌面會把通知數當作待辦數字）
        channel.setShowBadge(false)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
        // 開機「閃一下」用高重要性 channel：Samsung 對低重要性通知不會啟動 full-screen intent
        val flashChannel = NotificationChannel(
            FLASH_CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        )
        flashChannel.setSound(null, null)
        flashChannel.setVibrationPattern(LongArray(0))
        flashChannel.setShowBadge(false)
        nm.createNotificationChannel(flashChannel)
    }

    private fun createNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = PendingIntent.getService(
            this, 1, Config.stopIntent(this),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val restartPi = PendingIntent.getService(
            this, 2, Config.startIntent(this, restart = true),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .setOngoing(true)
            .addAction(0, getString(R.string.notification_action_restart), restartPi)
            .addAction(0, getString(R.string.notification_action_stop), stopPi)
            .build()
    }

    private fun publishStatus(text: String) {
        lastStatus = text
        Log.i(TAG, "Status: $text")
        // RECEIVER_NOT_EXPORTED 的 receiver 只收「顯式（setPackage）intent」，
        // 不加 package 在 Android 14+ 收不到
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName).putExtra("status", text)
        )
    }

    override fun onDestroy() {
        serviceScope.cancel()
        statsJob = null
        resetServerWatchdog()
        startPending = false
        isRunning = false
        super.onDestroy()
    }
}