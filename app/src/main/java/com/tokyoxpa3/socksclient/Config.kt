package com.tokyoxpa3.socksclient

import android.content.Context
import android.content.SharedPreferences

/**
 * 集中管理所有設定鍵，供 MainActivity / Service / BootReceiver / TileService 共用。
 */
object Config {
    const val PREFS = "tunnel_config"

    // 目前（最後一次）連線設定
    const val KEY_HOST = "host"
    const val KEY_PORT = "port"
    const val KEY_USER = "user"
    const val KEY_PASS = "pass"
    const val KEY_UDP_IN_TCP = "udp_in_tcp"
    const val KEY_REMOTE_DNS = "remote_dns"
    const val KEY_DNS1 = "dns1"
    const val KEY_DNS2 = "dns2"
    const val KEY_MODE = "tunnel_mode"      // 0=global 1=allowlist 2=exclude
    const val KEY_AUTO_START = "auto_start"

    // 設定檔（JSON 字串）
    const val KEY_PROFILES = "profiles"

    const val MODE_GLOBAL = 0
    const val MODE_ALLOWLIST = 1
    const val MODE_EXCLUDE = 2

    // 預設值集中管理，避免同一數值散落多檔（改動只需改此處）。
    const val DEFAULT_PORT = 1080
    const val DEFAULT_DNS1 = "8.8.8.8"
    const val DEFAULT_DNS2 = "1.1.1.1"
    // Remote DNS（fakedns）：預設開啟，讓 DNS 在代理出口側解析，
    // CDN／地理路由更貼近出口網路（5G 代理等場景尤為重要）。
    const val DEFAULT_REMOTE_DNS = true
    // TUN 位址 / MTU：與 C 層 tun_socks.c 的 TUN_MTU、對 fd00::/8 的 ICMP6 NS 處理
    // 互相耦合，改動時需同步 Java 與 C 兩側。
    const val TUN_ADDR_V4 = "10.8.0.2"
    const val TUN_ADDR_V6 = "fd00::2"
    const val TUN_MTU = 4096

    fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun dnsServers(ctx: Context): List<String> {
        val p = prefs(ctx)
        val list = mutableListOf<String>()
        p.getString(KEY_DNS1, DEFAULT_DNS1)?.takeIf { it.isNotBlank() }?.let { list.add(it) }
        p.getString(KEY_DNS2, DEFAULT_DNS2)?.takeIf { it.isNotBlank() }?.let { list.add(it) }
        return list
    }

    fun mode(ctx: Context): Int = prefs(ctx).getInt(KEY_MODE, MODE_GLOBAL)

    // 純 JVM 可測的 IP 驗證（不依賴 android.util.Patterns，讓單元測試可在一般 JVM 跑）
    private val IPV4_RE = java.util.regex.Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    )

    /**
     * 數字 IP（IPv4 / IPv6）格式檢查——純本機字串驗證，不觸發 DNS 查詢。
     * VpnService.Builder.addDnsServer 只接受數字位址；過去用 InetAddress.getByName
     * 驗證會對 hostname 發出網路查詢（主執行緒 ANR 風險），故改為此檢查。
     */
    fun isLiteralIp(s: String): Boolean {
        if (IPV4_RE.matcher(s).matches()) return true   // IPv4
        if (!s.contains(':')) return false
        // IPv6 粗驗：僅允許 hex / 冒號 / 內嵌 IPv4 的點（如 ::ffff:1.2.3.4）
        return s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
    }

    fun loadProfile(ctx: Context, name: String): Profile? = Profiles.find(ctx, name)

    fun startIntent(ctx: Context, restart: Boolean = false): android.content.Intent =
        android.content.Intent(ctx, TunSocksService::class.java).apply {
            action = if (restart) TunSocksService.ACTION_RESTART else TunSocksService.ACTION_START
        }

    fun stopIntent(ctx: Context): android.content.Intent =
        android.content.Intent(ctx, TunSocksService::class.java).apply {
            action = TunSocksService.ACTION_STOP
        }
}