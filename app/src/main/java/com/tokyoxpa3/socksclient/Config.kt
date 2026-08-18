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
    const val KEY_DNS1 = "dns1"
    const val KEY_DNS2 = "dns2"
    const val KEY_MODE = "tunnel_mode"      // 0=global 1=allowlist 2=exclude
    const val KEY_AUTO_START = "auto_start"

    // 設定檔（JSON 字串）
    const val KEY_PROFILES = "profiles"

    const val MODE_GLOBAL = 0
    const val MODE_ALLOWLIST = 1
    const val MODE_EXCLUDE = 2

    fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun dnsServers(ctx: Context): List<String> {
        val p = prefs(ctx)
        val list = mutableListOf<String>()
        p.getString(KEY_DNS1, "8.8.8.8")?.takeIf { it.isNotBlank() }?.let { list.add(it) }
        p.getString(KEY_DNS2, "1.1.1.1")?.takeIf { it.isNotBlank() }?.let { list.add(it) }
        return list
    }

    fun mode(ctx: Context): Int = prefs(ctx).getInt(KEY_MODE, MODE_GLOBAL)

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