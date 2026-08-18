package com.tokyoxpa3.socksclient

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * 開機自啟：BOOT_COMPLETED 後依「開機自動啟動」設定直接拉起隧道服務。
 * 服務會以 SharedPreferences 中儲存的最後設定啟動（不帶 extras）。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Config.prefs(context).getBoolean(Config.KEY_AUTO_START, false)) {
            Log.i(TAG, "Auto-start disabled, skip")
            return
        }
        val host = Config.prefs(context).getString(Config.KEY_HOST, "") ?: ""
        if (host.isBlank()) {
            Log.i(TAG, "No saved config, skip")
            return
        }
        Log.i(TAG, "BOOT_COMPLETED: starting tunnel")
        try {
            val i = Config.startIntent(context)
            i.putExtra(TunSocksService.EXTRA_BOOT_START, true)
            if (Build.VERSION.SDK_INT >= 26) {
                context.startForegroundService(i)
            } else {
                context.startService(i)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start tunnel on boot", e)
        }
    }

    companion object {
        private const val TAG = "BootReceiver"
    }
}