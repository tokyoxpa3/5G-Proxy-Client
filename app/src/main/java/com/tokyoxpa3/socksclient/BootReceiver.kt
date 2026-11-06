package com.tokyoxpa3.socksclient

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * 開機自啟（以及 App 更新後還原）：依「開機自動啟動」設定拉起隧道服務。
 *
 * 三個條件同時成立才會啟動，缺一不可：
 *  1. 使用者勾了「開機自動啟動隧道」（[Config.KEY_AUTO_START]，預設關）
 *  2. 關機前隧道仍在執行（[Config.KEY_WAS_RUNNING]，按過停止就是 false）
 *  3. 已存有伺服器設定
 *
 * 條件 2 不能省：只勾了開關、但使用者按過停止，重開機又自己連上，正是使用者不想被做的事
 * （同一個毛病也曾出現在「轉屏就自動連線」，見 MainActivity 的 isRecreation）。
 *
 * 服務會以 SharedPreferences 中儲存的最後設定啟動（不帶 extras）。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action !in ACTIONS) return
        val prefs = Config.prefs(context)
        if (!prefs.getBoolean(Config.KEY_AUTO_START, false)) {
            Log.i(TAG, "Auto-start disabled, skip")
            return
        }
        if (!prefs.getBoolean(Config.KEY_WAS_RUNNING, false)) {
            Log.i(TAG, "Stopped by user before shutdown, skip")
            return
        }
        val host = prefs.getString(Config.KEY_HOST, "") ?: ""
        if (host.isBlank()) {
            Log.i(TAG, "No saved config, skip")
            return
        }
        if (TunSocksService.isRunning) {
            Log.i(TAG, "Already running, skip")
            return
        }
        Log.i(TAG, "$action: starting tunnel")
        try {
            val i = Config.startIntent(context)
            i.putExtra(TunSocksService.EXTRA_BOOT_START, true)
            context.startForegroundService(i)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start tunnel on boot", e)
        }
    }

    companion object {
        private const val TAG = "BootReceiver"
        private val ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            "android.intent.action.QUICKBOOT_POWERON"
        )
    }
}
