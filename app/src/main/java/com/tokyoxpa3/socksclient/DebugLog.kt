package com.tokyoxpa3.socksclient

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 離線除錯工具：把崩潰與錯誤寫入 SharedPreferences + 檔案，
 * 介面上直接顯示，不需 logcat 即可回報問題。
 */
object DebugLog {
    private const val TAG = "DebugLog"
    private const val PREFS = "tunnel_debug"
    private const val KEY_CRASH = "last_crash"
    private const val KEY_ERROR = "last_error"

    private var ctx: Context? = null
    private var handlerInstalled = false

    fun init(context: Context) {
        if (ctx == null) ctx = context.applicationContext
        if (handlerInstalled) return
        handlerInstalled = true
        val original = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            val detail = ctx?.let { c ->
                c.getString(
                    R.string.debug_crash_detail,
                    ts(), thread.name, throwable.javaClass.name, throwable.message, throwable.stackTraceToString()
                )
            } ?: buildString {
                appendLine("時間: ${ts()}")
                appendLine("線程: ${thread.name}")
                appendLine("類型: ${throwable.javaClass.name}")
                appendLine("訊息: ${throwable.message}")
                appendLine("堆疊:")
                appendLine(throwable.stackTraceToString())
            }
            ctx?.let { c ->
                try {
                    c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                        .edit().putString(KEY_CRASH, detail).commit()
                    File(c.filesDir, "crash.log").writeText(detail)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to save crash log", e)
                }
            }
            Log.e(TAG, "Uncaught exception on ${thread.name}:\n$detail")
            original?.uncaughtException(thread, throwable)
        }
    }

    fun recordError(msg: String) {
        ctx?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            ?.edit()?.putString(KEY_ERROR, msg)?.apply()
        Log.e(TAG, msg)
    }

    fun getLastCrash(): String? =
        ctx?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)?.getString(KEY_CRASH, null)

    fun getLastError(): String? =
        ctx?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)?.getString(KEY_ERROR, null)

    private fun ts(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
}
