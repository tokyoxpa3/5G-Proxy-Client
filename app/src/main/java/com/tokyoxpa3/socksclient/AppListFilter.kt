package com.tokyoxpa3.socksclient

/**
 * App 清單過濾的純邏輯（不依賴 Android，可用 JVM 單元測試）。
 * [Entry] 僅含過濾所需的 pkg/label/system；icon 由 UI 層以 pkg 為鍵另存，
 * 避免把 android.graphics.Drawable 帶進純函式而無法在 JVM 測試。
 */
object AppListFilter {

    data class Entry(val pkg: String, val label: String, val system: Boolean)

    fun filter(entries: List<Entry>, query: String, showSystem: Boolean): List<Entry> {
        val base = if (showSystem) entries else entries.filterNot { it.system }
        // trim：輸入法常自動帶尾隨空白，未去除會讓「搜尋 App 」變成 0 筆結果
        val q = query.trim()
        return if (q.isEmpty()) base
        else base.filter { it.label.contains(q, ignoreCase = true) || it.pkg.contains(q, ignoreCase = true) }
    }
}
