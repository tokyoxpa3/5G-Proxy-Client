package com.tokyoxpa3.socksclient

import android.app.Activity
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import java.util.TreeSet

class AppListActivity : Activity() {

    private data class AppEntry(val pkg: String, val label: String, val icon: Drawable, val system: Boolean)

    private lateinit var selected: MutableSet<String>
    private lateinit var prefs: android.content.SharedPreferences
    private var showSystem = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        prefs = Config.prefs(this)
        // 相容舊版：讀取舊的 excluded_apps 鍵當作初始值
        selected = TreeSet(
            (prefs.getStringSet(KEY_APPS, null) ?: prefs.getStringSet(KEY_LEGACY_EXCLUDED, null)
                ?: emptySet()) as? Set<String> ?: emptySet()
        )
        migrateLegacy()

        val mode = prefs.getInt(Config.KEY_MODE, Config.MODE_GLOBAL)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 32, 24, 24)
        }

        val hintText = TextView(this).apply {
            text = when (mode) {
                Config.MODE_ALLOWLIST -> getString(R.string.applist_hint_allowlist)
                Config.MODE_EXCLUDE -> getString(R.string.applist_hint_exclude)
                else -> getString(R.string.applist_hint_global)
            }
            textSize = 13f
            setPadding(0, 0, 0, 16)
        }
        root.addView(hintText)

        val search = EditText(this).apply {
            hint = getString(R.string.applist_search_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT
            setPadding(8, 8, 8, 8)
        }
        root.addView(search)

        // 預設隱藏系統 App，勾選後才顯示（清單較乾淨）
        val showSystemToggle = CheckBox(this).apply {
            text = getString(R.string.applist_show_system)
            textSize = 14f
            setPadding(0, 4, 0, 4)
        }
        root.addView(showSystemToggle)

        val allApps = loadApps()
        val adapter = AppAdapter(mutableListOf())
        val list = ListView(this)
        list.adapter = adapter
        list.setOnItemClickListener { _, _, position, _ ->
            val entry = adapter.getItem(position) ?: return@setOnItemClickListener
            if (selected.contains(entry.pkg)) selected.remove(entry.pkg)
            else selected.add(entry.pkg)
            prefs.edit().putStringSet(KEY_APPS, selected).apply()
            adapter.notifyDataSetChanged()
            // 執行中改動 App 清單 → debounce 後自動重啟套用
            Config.applyPerAppIfRunning(this@AppListActivity)
        }
        root.addView(list)

        val empty = TextView(this).apply {
            text = getString(R.string.applist_empty)
            textSize = 14f
            gravity = Gravity.CENTER
            setPadding(0, 32, 0, 0)
            visibility = View.GONE
        }
        root.addView(empty)

        fun applyFilter(q: String) {
            val base = if (showSystem) allApps else allApps.filterNot { it.system }
            val filtered = if (q.isBlank()) base else
                base.filter { it.label.contains(q, ignoreCase = true) || it.pkg.contains(q, ignoreCase = true) }
            adapter.replaceAll(filtered)
            empty.visibility = if (filtered.isEmpty()) View.VISIBLE else View.GONE
            list.visibility = if (filtered.isEmpty()) View.GONE else View.VISIBLE
        }

        showSystemToggle.setOnCheckedChangeListener { _, checked ->
            showSystem = checked
            applyFilter(search.text?.toString() ?: "")
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) {
                applyFilter(s?.toString() ?: "")
            }
        })
        applyFilter("")

        setContentView(root)
    }

    // 首次開啟時把舊鍵值搬進新鍵
    private fun migrateLegacy() {
        if (!prefs.contains(KEY_APPS) && prefs.contains(KEY_LEGACY_EXCLUDED)) {
            val old = prefs.getStringSet(KEY_LEGACY_EXCLUDED, emptySet()) ?: emptySet()
            prefs.edit().putStringSet(KEY_APPS, old).remove(KEY_LEGACY_EXCLUDED).apply()
        }
    }

    private fun loadApps(): List<AppEntry> {
        val pm = packageManager
        return pm.getInstalledApplications(0).map { ai: ApplicationInfo ->
            AppEntry(
                ai.packageName,
                pm.getApplicationLabel(ai).toString(),
                ai.loadIcon(pm),
                (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            )
        }.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
    }

    private inner class AppAdapter(private var items: List<AppEntry>) : ArrayAdapter<AppEntry>(this@AppListActivity, 0, items) {

        fun replaceAll(newItems: List<AppEntry>) {
            items = newItems
            clear()
            addAll(newItems)
            notifyDataSetChanged()
        }

        // ViewHolder 式回收：列內含 checkbox / icon / 名稱 / 套件名
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val entry = items[position]
            val row: LinearLayout
            val cb: CheckBox
            val iv: ImageView
            val tvLabel: TextView
            val tvPkg: TextView
            if (convertView == null) {
                row = LinearLayout(this@AppListActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(8, 12, 8, 12)
                }
                cb = CheckBox(this@AppListActivity).apply {
                    isClickable = false
                    isFocusable = false
                }
                iv = ImageView(this@AppListActivity).apply {
                    setPadding(16, 0, 16, 0)
                }
                tvLabel = TextView(this@AppListActivity).apply {
                    textSize = 15f
                    maxLines = 1
                    ellipsize = android.text.TextUtils.TruncateAt.END
                }
                tvPkg = TextView(this@AppListActivity).apply {
                    textSize = 11f
                    maxLines = 1
                    ellipsize = android.text.TextUtils.TruncateAt.END
                    alpha = 0.6f
                }
                val texts = LinearLayout(this@AppListActivity).apply {
                    orientation = LinearLayout.VERTICAL
                }
                texts.addView(tvLabel)
                texts.addView(tvPkg)
                row.addView(cb)
                row.addView(iv)
                row.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                row.tag = arrayOf(cb, iv, tvLabel, tvPkg)
            } else {
                row = convertView as LinearLayout
                @Suppress("UNCHECKED_CAST")
                val t = row.tag as Array<View>
                cb = t[0] as CheckBox
                iv = t[1] as ImageView
                tvLabel = t[2] as TextView
                tvPkg = t[3] as TextView
            }
            iv.setImageDrawable(entry.icon)
            tvLabel.text = entry.label
            tvPkg.text = entry.pkg
            cb.isChecked = selected.contains(entry.pkg)
            return row
        }
    }

    companion object {
        const val KEY_APPS = "selected_apps"
        const val KEY_LEGACY_EXCLUDED = "excluded_apps"
    }
}