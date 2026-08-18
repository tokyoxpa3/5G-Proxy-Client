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

    private data class AppEntry(val pkg: String, val label: String, val icon: Drawable)

    private lateinit var selected: MutableSet<String>
    private lateinit var prefs: android.content.SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        prefs = getSharedPreferences("tunnel_config", MODE_PRIVATE)
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
            val filtered = if (q.isBlank()) allApps else
                allApps.filter { it.label.contains(q, ignoreCase = true) || it.pkg.contains(q, ignoreCase = true) }
            adapter.replaceAll(filtered)
            empty.visibility = if (filtered.isEmpty()) View.VISIBLE else View.GONE
            list.visibility = if (filtered.isEmpty()) View.GONE else View.VISIBLE
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
                ai.loadIcon(pm)
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

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val entry = items[position]
            val row = LinearLayout(this@AppListActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(8, 12, 8, 12)
            }
            val cb = CheckBox(this@AppListActivity).apply {
                isChecked = selected.contains(entry.pkg)
                isClickable = false
                isFocusable = false
            }
            val iv = ImageView(this@AppListActivity).apply {
                setImageDrawable(entry.icon)
                setPadding(16, 0, 16, 0)
            }
            val tv = TextView(this@AppListActivity).apply {
                text = entry.label
                textSize = 15f
            }
            row.addView(cb)
            row.addView(iv)
            row.addView(tv)
            return row
        }
    }

    companion object {
        const val KEY_APPS = "selected_apps"
        const val KEY_LEGACY_EXCLUDED = "excluded_apps"
    }
}