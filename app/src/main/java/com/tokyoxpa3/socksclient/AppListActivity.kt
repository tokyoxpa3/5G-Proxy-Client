package com.tokyoxpa3.socksclient

import android.app.Activity
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import java.util.TreeSet

class AppListActivity : Activity() {

    private data class AppEntry(val pkg: String, val label: String, val icon: Drawable)

    private lateinit var excluded: MutableSet<String>
    private lateinit var prefs: android.content.SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        prefs = getSharedPreferences("tunnel_config", MODE_PRIVATE)
        excluded = TreeSet(prefs.getStringSet(KEY_EXCLUDED, emptySet()) ?: emptySet())

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 32, 24, 24)
        }
        val hint = TextView(this).apply {
            text = getString(R.string.applist_hint)
            textSize = 13f
            setPadding(0, 0, 0, 16)
        }
        root.addView(hint)

        val apps = loadApps()
        val adapter = AppAdapter(apps)
        val list = ListView(this)
        list.adapter = adapter
        list.setOnItemClickListener { _, _, position, _ ->
            val entry = apps[position]
            if (excluded.contains(entry.pkg)) excluded.remove(entry.pkg)
            else excluded.add(entry.pkg)
            prefs.edit().putStringSet(KEY_EXCLUDED, excluded).apply()
            adapter.notifyDataSetChanged()
        }
        root.addView(list)
        setContentView(root)
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

    private inner class AppAdapter(val items: List<AppEntry>) : ArrayAdapter<AppEntry>(this@AppListActivity, 0, items) {
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val entry = items[position]
            val row = LinearLayout(this@AppListActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(8, 12, 8, 12)
            }
            val cb = CheckBox(this@AppListActivity).apply {
                isChecked = excluded.contains(entry.pkg)
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
        const val KEY_EXCLUDED = "excluded_apps"
    }
}