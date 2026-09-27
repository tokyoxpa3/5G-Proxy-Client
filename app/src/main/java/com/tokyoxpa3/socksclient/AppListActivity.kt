package com.tokyoxpa3.socksclient

import android.app.Activity
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.util.TreeSet

class AppListActivity : Activity() {

    private data class AppEntry(val pkg: String, val label: String, val icon: Drawable, val system: Boolean)

    private lateinit var selected: MutableSet<String>
    private lateinit var prefs: SharedPreferences
    private var showSystem = false

    private lateinit var allApps: List<AppEntry>
    private lateinit var adapter: AppAdapter
    private lateinit var search: EditText
    private lateinit var listView: ListView
    private lateinit var emptyView: TextView
    private lateinit var toggleSystem: Button
    private lateinit var summary: TextView
    private lateinit var proHint: TextView

    /** 目前清單上實際顯示的 App 數量（供摘要列使用）。 */
    private var shownCount = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        prefs = Config.prefs(this)
        // 相容舊版：讀取舊的 excluded_apps 鍵當作初始值
        selected = TreeSet(
            (prefs.getStringSet(KEY_APPS, null) ?: prefs.getStringSet(KEY_LEGACY_EXCLUDED, null)
                ?: emptySet()) as? Set<String> ?: emptySet()
        )
        migrateLegacy()
        // Pro 不得進隧道：指定 App 模式下把它擋在白名單外（見 Coexist）
        enforceCoexistInvariant()

        setContentView(buildUi())
    }

    /** 套用「Pro 不得進隧道」的不變式並落地；只有指定 App 模式會實際變動。 */
    private fun enforceCoexistInvariant() {
        val mode = prefs.getInt(Config.KEY_MODE, Config.MODE_GLOBAL)
        val fixed = Coexist.sanitize(mode, selected)
        if (fixed != selected) {
            selected = TreeSet(fixed)
            prefs.edit().putStringSet(KEY_APPS, TreeSet(selected)).apply()
        }
    }

    /** 指定 App 模式下 Pro 那一列要鎖住：勾了等於主動把它送進隧道。 */
    private fun isProRowLocked(pkg: String): Boolean =
        pkg == Coexist.PRO_PACKAGE &&
            Coexist.isLocked(prefs.getInt(Config.KEY_MODE, Config.MODE_GLOBAL))

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun buildUi(): View {
        val mode = prefs.getInt(Config.KEY_MODE, Config.MODE_GLOBAL)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
        }

        // 這一頁沒有 ActionBar（見 AppListTheme），標題自己畫，否則使用者不知道自己在哪一頁。
        val title = TextView(this).apply {
            text = getString(R.string.applist_title)
            textSize = 20f
            setPadding(0, 0, 0, dp(6))
        }
        root.addView(title)

        val hintText = TextView(this).apply {
            text = when (mode) {
                Config.MODE_ALLOWLIST -> getString(R.string.applist_hint_allowlist)
                Config.MODE_EXCLUDE -> getString(R.string.applist_hint_exclude)
                else -> getString(R.string.applist_hint_global)
            }
            textSize = 13f
            setPadding(0, 0, 0, dp(10))
        }
        root.addView(hintText)

        // 同機共存提示：5G Proxy Pro（伺服器端）必須被「排除在隧道之外」才能與本 App
        // 同時運作 —— Pro 要把 socket 綁到蜂巢式出口，被隧道接管時系統會以 EPERM 拒絕。
        // 只提示、不自動勾選：是否排除由使用者決定（勾選 = 該 App 走本機網路）。
        proHint = TextView(this).apply {
            textSize = 13f
            alpha = 0.85f
            visibility = View.GONE
            setPadding(0, 0, 0, dp(10))
        }
        root.addView(proHint)

        // 搜尋列：輸入框 + 清除鈕。獨立成一列（橫向填滿）以確保在任何 ROM 上都辨識得出來。
        search = EditText(this).apply {
            hint = getString(R.string.applist_search_hint)
            inputType = InputType.TYPE_CLASS_TEXT
            maxLines = 1
            imeOptions = EditorInfo.IME_ACTION_SEARCH
        }
        val clearSearch = Button(this).apply {
            text = getString(R.string.applist_search_clear)
            minWidth = 0
            minimumWidth = 0
            setPadding(dp(12), 0, dp(12), 0)
            setOnClickListener { search.setText("") }
        }
        val searchRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        searchRow.addView(
            search,
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        )
        searchRow.addView(clearSearch)
        root.addView(searchRow)

        // 系統 App 開關：用 Button 而非裸 CheckBox —— 小米等第三方 ROM 對 CheckBox 的
        // 著色不一致時，裸 CheckBox 會整列「看不見」；Button 有實心背景，任何主題都看得見。
        toggleSystem = Button(this).apply {
            setOnClickListener {
                showSystem = !showSystem
                updateToggleLabel()
                applyFilter()
            }
        }
        root.addView(toggleSystem)

        summary = TextView(this).apply {
            textSize = 12f
            alpha = 0.75f
            setPadding(0, dp(4), 0, dp(6))
        }
        root.addView(summary)

        allApps = loadApps()
        // 用區域變數指向 adapter：在 ListView.apply { } 內 `adapter` 會解析成
        // ListView 自己的 ListAdapter 屬性，取不到 AppEntry 的型別。
        val appAdapter = AppAdapter()
        adapter = appAdapter

        listView = ListView(this).apply {
            adapter = appAdapter
            setOnItemClickListener { _, _, position, _ ->
                val entry = appAdapter.getItem(position) ?: return@setOnItemClickListener
                // 指定 App 模式下 Pro 那一列鎖住（勾了 = 送它進隧道，共存就沒了）
                if (isProRowLocked(entry.pkg)) return@setOnItemClickListener
                if (!selected.remove(entry.pkg)) selected.add(entry.pkg)
                // 傳副本給 SharedPreferences，避免之後就地修改同一個 Set 造成未定義行為
                prefs.edit().putStringSet(KEY_APPS, TreeSet(selected)).apply()
                appAdapter.notifyDataSetChanged()
                updateSummary()
                updateProHint()
            }
        }

        emptyView = TextView(this).apply {
            text = getString(R.string.applist_empty)
            textSize = 14f
            gravity = Gravity.CENTER
            visibility = View.GONE
        }

        // 清單與空狀態疊在同一塊（weight 填滿剩餘高度）：空狀態才會置中，
        // 且清單有明確高度可正常捲動，不會把下方元件推出畫面。
        val listArea = FrameLayout(this)
        listArea.addView(
            listView,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        )
        listArea.addView(
            emptyView,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER
            )
        )
        root.addView(
            listArea,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        )

        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) = applyFilter()
        })

        updateToggleLabel()
        applyFilter()
        updateProHint()

        // targetSdk 35 強制 edge-to-edge：把系統列 insets 併入 root padding，
        // 否則小米（HyperOS）等高狀態列／有挖孔的裝置上，最上面的搜尋列與
        // 「顯示系統 App」開關會被狀態列蓋掉（本頁過去漏了 MainActivity 已有的處理）。
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(
                dp(16) + bars.left,
                dp(12) + bars.top,
                dp(16) + bars.right,
                dp(12) + bars.bottom
            )
            insets
        }
        ViewCompat.requestApplyInsets(root)

        return root
    }

    private fun updateToggleLabel() {
        toggleSystem.text = getString(
            if (showSystem) R.string.applist_show_system_on else R.string.applist_show_system_off
        )
    }

    private fun updateSummary() {
        summary.text = getString(R.string.applist_summary, shownCount, selected.size)
    }

    private fun applyFilter() {
        val query = search.text?.toString() ?: ""
        val filtered = AppListFilter.filter(
            allApps.map { AppListFilter.Entry(it.pkg, it.label, it.system) },
            query, showSystem
        )
        val keep = filtered.mapTo(HashSet()) { it.pkg }
        adapter.submit(allApps.filter { it.pkg in keep })
        shownCount = filtered.size
        val isEmpty = filtered.isEmpty()
        emptyView.visibility = if (isEmpty) View.VISIBLE else View.GONE
        listView.visibility = if (isEmpty) View.GONE else View.VISIBLE
        updateSummary()
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

    private inner class AppAdapter : ArrayAdapter<AppEntry>(this@AppListActivity, 0, ArrayList()) {

        fun submit(newItems: List<AppEntry>) {
            clear()
            addAll(newItems)
            notifyDataSetChanged()
        }

        // ViewHolder 式回收：列內含 checkbox / icon / 名稱 / 套件名
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val entry = getItem(position) ?: return convertView ?: View(this@AppListActivity)
            val row: LinearLayout
            val cb: CheckBox
            val iv: ImageView
            val tvLabel: TextView
            val tvPkg: TextView
            if (convertView == null) {
                row = LinearLayout(this@AppListActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(4), dp(10), dp(4), dp(10))
                }
                cb = CheckBox(this@AppListActivity).apply {
                    isClickable = false
                    isFocusable = false
                }
                iv = ImageView(this@AppListActivity).apply {
                    setPadding(dp(12), 0, dp(12), 0)
                }
                tvLabel = TextView(this@AppListActivity).apply {
                    textSize = 15f
                    maxLines = 1
                    ellipsize = TextUtils.TruncateAt.END
                }
                tvPkg = TextView(this@AppListActivity).apply {
                    textSize = 11f
                    maxLines = 1
                    ellipsize = TextUtils.TruncateAt.END
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
            // 鎖住的列要「看得出來不能勾」，而不是按了沒反應
            val locked = isProRowLocked(entry.pkg)
            cb.isEnabled = !locked
            row.isEnabled = !locked
            row.alpha = if (locked) 0.45f else 1f
            return row
        }
    }

    /**
     * 同機共存提示：5G Proxy Pro（伺服器端）必須被排除在隧道之外，才能與本 App 同時運作
     * —— Pro 需要把 socket 綁定到蜂巢式出口，被隧道接管時系統會以 EPERM 拒絕。
     *
     * 這裡只「提示」，不代使用者改設定：主頁的「同機共存」開關才是改設定的入口，
     * 而它與本頁的勾選清單是同一個狀態的兩種呈現（見 [Coexist]）。
     *
     * 三種隧道模式對 Pro 的影響（勾選的語意在排除與白名單之間是相反的）：
     *  - 排除模式：勾選 = 走本機網路 → 勾了 Pro 才安全，沒勾就要提示
     *  - 白名單模式：勾選 = 走隧道 → 不勾 Pro 就自動共存，該列已鎖住 → 顯示資訊
     *  - 全局模式：所有 App 都被吃掉、清單不生效 → 提示改用排除模式或開主頁開關
     */
    private fun updateProHint() {
        val mode = prefs.getInt(Config.KEY_MODE, Config.MODE_GLOBAL)
        val textRes = when {
            !isProInstalled() -> 0
            mode == Config.MODE_EXCLUDE ->
                if (selected.contains(Coexist.PRO_PACKAGE)) 0 else R.string.applist_hint_pro_exclude
            mode == Config.MODE_ALLOWLIST -> R.string.applist_hint_pro_allowlist
            else -> R.string.applist_hint_pro_global
        }
        if (textRes == 0) {
            proHint.visibility = View.GONE
        } else {
            proHint.text = getString(textRes)
            proHint.visibility = View.VISIBLE
        }
    }

    /** 5G Proxy Pro 是否已安裝（本 App 具備 QUERY_ALL_PACKAGES，看得到）。 */
    private fun isProInstalled(): Boolean = try {
        packageManager.getPackageInfo(Coexist.PRO_PACKAGE, 0)
        true
    } catch (e: Exception) {
        false
    }

    companion object {
        const val KEY_APPS = "selected_apps"
        const val KEY_LEGACY_EXCLUDED = "excluded_apps"
    }
}
