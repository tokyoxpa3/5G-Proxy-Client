package com.tokyoxpa3.socksclient

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ScrollView
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import android.widget.AdapterView

class MainActivity : Activity() {

    companion object {
        private const val REQ_VPN_PERMISSION = 100
        private const val REQ_NOTIFICATION_PERMISSION = 200
        const val EXTRA_AUTO_START = "auto_start_from_tile"
    }

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var etUser: EditText
    private lateinit var etPass: EditText
    private lateinit var etDns1: EditText
    private lateinit var etDns2: EditText
    private lateinit var etProfileName: EditText
    private lateinit var cbUdpInTcp: CheckBox
    private lateinit var cbAutoStart: CheckBox
    private lateinit var modeGroup: RadioGroup
    private lateinit var btnToggle: Button
    private lateinit var btnSelectApps: Button
    private lateinit var btnSaveProfile: Button
    private lateinit var btnDeleteProfile: Button
    private lateinit var spinnerProfile: Spinner
    private lateinit var tvStatus: TextView

    private var pendingAutoStart = false
    private var autoFinishPending = false
    private val profileNames = mutableListOf<String>()

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == TunSocksService.ACTION_STATUS) {
                updateStatus(intent.getStringExtra("status"))
                // 開機自動啟動的「閃一下」：隧道建立成功後自動關閉
                if (autoFinishPending && TunSocksService.isRunning) {
                    autoFinishPending = false
                    finish()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DebugLog.init(this)
        pendingAutoStart = intent?.getBooleanExtra(EXTRA_AUTO_START, false) ?: false
        buildUi()
        // 開啟 App 即自動連線（像 sockstun）：非「閃一下」啟動、隧道未在跑、有已存設定 → 自動建立 VPN
        if (!pendingAutoStart && !TunSocksService.isRunning &&
            !(Config.prefs(this).getString(Config.KEY_HOST, "") ?: "").isBlank()
        ) {
            attemptStart()
        }
        if (savedInstanceState == null) {
            DebugLog.getLastCrash()?.let { crash ->
                tvStatus.text = getString(R.string.last_crash_prefix, crash)
            } ?: DebugLog.getLastError()?.let { err ->
                tvStatus.text = getString(R.string.last_error_prefix, err)
            }
        }
        requestNotificationPermissionIfNeeded()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pendingAutoStart = intent.getBooleanExtra(EXTRA_AUTO_START, false)
    }

    override fun onResume() {
        super.onResume()
        // Android 14+ (targetSdk 34)：context-registered receiver 必須指定 export flag，
        // 否則 SecurityException 直接崩潰（小米 Pad Mini / Android 15 上閃退的主因）
        registerReceiver(
            statusReceiver,
            IntentFilter(TunSocksService.ACTION_STATUS),
            Context.RECEIVER_NOT_EXPORTED
        )
        updateStatus(TunSocksService.lastStatus)

        // 開機「閃一下」：若在背景停留期間隧道已連上，回到前台時立即關閉
        if (autoFinishPending && TunSocksService.isRunning) {
            autoFinishPending = false
            finish()
            return
        }

        if (pendingAutoStart) {
            pendingAutoStart = false
            if (!TunSocksService.isRunning) {
                Toast.makeText(this, R.string.toast_starting, Toast.LENGTH_SHORT).show()
                attemptStart()
                autoFinishPending = true
            }
        }
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(statusReceiver)
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 48)
        }

        fun label(text: String) = TextView(this).apply {
            this.text = text
            textSize = 15f
            setPadding(0, 20, 0, 6)
        }

        etHost = EditText(this).apply { hint = getString(R.string.hint_host) }
        etPort = EditText(this).apply {
            hint = getString(R.string.hint_port)
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }
        etDns1 = EditText(this).apply { hint = getString(R.string.hint_dns1) }
        etDns2 = EditText(this).apply { hint = getString(R.string.hint_dns2) }
        etUser = EditText(this).apply { hint = getString(R.string.hint_user) }
        etPass = EditText(this).apply {
            hint = getString(R.string.hint_pass)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        etProfileName = EditText(this).apply { hint = getString(R.string.hint_profile_name) }

        btnToggle = Button(this).apply {
            text = getString(R.string.btn_start_tunnel)
            setOnClickListener {
                if (TunSocksService.isRunning) {
                    startService(Config.stopIntent(this@MainActivity))
                } else {
                    attemptStart()
                }
            }
        }
        btnSelectApps = Button(this).apply {
            text = getString(R.string.btn_select_apps)
            setOnClickListener {
                startActivity(Intent(this@MainActivity, AppListActivity::class.java))
            }
        }
        tvStatus = TextView(this).apply {
            textSize = 14f
            setPadding(0, 24, 0, 0)
        }

        cbUdpInTcp = CheckBox(this).apply {
            text = getString(R.string.label_udp_in_tcp)
            setPadding(0, 8, 0, 0)
        }
        cbAutoStart = CheckBox(this).apply {
            text = getString(R.string.label_auto_start)
            setPadding(0, 8, 0, 0)
        }

        // 隧道模式
        modeGroup = RadioGroup(this).apply { orientation = RadioGroup.VERTICAL }
        fun modeBtn(text: String, id: Int) = RadioButton(this).apply {
            this.text = text
            id.let { setId(it) }
        }
        modeGroup.addView(modeBtn(getString(R.string.label_mode_global), Config.MODE_GLOBAL))
        modeGroup.addView(modeBtn(getString(R.string.label_mode_allowlist), Config.MODE_ALLOWLIST))
        modeGroup.addView(modeBtn(getString(R.string.label_mode_exclude), Config.MODE_EXCLUDE))

        // 設定檔
        spinnerProfile = Spinner(this)
        btnSaveProfile = Button(this).apply { text = getString(R.string.btn_save_profile) }
        btnDeleteProfile = Button(this).apply { text = getString(R.string.btn_delete_profile) }
        val profileRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        profileRow.addView(btnSaveProfile, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        profileRow.addView(btnDeleteProfile, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        root.addView(label(getString(R.string.label_server)))
        root.addView(etHost)
        root.addView(etPort)
        root.addView(label(getString(R.string.label_dns)))
        root.addView(etDns1)
        root.addView(etDns2)
        root.addView(label(getString(R.string.label_auth)))
        root.addView(etUser)
        root.addView(etPass)
        root.addView(label(getString(R.string.label_mode)))
        root.addView(modeGroup)
        // App 按鈕貼近「僅排除以下 App」選項
        root.addView(btnSelectApps)
        root.addView(btnToggle)
        root.addView(label(getString(R.string.label_other)))
        root.addView(cbUdpInTcp)
        root.addView(cbAutoStart)
        root.addView(label(getString(R.string.label_profiles)))
        root.addView(etProfileName)
        root.addView(spinnerProfile)
        root.addView(profileRow)
        root.addView(tvStatus)

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(root)
        }
        setContentView(scroll)

        val prefs = getSharedPreferences("tunnel_config", MODE_PRIVATE)
        etHost.setText(prefs.getString("host", ""))
        etPort.setText(prefs.getString("port", "1080"))
        etUser.setText(prefs.getString("user", ""))
        etPass.setText(prefs.getString("pass", ""))
        etDns1.setText(prefs.getString("dns1", "8.8.8.8"))
        etDns2.setText(prefs.getString("dns2", "1.1.1.1"))
        cbUdpInTcp.isChecked = prefs.getBoolean("udp_in_tcp", false)
        cbAutoStart.isChecked = prefs.getBoolean("auto_start", false)
        // 勾選/取消當下立即存檔，確保重開機使用最新設定（不必等到按下「啟動」）
        cbAutoStart.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(Config.KEY_AUTO_START, checked).apply()
        }
        modeGroup.check(prefs.getInt("tunnel_mode", Config.MODE_GLOBAL))

        btnToggle.setOnClickListener {
            if (TunSocksService.isRunning) {
                startService(Config.stopIntent(this))
            } else {
                attemptStart()
            }
        }

        setupProfileUi()

        refreshProfileSpinner()
    }

    private fun attemptStart() {
        try {
            val host = etHost.text.toString().trim()
            val port = etPort.text.toString().trim().toIntOrNull()
            if (host.isEmpty() || port == null || port !in 1..65535) {
                Toast.makeText(this, getString(R.string.toast_invalid_input), Toast.LENGTH_SHORT).show()
                return
            }
            val dns1 = etDns1.text.toString().trim()
            val dns2 = etDns2.text.toString().trim()
            if (dns1.isNotBlank() && !isValidIp(dns1)) {
                Toast.makeText(this, getString(R.string.err_invalid_dns, dns1), Toast.LENGTH_LONG).show()
                return
            }
            if (dns2.isNotBlank() && !isValidIp(dns2)) {
                Toast.makeText(this, getString(R.string.err_invalid_dns, dns2), Toast.LENGTH_LONG).show()
                return
            }

            prefs().edit()
                .putString(Config.KEY_HOST, host)
                .putString(Config.KEY_PORT, etPort.text.toString().trim())
                .putString(Config.KEY_USER, etUser.text.toString().trim())
                .putString(Config.KEY_PASS, etPass.text.toString().trim())
                .putString(Config.KEY_DNS1, dns1)
                .putString(Config.KEY_DNS2, dns2)
                .putBoolean(Config.KEY_UDP_IN_TCP, cbUdpInTcp.isChecked)
                .putBoolean(Config.KEY_AUTO_START, cbAutoStart.isChecked)
                .putInt(Config.KEY_MODE, modeGroup.checkedRadioButtonId)
                .apply()

            Toast.makeText(this, getString(R.string.toast_starting), Toast.LENGTH_SHORT).show()
            android.util.Log.i("MainActivity", "Start button pressed, preparing VPN")

            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                Toast.makeText(this, getString(R.string.toast_allow_vpn), Toast.LENGTH_LONG).show()
                startActivityForResult(vpnIntent, REQ_VPN_PERMISSION)
            } else {
                startTunnel(host, port)
            }
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Start click error", e)
            DebugLog.recordError("點擊啟動時錯誤：${e.message}")
            Toast.makeText(this, getString(R.string.toast_start_failed, e.message), Toast.LENGTH_LONG).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) {
                val port = etPort.text.toString().trim().toIntOrNull() ?: 1080
                startTunnel(etHost.text.toString().trim(), port)
            } else {
                Toast.makeText(this, getString(R.string.toast_vpn_denied), Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIFICATION_PERMISSION) {
            val granted = grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                Toast.makeText(this, R.string.toast_notification_permission, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun startTunnel(host: String, port: Int) {
        val intent = Intent(this, TunSocksService::class.java).apply {
            action = TunSocksService.ACTION_START
            putExtra(TunSocksService.EXTRA_HOST, host)
            putExtra(TunSocksService.EXTRA_PORT, port)
            putExtra(TunSocksService.EXTRA_USER, etUser.text.toString().trim())
            putExtra(TunSocksService.EXTRA_PASS, etPass.text.toString().trim())
            putExtra(TunSocksService.EXTRA_UDP_IN_TCP, cbUdpInTcp.isChecked)
        }
        try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "startForegroundService error", e)
            DebugLog.recordError(getString(R.string.toast_service_start_failed, e.message))
            Toast.makeText(this, getString(R.string.toast_service_start_failed, e.message), Toast.LENGTH_LONG).show()
        }
    }

    private fun setupProfileUi() {
        spinnerProfile.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                if (position == 0) return  // 佔位項目（載入設定檔…）
                val name = profileNames.getOrNull(position - 1) ?: return
                Profiles.find(this@MainActivity, name)?.let { p ->
                    etHost.setText(p.host)
                    etPort.setText(p.port)
                    etUser.setText(p.user)
                    etPass.setText(p.pass)
                    etDns1.setText(p.dns1)
                    etDns2.setText(p.dns2)
                    cbUdpInTcp.isChecked = p.udpInTcp
                    modeGroup.check(p.mode)
                    etProfileName.setText(p.name)
                }
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        btnSaveProfile.setOnClickListener {
            val name = etProfileName.text.toString().trim()
            if (name.isEmpty()) {
                Toast.makeText(this, R.string.toast_profile_name_empty, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            Profiles.save(this, currentProfile(name))
            Toast.makeText(this, R.string.toast_profile_saved, Toast.LENGTH_SHORT).show()
            refreshProfileSpinner()
        }

        btnDeleteProfile.setOnClickListener {
            val name = etProfileName.text.toString().trim()
            if (name.isEmpty()) {
                Toast.makeText(this, R.string.toast_profile_name_empty, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            Profiles.delete(this, name)
            Toast.makeText(this, R.string.toast_profile_deleted, Toast.LENGTH_SHORT).show()
            refreshProfileSpinner()
        }
    }

    private fun currentProfile(name: String): Profile = Profile(
        name = name,
        host = etHost.text.toString().trim(),
        port = etPort.text.toString().trim(),
        user = etUser.text.toString().trim(),
        pass = etPass.text.toString().trim(),
        udpInTcp = cbUdpInTcp.isChecked,
        dns1 = etDns1.text.toString().trim(),
        dns2 = etDns2.text.toString().trim(),
        mode = modeGroup.checkedRadioButtonId
    )

    private fun refreshProfileSpinner() {
        profileNames.clear()
        profileNames.addAll(Profiles.names(this))
        val display = mutableListOf(getString(R.string.btn_load_profile))
        display.addAll(profileNames)
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, display).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        spinnerProfile.adapter = adapter
        spinnerProfile.setSelection(0)
    }

    private fun isValidIp(s: String): Boolean = try {
        val a = java.net.InetAddress.getByName(s)
        a.hostAddress != null
    } catch (e: Exception) {
        false
    }

    private fun prefs() = getSharedPreferences("tunnel_config", MODE_PRIVATE)

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATION_PERMISSION)
        }
    }

    private fun updateStatus(text: String?) {
        tvStatus.text = text ?: ""
        // 啟動/停止共用單一按鈕：執行中顯示「停止隧道」，停止時顯示「啟動隧道」
        val running = TunSocksService.isRunning
        btnToggle.text = getString(if (running) R.string.btn_stop_tunnel else R.string.btn_start_tunnel)
    }
}