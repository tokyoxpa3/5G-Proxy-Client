package com.tokyoxpa3.socksclient

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    companion object {
        private const val REQ_VPN_PERMISSION = 100
    }

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var etUser: EditText
    private lateinit var etPass: EditText
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button
    private lateinit var tvStatus: TextView

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == TunSocksService.ACTION_STATUS) {
                updateStatus(intent.getStringExtra("status"))
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DebugLog.init(this)
        buildUi()
        DebugLog.getLastCrash()?.let { crash ->
            tvStatus.text = "⚠️ 上次發生崩潰：\n$crash"
        } ?: DebugLog.getLastError()?.let { err ->
            tvStatus.text = "⚠️ 上次錯誤：\n$err"
        }
    }

    override fun onResume() {
        super.onResume()
        registerReceiver(statusReceiver, IntentFilter(TunSocksService.ACTION_STATUS))
        updateStatus(TunSocksService.lastStatus)
    }

    override fun onPause() {
        super.onPause()
        unregisterReceiver(statusReceiver)
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
        }

        fun label(text: String) = TextView(this).apply {
            this.text = text
            textSize = 15f
            setPadding(0, 24, 0, 6)
        }

        etHost = EditText(this).apply { hint = "伺服器 IP（例：192.168.1.100）" }
        etPort = EditText(this).apply {
            hint = "連接埠（例：1080）"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }
        etUser = EditText(this).apply { hint = "使用者名稱（可留空）" }
        etPass = EditText(this).apply {
            hint = "密碼（可留空）"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }

        btnStart = Button(this).apply { text = "🚀 啟動隧道" }
        btnStop = Button(this).apply {
            text = "🛑 停止隧道"
            isEnabled = false
        }
        tvStatus = TextView(this).apply {
            textSize = 14f
            setPadding(0, 24, 0, 0)
        }

        root.addView(label("SOCKS5 伺服器"))
        root.addView(etHost)
        root.addView(etPort)
        root.addView(label("認證（可選）"))
        root.addView(etUser)
        root.addView(etPass)
        root.addView(btnStart)
        root.addView(btnStop)
        root.addView(tvStatus)

        setContentView(root)

        val prefs = getSharedPreferences("tunnel_config", MODE_PRIVATE)
        etHost.setText(prefs.getString("host", ""))
        etPort.setText(prefs.getString("port", "1080"))
        etUser.setText(prefs.getString("user", ""))
        etPass.setText(prefs.getString("pass", ""))

        btnStart.setOnClickListener {
            try {
                val host = etHost.text.toString().trim()
                val port = etPort.text.toString().trim().toIntOrNull()
                if (host.isEmpty() || port == null || port !in 1..65535) {
                    Toast.makeText(this, "請輸入有效的伺服器位址與連接埠", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                prefs.edit()
                    .putString("host", host)
                    .putString("port", etPort.text.toString().trim())
                    .putString("user", etUser.text.toString().trim())
                    .putString("pass", etPass.text.toString().trim())
                    .apply()

                Toast.makeText(this, "正在啟動隧道…", Toast.LENGTH_SHORT).show()
                android.util.Log.i("MainActivity", "Start button pressed, preparing VPN")

                val vpnIntent = VpnService.prepare(this)
                if (vpnIntent != null) {
                    Toast.makeText(this, "請在系統視窗允許 VPN 連線", Toast.LENGTH_LONG).show()
                    startActivityForResult(vpnIntent, REQ_VPN_PERMISSION)
                } else {
                    startTunnel(host, port)
                }
            } catch (e: Exception) {
                android.util.Log.e("MainActivity", "Start click error", e)
                DebugLog.recordError("點擊啟動時錯誤：${e.message}")
                Toast.makeText(this, "啟動失敗：${e.message}", Toast.LENGTH_LONG).show()
            }
        }

        btnStop.setOnClickListener {
            sendStop()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) {
                val port = etPort.text.toString().trim().toIntOrNull() ?: 1080
                startTunnel(etHost.text.toString().trim(), port)
            } else {
                Toast.makeText(this, "未取得 VPN 權限", Toast.LENGTH_SHORT).show()
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
        }
        try {
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "startForegroundService error", e)
            DebugLog.recordError("服務啟動失敗：${e.message}")
            Toast.makeText(this, "服務啟動失敗：${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun sendStop() {
        startService(Intent(this, TunSocksService::class.java).apply {
            action = TunSocksService.ACTION_STOP
        })
    }

    private fun updateStatus(text: String?) {
        tvStatus.text = text ?: ""
        val running = TunSocksService.isRunning
        btnStart.isEnabled = !running
        btnStop.isEnabled = running
    }
}
