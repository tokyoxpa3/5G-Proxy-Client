package com.tokyoxpa3.socksclient

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log

/**
 * Quick Settings 快速磁貼：一鍵開關隧道。
 * - 隧道運作中 → 點擊停止
 * - 未運作 → 直接以最後設定啟動；若尚未授權 VPN 則先開啟 MainActivity 處理授權
 */
class TunnelTileService : TileService() {

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == TunSocksService.ACTION_STATUS) updateTile()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(statusReceiver, IntentFilter(TunSocksService.ACTION_STATUS), Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(statusReceiver, IntentFilter(TunSocksService.ACTION_STATUS))
            }
        } catch (e: Exception) {
            Log.w(TAG, "registerReceiver failed: ${e.message}")
        }
    }

    override fun onStopListening() {
        super.onStopListening()
        try {
            unregisterReceiver(statusReceiver)
        } catch (e: Exception) {
            Log.w(TAG, "unregisterReceiver failed: ${e.message}")
        }
    }

    override fun onClick() {
        super.onClick()
        if (TunSocksService.isRunning) {
            Log.i(TAG, "Tile: stopping tunnel")
            startService(Config.stopIntent(this))
        } else {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                Log.i(TAG, "Tile: VPN permission needed, opening MainActivity")
                val i = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    putExtra(MainActivity.EXTRA_AUTO_START, true)
                }
                startActivityAndCollapse(i)
            } else {
                Log.i(TAG, "Tile: starting tunnel from saved config")
                startService(Config.startIntent(this))
            }
        }
        updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val active = TunSocksService.isRunning
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.tile_label)
        tile.subtitle = getString(if (active) R.string.tile_state_active else R.string.tile_state_inactive)
        tile.updateTile()
    }

    companion object {
        private const val TAG = "TunnelTile"
    }
}