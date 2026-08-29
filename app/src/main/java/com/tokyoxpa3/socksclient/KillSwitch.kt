package com.tokyoxpa3.socksclient

/**
 * 斷線保護（Kill Switch）三態判定——純邏輯、不依賴 Android，
 * 供 JVM 單元測試直接注入原始系統設定字串驗證。
 *
 * 語意：以「本 App 是否為系統 Always-on VPN App」為前提；
 * `always_on_vpn_lockdown == "1"` 代表「封鎖未使用 VPN 的連線」已開啟。
 */
enum class KillSwitchStatus {
    /** 未啟用：本 App 不是系統的 Always-on VPN App */
    NONE,

    /** 永遠連線：Always-on VPN 已設為本 App，但未封鎖無 VPN 流量 */
    ALWAYS_ON,

    /** 已封鎖無 VPN：Always-on VPN + 封鎖未使用 VPN 的連線皆開啟 */
    LOCKDOWN
}

object KillSwitch {

    /**
     * 判定目前的系統斷線保護狀態。
     *
     * @param ourPackage     本 App 的 package name（Context.packageName）
     * @param alwaysOnVpnApp 系統 `always_on_vpn_app` 設定值（目前 Always-on VPN App 的 package，可能為 null/空白）
     * @param lockdownEnabled 系統 `always_on_vpn_lockdown` 是否為 "1"
     */
    fun status(ourPackage: String, alwaysOnVpnApp: String?, lockdownEnabled: Boolean): KillSwitchStatus {
        if (alwaysOnVpnApp != ourPackage) return KillSwitchStatus.NONE
        return if (lockdownEnabled) KillSwitchStatus.LOCKDOWN else KillSwitchStatus.ALWAYS_ON
    }
}
