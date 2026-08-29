package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * KillSwitch 純邏輯單元測試——直接注入系統 Always-on VPN 設定原始值，
 * 不需 Android 環境即可驗證三態判定。
 */
class KillSwitchTest {

    private val ourPackage = "com.tokyoxpa3.socksclient"

    @Test
    fun nullAlwaysOnApp_isNone() {
        assertEquals(KillSwitchStatus.NONE, KillSwitch.status(ourPackage, null, false))
        assertEquals(KillSwitchStatus.NONE, KillSwitch.status(ourPackage, null, true))
    }

    @Test
    fun blankAlwaysOnApp_isNone() {
        assertEquals(KillSwitchStatus.NONE, KillSwitch.status(ourPackage, "", false))
        assertEquals(KillSwitchStatus.NONE, KillSwitch.status(ourPackage, "   ", true))
    }

    @Test
    fun otherAppAlwaysOn_isNone() {
        assertEquals(KillSwitchStatus.NONE, KillSwitch.status(ourPackage, "com.other.vpn", false))
        // 即使是別人的 lockdown 也與本 App 無關
        assertEquals(KillSwitchStatus.NONE, KillSwitch.status(ourPackage, "com.other.vpn", true))
    }

    @Test
    fun ownAppWithoutLockdown_isAlwaysOn() {
        assertEquals(KillSwitchStatus.ALWAYS_ON, KillSwitch.status(ourPackage, ourPackage, false))
    }

    @Test
    fun ownAppWithLockdown_isLockdown() {
        assertEquals(KillSwitchStatus.LOCKDOWN, KillSwitch.status(ourPackage, ourPackage, true))
    }
}
