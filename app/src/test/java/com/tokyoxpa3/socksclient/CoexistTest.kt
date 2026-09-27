package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coexist 純決策邏輯單元測試——不依賴 Android。
 *
 * 核心不變式：**Pro 不得進隧道**。同一個勾選動作在排除模式與白名單模式語意相反，
 * 所以「共存成立」對應的操作也相反 —— 這正是這組測試要鎖住的地方。
 */
class CoexistTest {

    private val pro = Coexist.PRO_PACKAGE
    private val others = setOf("com.a", "com.b")

    // --- isOn：共存是否成立 ---

    @Test
    fun isOn_excludeWithPro_isTrue() {
        // 排除模式：勾選 = 走本機網路 → 勾了 Pro 才把牠留在隧道外
        assertTrue(Coexist.isOn(Config.MODE_EXCLUDE, others + pro))
    }

    @Test
    fun isOn_excludeWithoutPro_isFalse() {
        assertFalse(Coexist.isOn(Config.MODE_EXCLUDE, others))
    }

    @Test
    fun isOn_allowlistWithoutPro_isTrue() {
        // 白名單模式：勾選 = 走隧道 → 不勾 Pro 才是共存
        assertTrue(Coexist.isOn(Config.MODE_ALLOWLIST, others))
    }

    @Test
    fun isOn_allowlistWithPro_isFalse() {
        assertFalse(Coexist.isOn(Config.MODE_ALLOWLIST, others + pro))
    }

    @Test
    fun isOn_global_isFalse() {
        // 全局模式不套用勾選清單（PerAppMode 對 GLOBAL 回空 Plan），無法表達
        assertFalse(Coexist.isOn(Config.MODE_GLOBAL, others))
        assertFalse(Coexist.isOn(Config.MODE_GLOBAL, others + pro))
    }

    // --- isLocked：可否由使用者關閉 ---

    @Test
    fun isLocked_allowlistOnly() {
        assertTrue("白名單模式下共存強制成立", Coexist.isLocked(Config.MODE_ALLOWLIST))
        assertFalse(Coexist.isLocked(Config.MODE_EXCLUDE))
        assertFalse(Coexist.isLocked(Config.MODE_GLOBAL))
    }

    // --- turnOn ---

    @Test
    fun turnOn_exclude_checksPro() {
        val st = Coexist.turnOn(Config.MODE_EXCLUDE, others)
        assertEquals(Config.MODE_EXCLUDE, st.mode)
        assertEquals(others + pro, st.selected)
    }

    @Test
    fun turnOn_global_switchesToExclude() {
        // 全局無法表達排除 → 連帶切到排除模式（電台會同步跳過去）
        val st = Coexist.turnOn(Config.MODE_GLOBAL, others)
        assertEquals(Config.MODE_EXCLUDE, st.mode)
        assertEquals(others + pro, st.selected)
    }

    @Test
    fun turnOn_allowlist_keepsModeAndUnchecksPro() {
        val st = Coexist.turnOn(Config.MODE_ALLOWLIST, others + pro)
        assertEquals("白名單模式不必改模式", Config.MODE_ALLOWLIST, st.mode)
        assertEquals(others, st.selected)
        assertTrue(Coexist.isOn(st.mode, st.selected))
    }

    @Test
    fun turnOn_preservesOtherCheckedApps() {
        val st = Coexist.turnOn(Config.MODE_EXCLUDE, setOf("com.a", "com.b", "com.c"))
        assertTrue(st.selected.containsAll(setOf("com.a", "com.b", "com.c")))
    }

    @Test
    fun turnOn_isIdempotent() {
        val once = Coexist.turnOn(Config.MODE_EXCLUDE, others)
        assertEquals(once, Coexist.turnOn(once.mode, once.selected))
    }

    // --- turnOff ---

    @Test
    fun turnOff_exclude_removesProAndKeepsMode() {
        val st = Coexist.turnOff(Config.MODE_EXCLUDE, others + pro)
        assertEquals("關閉開關不該代使用者改模式", Config.MODE_EXCLUDE, st.mode)
        assertEquals(others, st.selected)
        assertFalse(Coexist.isOn(st.mode, st.selected))
    }

    @Test
    fun turnOff_allowlist_isRefused() {
        // 白名單模式不可關閉：狀態原樣回傳，不會把 Pro 勾進隧道
        val st = Coexist.turnOff(Config.MODE_ALLOWLIST, others)
        assertEquals(Config.MODE_ALLOWLIST, st.mode)
        assertEquals(others, st.selected)
        assertTrue(Coexist.isOn(st.mode, st.selected))
    }

    @Test
    fun turnOff_global_isNoOp() {
        val st = Coexist.turnOff(Config.MODE_GLOBAL, others)
        assertEquals(Config.MODE_GLOBAL, st.mode)
        assertEquals(others, st.selected)
    }

    // --- sanitize：把 Pro 擋在白名單外 ---

    @Test
    fun sanitize_allowlist_removesPro() {
        assertEquals(others, Coexist.sanitize(Config.MODE_ALLOWLIST, others + pro))
    }

    @Test
    fun sanitize_allowlist_keepsOthers() {
        val st = Coexist.sanitize(Config.MODE_ALLOWLIST, setOf("com.a", "com.b", "com.c"))
        assertEquals(setOf("com.a", "com.b", "com.c"), st)
    }

    @Test
    fun sanitize_exclude_doesNotTouch() {
        // 排除模式交給開關決定，否則使用者就無法關閉共存
        assertEquals(others + pro, Coexist.sanitize(Config.MODE_EXCLUDE, others + pro))
    }

    @Test
    fun sanitize_global_doesNotTouch() {
        assertEquals(others + pro, Coexist.sanitize(Config.MODE_GLOBAL, others + pro))
    }

    // --- 往返 ---

    @Test
    fun turnOnThenOff_restoresSelection() {
        val on = Coexist.turnOn(Config.MODE_EXCLUDE, others)
        val off = Coexist.turnOff(on.mode, on.selected)
        assertEquals(others, off.selected)
    }

    // --- 與 PerAppMode 的接合：不變式的最終驗收 ---

    @Test
    fun excludePlan_disallowsProWhenOn() {
        val st = Coexist.turnOn(Config.MODE_EXCLUDE, others)
        val plan = PerAppMode.compute(st.mode, st.selected, emptyList(), 33)
        assertTrue("Pro 必須走本機網路", plan.disallowed.contains(pro))
    }

    @Test
    fun allowlistPlan_neverTunnelsPro() {
        // 白名單 + API30：allowed = selected（sanitize 後不含 Pro）
        val selected = Coexist.sanitize(Config.MODE_ALLOWLIST, others + pro)
        val plan = PerAppMode.compute(Config.MODE_ALLOWLIST, selected, others + pro, 33)
        assertFalse("Pro 不得出現在 allowed", plan.allowed.contains(pro))
        assertTrue(plan.allowed.containsAll(others))
    }

    @Test
    fun allowlistPlan_api29_disallowsPro() {
        // 白名單 + API<30：disallowed = installed - selected，Pro 不在 selected 故必然被排除
        val selected = Coexist.sanitize(Config.MODE_ALLOWLIST, others + pro)
        val plan = PerAppMode.compute(Config.MODE_ALLOWLIST, selected, others + pro, 29)
        assertTrue("Pro 必須走本機網路", plan.disallowed.contains(pro))
    }

    @Test
    fun globalPlan_cannotExpressExclusion() {
        // 記錄「為什麼 turnOn 在全局模式下必須改模式」：全局產不出任何 disallowed
        val plan = PerAppMode.compute(Config.MODE_GLOBAL, others + pro, emptyList(), 33)
        assertTrue(plan.disallowed.isEmpty())
    }
}
