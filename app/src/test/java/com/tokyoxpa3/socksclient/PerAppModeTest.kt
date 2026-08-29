package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PerAppMode 純決策邏輯單元測試——不依賴 Android，驗證三種模式
 * 在 API 26-29 / 30+ 兩種能力下的 disallowed/allowed 集合。
 */
class PerAppModeTest {

    private val apps = setOf("com.a", "com.b", "com.c")

    @Test
    fun global_addsNothing() {
        val plan = PerAppMode.compute(Config.MODE_GLOBAL, setOf("com.a"), apps, 33)
        assertTrue("GLOBAL 不該有 disallowed", plan.disallowed.isEmpty())
        assertTrue("GLOBAL 不該有 allowed", plan.allowed.isEmpty())
    }

    @Test
    fun exclude_disallowsSelected() {
        val plan = PerAppMode.compute(Config.MODE_EXCLUDE, setOf("com.a", "com.b"), apps, 33)
        assertEquals(setOf("com.a", "com.b"), plan.disallowed)
        assertTrue(plan.allowed.isEmpty())
    }

    @Test
    fun allowlist_api30plus_allowsSelected() {
        val plan = PerAppMode.compute(Config.MODE_ALLOWLIST, setOf("com.a"), apps, 30)
        assertEquals(setOf("com.a"), plan.allowed)
        assertTrue(plan.disallowed.isEmpty())
    }

    @Test
    fun allowlist_api29_disallowsUnselected() {
        val plan = PerAppMode.compute(Config.MODE_ALLOWLIST, setOf("com.a"), apps, 29)
        // 未勾選的 com.b / com.c 走本機網路
        assertEquals(setOf("com.b", "com.c"), plan.disallowed)
        assertTrue(plan.allowed.isEmpty())
    }

    @Test
    fun allowlist_api29_noneSelected_disallowsAllInstalled() {
        val plan = PerAppMode.compute(Config.MODE_ALLOWLIST, emptySet(), apps, 26)
        assertEquals(apps, plan.disallowed)
        assertTrue(plan.allowed.isEmpty())
    }

    @Test
    fun allowlist_api29_allSelected_disallowsNothing() {
        val plan = PerAppMode.compute(Config.MODE_ALLOWLIST, apps, apps, 26)
        assertTrue(plan.disallowed.isEmpty())
        assertTrue(plan.allowed.isEmpty())
    }

    @Test
    fun isEmptyAllowlist_allowlistEmpty_isTrue() {
        assertTrue(PerAppMode.isEmptyAllowlist(Config.MODE_ALLOWLIST, emptySet()))
    }

    @Test
    fun isEmptyAllowlist_allowlistNonEmpty_isFalse() {
        assertTrue(!PerAppMode.isEmptyAllowlist(Config.MODE_ALLOWLIST, setOf("com.a")))
    }

    @Test
    fun isEmptyAllowlist_otherModesEmpty_isFalse() {
        assertTrue(!PerAppMode.isEmptyAllowlist(Config.MODE_GLOBAL, emptySet()))
        assertTrue(!PerAppMode.isEmptyAllowlist(Config.MODE_EXCLUDE, emptySet()))
    }
}
