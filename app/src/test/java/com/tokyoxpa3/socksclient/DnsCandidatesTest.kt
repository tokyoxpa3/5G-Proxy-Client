package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 軟重連的 DNS 候選順序：**底層網路 DNS 必須排在設定值前面**。
 * 這正是「不要把伺服器主機名多送給第三方解析器（預設 8.8.8.8 / 1.1.1.1）」的實作，
 * 順序錯了就等於沒修 —— 所以把順序寫成斷言，而不是只寫在註解裡。
 */
class DnsCandidatesTest {

    @Test
    fun underlyingComesFirstConfiguredIsFallback() {
        val plan = DnsCandidates.plan(
            underlying = listOf("192.168.1.1"),
            configured = listOf("8.8.8.8", "1.1.1.1")
        )
        assertEquals(
            listOf("192.168.1.1", "8.8.8.8", "1.1.1.1"),
            plan.map { it.server }
        )
        assertEquals(listOf(false, true, true), plan.map { it.fallback })
    }

    @Test
    fun configuredAloneIsStillTriedWhenUnderlyingIsUnknown() {
        // 底層查不到（allNetworks 還沒就緒等）時仍要能解析，否則 DDNS 換 IP 後追不上
        val plan = DnsCandidates.plan(emptyList(), listOf("8.8.8.8"))
        assertEquals(listOf(DnsCandidates.Candidate("8.8.8.8", fallback = true)), plan)
    }

    @Test
    fun duplicateAcrossTiersIsNotQueriedTwice() {
        // 使用者把 DNS 設成與底層相同時，不該查兩遍（多等一個 3 秒逾時）
        val plan = DnsCandidates.plan(listOf("192.168.1.1"), listOf("192.168.1.1"))
        assertEquals(listOf("192.168.1.1"), plan.map { it.server })
        assertTrue(plan.none { it.fallback })
    }

    @Test
    fun invalidEntriesAreDropped() {
        val plan = DnsCandidates.plan(
            underlying = listOf("", "   ", "not-an-ip", "10.0.0.1"),
            configured = listOf("8.8.8.8")
        )
        assertEquals(listOf("10.0.0.1", "8.8.8.8"), plan.map { it.server })
    }

    @Test
    fun linkLocalV6IsDropped() {
        // 實測本機 Wi-Fi 的 LinkProperties 第一個 DNS 就是 "fe80::524f:3bff:fe79:6e1c%wlan0"。
        // 去掉 zone id 後（fe80::524f:…）沒有 scope 可送，留著只會白等一個 3 秒逾時。
        val plan = DnsCandidates.plan(
            underlying = listOf("fe80::524f:3bff:fe79:6e1c%wlan0", "8.8.8.8", "8.8.4.4"),
            configured = listOf("1.1.1.1")
        )
        assertEquals(listOf("8.8.8.8", "8.8.4.4", "1.1.1.1"), plan.map { it.server })
    }

    @Test
    fun linkLocalRangeCoversWholeFe80Slash10() {
        assertTrue(DnsCandidates.isLinkLocalV6("fe80::1"))
        assertTrue(DnsCandidates.isLinkLocalV6("fe8::1"))     // 省略前導零的寫法
        assertTrue(DnsCandidates.isLinkLocalV6("FE80::1"))    // 大小寫
        assertTrue(DnsCandidates.isLinkLocalV6("febf::1"))    // /10 的上界
        assertTrue(!DnsCandidates.isLinkLocalV6("fec0::1"))   // 舊 site-local，不在 /10
        assertTrue(!DnsCandidates.isLinkLocalV6("2001:db8::1"))
        assertTrue(!DnsCandidates.isLinkLocalV6("8.8.8.8"))
    }

    @Test
    fun orderWithinEachTierIsPreserved() {
        val plan = DnsCandidates.plan(
            underlying = listOf("fd00::1", "192.168.1.1"),
            configured = listOf("1.1.1.1", "8.8.8.8")
        )
        assertEquals(
            listOf("fd00::1", "192.168.1.1", "1.1.1.1", "8.8.8.8"),
            plan.map { it.server }
        )
    }
}
