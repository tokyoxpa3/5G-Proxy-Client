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
        assertTrue(DnsCandidates.isLinkLocalV6("fe80::1"))    // /10 的下界
        assertTrue(DnsCandidates.isLinkLocalV6("FE80::1"))    // 大小寫
        assertTrue(DnsCandidates.isLinkLocalV6("febf::1"))    // /10 的上界
        assertTrue(!DnsCandidates.isLinkLocalV6("fec0::1"))   // 舊 site-local，不在 /10
        assertTrue(!DnsCandidates.isLinkLocalV6("2001:db8::1"))
        assertTrue(!DnsCandidates.isLinkLocalV6("8.8.8.8"))
    }

    @Test
    fun shortenedHextetIsNotMistakenForLinkLocal() {
        // ⚠️ 這裡原本斷言 `fe8::1` 是連結本地 —— 那是錯的，等於把 bug 寫成規格。
        // 省略前導零時 `fe8` 是 hextet 0x0fe8（不是 0xfe80），不在 fe80::/10。
        // F-Droid 1.6.5 review 指出此 over-filtering；比對數值而非文字即可修正。
        assertTrue(!DnsCandidates.isLinkLocalV6("fe8::1"))
        assertTrue(!DnsCandidates.isLinkLocalV6("fe9::1"))
        assertTrue(!DnsCandidates.isLinkLocalV6("fea::1"))
        assertTrue(!DnsCandidates.isLinkLocalV6("feb::1"))
        // 反向對照：真的落在 /10 裡的（含省零寫法）仍必須判為連結本地，別修過頭
        assertTrue(DnsCandidates.isLinkLocalV6("fe80::1"))
        assertTrue(DnsCandidates.isLinkLocalV6("fe8f::1"))    // 0xfe8f 在 /10 內
        assertTrue(DnsCandidates.isLinkLocalV6("fea0::1"))    // 0xfea0 在 /10 內
        assertTrue(DnsCandidates.isLinkLocalV6("febf::1"))
    }

    @Test
    fun shortenedHextetSurvivesNormalization() {
        // 修正後 fe8::1（0x0fe8::/16）不該再被 normalize 當成連結本地丟掉
        val plan = DnsCandidates.plan(underlying = listOf("fe8::1", "8.8.8.8"), configured = emptyList())
        assertEquals(listOf("fe8::1", "8.8.8.8"), plan.map { it.server })
    }

    @Test
    fun normalizeOneMatchesWhatPlanEmits() {
        // 「位址 → 來源網路」對照表用 normalizeOne 當 key，必須與 plan() 實際吐出的字串逐字
        // 一致；不一致時查詢 socket 會**靜默**退回預設路由（＝F-Droid review 指出的
        // Limitation 原樣復活），沒有任何錯誤訊息。所以把這個契約寫成斷言。
        val raw = listOf(" 192.168.1.1 ", "fe80::1%wlan0", "fe8::1", "not-an-ip", "")
        val plan = DnsCandidates.plan(underlying = raw, configured = emptyList())
        assertEquals(listOf("192.168.1.1", "fe8::1"), plan.map { it.server })
        assertEquals(plan.map { it.server }, raw.mapNotNull { DnsCandidates.normalizeOne(it) })
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
