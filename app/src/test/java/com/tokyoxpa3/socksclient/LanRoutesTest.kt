package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LanRoutesTest {

    // ---- IPv4：私網 / link-local / loopback / multicast 必須排除 ----
    @Test
    fun v4_excludesPrivateRanges() {
        assertFalse("10.0.0.1", LanRoutes.containsV4("10.0.0.1"))
        assertFalse("10.255.255.254", LanRoutes.containsV4("10.255.255.254"))
        assertFalse("172.16.0.1", LanRoutes.containsV4("172.16.0.1"))
        assertFalse("172.31.255.254", LanRoutes.containsV4("172.31.255.254"))
        assertFalse("192.168.1.1", LanRoutes.containsV4("192.168.1.1"))
    }

    @Test
    fun v4_excludesLinkLocalLoopbackAndMulticast() {
        assertFalse("169.254.1.1 (link-local)", LanRoutes.containsV4("169.254.1.1"))
        assertFalse("127.0.0.1 (loopback)", LanRoutes.containsV4("127.0.0.1"))
        assertFalse("0.0.0.0", LanRoutes.containsV4("0.0.0.0"))
        assertFalse("224.0.0.1 (multicast)", LanRoutes.containsV4("224.0.0.1"))
        assertFalse("239.255.255.255 (multicast)", LanRoutes.containsV4("239.255.255.255"))
    }

    // ---- IPv4：公網樣本必須涵蓋 ----
    @Test
    fun v4_containsPublicAddresses() {
        assertTrue("8.8.8.8", LanRoutes.containsV4("8.8.8.8"))
        assertTrue("1.1.1.1", LanRoutes.containsV4("1.1.1.1"))
        assertTrue("9.9.9.9", LanRoutes.containsV4("9.9.9.9"))
        assertTrue("11.1.1.1", LanRoutes.containsV4("11.1.1.1"))
        assertTrue("172.15.0.1 (172.16/12 前一格)", LanRoutes.containsV4("172.15.0.1"))
        assertTrue("172.32.0.1 (172.16/12 後一格)", LanRoutes.containsV4("172.32.0.1"))
        assertTrue("192.169.1.1 (192.168/16 後)", LanRoutes.containsV4("192.169.1.1"))
        assertTrue("223.255.255.254 (公網最後)", LanRoutes.containsV4("223.255.255.254"))
        assertTrue("126.1.2.3 (127/8 前一格)", LanRoutes.containsV4("126.1.2.3"))
    }

    @Test
    fun v4_hasNoOverlapOrGap_acrossBoundaries() {
        // 私網與公網的邊界：172.15 公網、172.16 私網、172.31 私網、172.32 公網
        assertTrue(LanRoutes.containsV4("172.15.255.255"))
        assertFalse(LanRoutes.containsV4("172.16.0.0"))
        assertFalse(LanRoutes.containsV4("172.31.255.255"))
        assertTrue(LanRoutes.containsV4("172.32.0.0"))
        // 192.167 公網、192.168 私網、192.169 公網
        assertTrue(LanRoutes.containsV4("192.167.255.255"))
        assertFalse(LanRoutes.containsV4("192.168.0.0"))
        assertTrue(LanRoutes.containsV4("192.169.0.0"))
    }

    // ---- IPv6：結構驗證 ----
    @Test
    fun v6_hasGlobalUnicastAndFakeDns() {
        val v6 = LanRoutes.v6()
        assertTrue(v6.contains("2000::" to 3))
        assertTrue(v6.contains("fd00::" to 8))
    }

    @Test
    fun v6_excludesLinkLocalUlaAndMulticast() {
        val v6 = LanRoutes.v6()
        // 不應包含 link-local (fe80::/10)、ULA (fc00::/7)、multicast (ff00::/8)
        assertFalse(v6.any { it.first.startsWith("fe") && it.second <= 10 })
        assertFalse(v6.any { it.first.startsWith("fc") && it.second <= 7 })
        assertFalse(v6.any { it.first.startsWith("ff") })
        // 也不應用 ::/0 這種全抓路由
        assertFalse(v6.contains("::" to 0))
    }

    @Test
    fun v4_routeCount_isReasonable() {
        // 完整「全公網單播」表應落在數十筆，遠小於逐個 /8 的 224 筆
        val n = LanRoutes.v4().size
        assertTrue("v4 route count $n", n in 40..60)
        assertEquals(2, LanRoutes.v6().size)
    }
}
