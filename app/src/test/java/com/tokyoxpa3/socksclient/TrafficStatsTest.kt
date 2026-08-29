package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Test

class TrafficStatsTest {

    @Test
    fun formatBytes_belowKb_showsBytes() {
        assertEquals("0 B", TrafficStats.formatBytes(0))
        assertEquals("1023 B", TrafficStats.formatBytes(1023))
    }

    @Test
    fun formatBytes_kbRange_usesOneDecimal() {
        assertEquals("1.0 KB", TrafficStats.formatBytes(1024))
        assertEquals("1.5 KB", TrafficStats.formatBytes(1536))
    }

    @Test
    fun formatBytes_mbRange_usesOneDecimal() {
        assertEquals("1.0 MB", TrafficStats.formatBytes(1024L * 1024))
        assertEquals("2.5 MB", TrafficStats.formatBytes((2.5 * 1024 * 1024).toLong()))
    }

    @Test
    fun formatBytes_gbRange_usesTwoDecimals() {
        assertEquals("1.00 GB", TrafficStats.formatBytes(1024L * 1024 * 1024))
    }

    @Test
    fun summary_fullArray_formatsAllFields() {
        val stats = longArrayOf(1024L, 2048L, 3L, 4L)
        assertEquals("↑1.0 KB ↓2.0 KB • TCP:3 UDP:4", TrafficStats.summary(stats))
    }

    @Test
    fun summary_emptyArray_defaultsToZero() {
        assertEquals("↑0 B ↓0 B • TCP:0 UDP:0", TrafficStats.summary(longArrayOf()))
    }

    @Test
    fun summary_partialArray_fillsMissingWithZero() {
        assertEquals("↑0 B ↓0 B • TCP:2 UDP:0", TrafficStats.summary(longArrayOf(0L, 0L, 2L)))
    }
}
