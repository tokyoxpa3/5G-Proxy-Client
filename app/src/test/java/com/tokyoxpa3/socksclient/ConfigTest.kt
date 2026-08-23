package com.tokyoxpa3.socksclient

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigTest {

    @Test
    fun validIpv4_accepted() {
        assertTrue(Config.isLiteralIp("8.8.8.8"))
        assertTrue(Config.isLiteralIp("192.168.1.1"))
        assertTrue(Config.isLiteralIp("0.0.0.0"))
        assertTrue(Config.isLiteralIp("255.255.255.255"))
        assertTrue(Config.isLiteralIp("1.2.3.4"))
    }

    @Test
    fun invalidIpv4_rejected() {
        assertFalse(Config.isLiteralIp("256.1.1.1"))
        assertFalse(Config.isLiteralIp("1.2.3"))
        assertFalse(Config.isLiteralIp("1.2.3.4.5"))
        assertFalse(Config.isLiteralIp("a.b.c.d"))
        assertFalse(Config.isLiteralIp("1.2.3.999"))
        assertFalse(Config.isLiteralIp(""))
        assertFalse(Config.isLiteralIp("192.168.1.1 "))
    }

    @Test
    fun validIpv6_accepted() {
        assertTrue(Config.isLiteralIp("::1"))
        assertTrue(Config.isLiteralIp("fe80::1"))
        assertTrue(Config.isLiteralIp("2001:db8::1"))
        assertTrue(Config.isLiteralIp("::"))
        assertTrue(Config.isLiteralIp("2001:db8:0:0:0:0:2:1"))
        assertTrue(Config.isLiteralIp("::ffff:1.2.3.4"))
    }

    @Test
    fun invalidIpv6_rejected() {
        assertFalse(Config.isLiteralIp("gg::1"))       // g 非 hex
        assertFalse(Config.isLiteralIp("2001:db8::1:gg"))
        assertFalse(Config.isLiteralIp("example.com"))
        assertFalse(Config.isLiteralIp("127.0.0.1.example"))
        assertFalse(Config.isLiteralIp(": :1"))        // 空白
    }
}
