package com.tokyoxpa3.socksclient

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigValidatorTest {

    @Test
    fun serverValid() {
        assertTrue(ConfigValidator.isServerValid("example.com", 1080))
        assertTrue(ConfigValidator.isServerValid("1.2.3.4", 1))
        assertTrue(ConfigValidator.isServerValid("1.2.3.4", 65535))
    }

    @Test
    fun serverInvalid() {
        assertFalse(ConfigValidator.isServerValid("", 1080))
        assertFalse(ConfigValidator.isServerValid("   ", 1080))
        assertFalse(ConfigValidator.isServerValid("host", null))
        assertFalse(ConfigValidator.isServerValid("host", 0))
        assertFalse(ConfigValidator.isServerValid("host", 65536))
        assertFalse(ConfigValidator.isServerValid("host", -1))
    }

    @Test
    fun dnsValid() {
        assertTrue(ConfigValidator.isDnsValid(""))      // 空白 → 不填則用預設
        assertTrue(ConfigValidator.isDnsValid("8.8.8.8"))
        assertTrue(ConfigValidator.isDnsValid("1.1.1.1"))
        assertTrue(ConfigValidator.isDnsValid("::1"))
        assertTrue(ConfigValidator.isDnsValid("2001:db8::1"))
    }

    @Test
    fun dnsInvalid() {
        assertFalse(ConfigValidator.isDnsValid("example.com"))
        assertFalse(ConfigValidator.isDnsValid("8.8.8.8.8"))
        assertFalse(ConfigValidator.isDnsValid("300.1.1.1"))
    }
}
