package com.tokyoxpa3.socksclient

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileTest {

    private fun sample() = Profile(
        name = "Home",
        host = "192.168.1.178",
        port = "1080",
        user = "u",
        pass = "p",
        udpInTcp = true,
        remoteDns = true,
        dns1 = "8.8.8.8",
        dns2 = "1.1.1.1",
        mode = Config.MODE_EXCLUDE
    )

    @Test
    fun roundTrip_preservesAllFields() {
        val p = sample()
        val restored = Profile.fromJson(p.toJson())
        assertEquals(p, restored)
    }

    @Test
    fun fromJson_defaults_whenMissing() {
        val p = Profile.fromJson(JSONObject().put("name", "X"))
        assertEquals("X", p.name)
        assertEquals("1080", p.port)
        assertEquals("8.8.8.8", p.dns1)
        assertEquals("1.1.1.1", p.dns2)
        assertEquals(Config.MODE_GLOBAL, p.mode)
        assertEquals(false, p.udpInTcp)
        assertEquals(false, p.remoteDns)
        assertEquals("", p.host)
        assertEquals("", p.pass)
    }

    @Test
    fun fromJson_handlesNullAndOddTypes() {
        val p = Profile.fromJson(JSONObject().put("name", "Z").put("port", 1080).put("udp_in_tcp", "yes"))
        assertEquals("Z", p.name)
        // optString(1080) → "1080"
        assertEquals("1080", p.port)
        // optBoolean("yes") → false
        assertEquals(false, p.udpInTcp)
    }

    @Test
    fun roundTrip_appsEmpty_default() {
        val p = sample() // apps 預設 emptySet
        assertTrue(p.apps.isEmpty())
        assertEquals(p, Profile.fromJson(p.toJson()))
        // 空 apps 不寫 "apps" 鍵
        assertTrue(!p.toJson().has("apps"))
    }

    @Test
    fun roundTrip_appsNonEmpty() {
        val p = sample().copy(apps = setOf("com.a", "com.b"))
        val restored = Profile.fromJson(p.toJson())
        assertEquals(setOf("com.a", "com.b"), restored.apps)
        assertEquals(p, restored)
    }

    @Test
    fun fromJson_missingAppsKey_returnsEmptySet() {
        val o = sample().toJson()
        o.remove("apps")
        val p = Profile.fromJson(o)
        assertTrue(p.apps.isEmpty())
    }

    @Test
    fun profilesJson_arrayRoundTrip() {
        val list = listOf(sample(), sample().copy(name = "Office", port = "1090"))
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        val restored = (0 until arr.length()).mapNotNull {
            try {
                Profile.fromJson(arr.getJSONObject(it))
            } catch (e: Exception) {
                null
            }
        }
        assertEquals(list, restored)
        assertTrue(restored.map { it.name }.containsAll(listOf("Home", "Office")))
    }
}
