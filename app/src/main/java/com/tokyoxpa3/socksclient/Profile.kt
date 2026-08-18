package com.tokyoxpa3.socksclient

import org.json.JSONArray
import org.json.JSONObject

data class Profile(
    val name: String,
    val host: String,
    val port: String,
    val user: String,
    val pass: String,
    val udpInTcp: Boolean,
    val dns1: String,
    val dns2: String,
    val mode: Int
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("host", host)
        put("port", port)
        put("user", user)
        put("pass", pass)
        put("udp_in_tcp", udpInTcp)
        put("dns1", dns1)
        put("dns2", dns2)
        put("mode", mode)
    }

    companion object {
        fun fromJson(o: JSONObject): Profile = Profile(
            name = o.optString("name", ""),
            host = o.optString("host", ""),
            port = o.optString("port", "1080"),
            user = o.optString("user", ""),
            pass = o.optString("pass", ""),
            udpInTcp = o.optBoolean("udp_in_tcp", false),
            dns1 = o.optString("dns1", "8.8.8.8"),
            dns2 = o.optString("dns2", "1.1.1.1"),
            mode = o.optInt("mode", Config.MODE_GLOBAL)
        )
    }
}

object Profiles {
    fun load(ctx: android.content.Context): List<Profile> {
        val raw = Config.prefs(ctx).getString(Config.KEY_PROFILES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull {
                try { Profile.fromJson(arr.getJSONObject(it)) } catch (e: Exception) { null }
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun find(ctx: android.content.Context, name: String): Profile? =
        load(ctx).firstOrNull { it.name == name }

    fun save(ctx: android.content.Context, profile: Profile) {
        val list = load(ctx).toMutableList()
        val idx = list.indexOfFirst { it.name == profile.name }
        if (idx >= 0) list[idx] = profile else list.add(profile)
        persist(ctx, list)
    }

    fun delete(ctx: android.content.Context, name: String) {
        persist(ctx, load(ctx).filterNot { it.name == name })
    }

    fun names(ctx: android.content.Context): List<String> = load(ctx).map { it.name }

    private fun persist(ctx: android.content.Context, list: List<Profile>) {
        val arr = JSONArray()
        list.forEach { arr.put(it.toJson()) }
        Config.prefs(ctx).edit().putString(Config.KEY_PROFILES, arr.toString()).apply()
    }
}