package com.tokyoxpa3.socksclient

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

data class Profile(
    val name: String,
    val host: String,
    val port: String,
    val user: String,
    val pass: String,
    val udpInTcp: Boolean,
    val remoteDns: Boolean,
    val dns1: String,
    val dns2: String,
    val mode: Int,
    val apps: Set<String> = emptySet()
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("host", host)
        put("port", port)
        put("user", user)
        put("pass", pass)
        put("udp_in_tcp", udpInTcp)
        put("remote_dns", remoteDns)
        put("dns1", dns1)
        put("dns2", dns2)
        put("mode", mode)
        if (apps.isNotEmpty()) {
            val arr = JSONArray()
            apps.forEach { arr.put(it) }
            put("apps", arr)
        }
    }

    // 匯出（剪貼簿／跨裝置）用：刻意省略 user/pass，避免機密以明文離開本裝置。
    // 匯入端以空值接住（fromJson 的 optString 預設 ""），密碼需在目標裝置重填。
    fun toExportJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("host", host)
        put("port", port)
        put("udp_in_tcp", udpInTcp)
        put("remote_dns", remoteDns)
        put("dns1", dns1)
        put("dns2", dns2)
        put("mode", mode)
        if (apps.isNotEmpty()) {
            val arr = JSONArray()
            apps.forEach { arr.put(it) }
            put("apps", arr)
        }
    }

    companion object {
        fun fromJson(o: JSONObject): Profile = Profile(
            name = o.optString("name", ""),
            host = o.optString("host", ""),
            port = o.optString("port", Config.DEFAULT_PORT.toString()),
            user = o.optString("user", ""),
            pass = o.optString("pass", ""),
            udpInTcp = o.optBoolean("udp_in_tcp", false),
            remoteDns = o.optBoolean("remote_dns", Config.DEFAULT_REMOTE_DNS),
            dns1 = o.optString("dns1", Config.DEFAULT_DNS1),
            dns2 = o.optString("dns2", Config.DEFAULT_DNS2),
            mode = o.optInt("mode", Config.MODE_GLOBAL),
            apps = o.optJSONArray("apps")?.let { arr ->
                (0 until arr.length()).mapNotNull {
                    try { arr.optString(it).takeIf { s -> s.isNotBlank() } } catch (e: Exception) { null }
                }.toSet()
            } ?: emptySet()
        )
    }
}

object Profiles {
    fun load(ctx: android.content.Context): List<Profile> {
        // 設定檔整份 JSON 以 Keystore 加密入庫（無 "enc:" 前綴／解密失敗回退舊明文）
        val raw = SecretCipher.decrypt(Config.prefs(ctx).getString(Config.KEY_PROFILES, null)) ?: return emptyList()
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
        // 整份 JSON（含 pass 欄位）加密後入庫，避免明文密碼落在 SharedPreferences；
        // 加密失敗保留舊值、不寫入明文。
        val enc = SecretCipher.encrypt(arr.toString()) ?: run {
            Log.e("Profiles", "persist: encrypt failed, profiles not saved")
            return
        }
        Config.prefs(ctx).edit().putString(Config.KEY_PROFILES, enc).apply()
    }
}
