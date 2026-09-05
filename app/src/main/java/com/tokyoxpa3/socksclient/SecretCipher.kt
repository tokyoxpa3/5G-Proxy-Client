package com.tokyoxpa3.socksclient

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 以 Android Keystore 的 AES-256-GCM 金鑰加密機密字串（帳號／密碼、設定檔）。
 * 密文格式（`enc:` 前綴 + Base64(IV ‖ 密文)）與解析邏輯在 [SecretCodec]（純 JVM 可測），
 * 此處僅負責 Keystore 金鑰與 GCM 加解密。前綴用於區分舊版明文（向後相容）。
 */
object SecretCipher {
    private const val TAG = "SecretCipher"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "tunnel_secret_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val TAG_LEN_BITS = 128

    // 取得（或首次產生）Keystore 中的 AES 金鑰。明確設為「不需使用者驗證」：
    // 此參數預設為 true，無安全鎖定畫面的裝置會在產生金鑰時觸發 keystore 的
    // super-encryption（User ECDH key missing）而失敗；VPN 後台服務本就不該要求即時解鎖。
    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return kg.generateKey()
    }

    /** 加密；空字串回傳空字串（不加密空值，保持既有語意）。
     *  加密失敗回傳 null（而非明文）——絕不把未加密的機密寫回儲存，由呼叫端決定後續。 */
    fun encrypt(plain: String): String? {
        if (plain.isEmpty()) return ""
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            // Keystore 硬體金鑰不允許呼叫端自訂 IV（"Caller-provided IV not permitted"），
            // 必須由 Keystore 自行產生，再經 cipher.iv 讀回存入密文。
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            SecretCodec.pack(cipher.iv, ct)
        } catch (e: Exception) {
            // Keystore 硬體故障等極端情況：拒絕回傳明文，避免加密靜默失效而讓
            // 機密以明文落地。回傳 null 讓呼叫端保留舊值或提示使用者。
            Log.e(TAG, "encrypt failed, refusing to return plaintext", e)
            null
        }
    }

    /** 解密；無 `enc:` 前綴視為舊明文直接回傳，解密失敗回傳 null（呼叫端以預設值接）。 */
    fun decrypt(stored: String?): String? {
        if (stored.isNullOrEmpty()) return stored
        if (!SecretCodec.isEncrypted(stored)) return stored
        val (iv, ct) = SecretCodec.unpack(stored) ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_LEN_BITS, iv))
            String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "decrypt failed", e)
            null   // 金鑰遺失／資料損毀 → 視為無值
        }
    }
}