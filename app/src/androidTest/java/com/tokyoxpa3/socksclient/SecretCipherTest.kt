package com.tokyoxpa3.socksclient

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SecretCipher 的儀器化測試——驗證真實 AndroidKeyStore AES-256-GCM 加解密。
 * JVM 環境無法提供 AndroidKeyStore provider，故必須在真機/模擬器上跑
 * （connectedDebugAndroidTest），純格式邏輯則另由 JVM 的 SecretCodecTest 覆蓋。
 */
@RunWith(AndroidJUnit4::class)
class SecretCipherTest {

    @Test
    fun roundTrip() {
        val enc = SecretCipher.encrypt("my secret value")
        assertTrue(enc != null)
        assertTrue(enc!!.startsWith(SecretCodec.PREFIX))
        assertEquals("my secret value", SecretCipher.decrypt(enc))
    }

    @Test
    fun emptyStringIsPassThrough() {
        assertEquals("", SecretCipher.encrypt(""))
        assertEquals("", SecretCipher.decrypt(""))
    }

    @Test
    fun legacyPlaintextPassesThrough() {
        assertEquals("legacy-plain", SecretCipher.decrypt("legacy-plain"))
    }

    @Test
    fun corruptCiphertextReturnsNull() {
        assertNull(SecretCipher.decrypt("enc:!!!!not-base64"))
    }

    @Test
    fun encryptNeverReturnsPlaintext() {
        val plain = "sensitive-credential"
        val enc = SecretCipher.encrypt(plain)
        assertTrue(enc != null)
        assertTrue(enc!!.startsWith(SecretCodec.PREFIX))
        assertNotEquals(plain, enc)
    }
}
