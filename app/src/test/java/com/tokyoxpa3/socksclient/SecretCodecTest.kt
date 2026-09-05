package com.tokyoxpa3.socksclient

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretCodecTest {

    @Test
    fun pack_hasPrefixAndIsUnwrappedBase64() {
        val iv = ByteArray(SecretCodec.IV_LEN_BYTES) { it.toByte() }
        val ct = byteArrayOf(1, 2, 3, 4)
        val packed = SecretCodec.pack(iv, ct)
        assertTrue(packed.startsWith(SecretCodec.PREFIX))
        val body = packed.substring(SecretCodec.PREFIX.length)
        // 無換行（Base64 不 wrap）
        assertFalse(body.contains('\n'))
        // 12 + 4 = 16 bytes → ceil(16/3)*4 = 24 個字元（含 padding）
        assertEquals(24, body.length)
    }

    @Test
    fun pack_unpack_roundTrips() {
        val iv = ByteArray(SecretCodec.IV_LEN_BYTES) { (it * 7).toByte() }
        val ct = byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2, 1)
        val (iv2, ct2) = SecretCodec.unpack(SecretCodec.pack(iv, ct))!!
        assertArrayEquals(iv, iv2)
        assertArrayEquals(ct, ct2)
    }

    @Test
    fun isEncrypted_detectsPrefixOnly() {
        assertTrue(SecretCodec.isEncrypted("enc:abc"))
        assertFalse(SecretCodec.isEncrypted("plaintext"))
        assertFalse(SecretCodec.isEncrypted(""))
        assertFalse(SecretCodec.isEncrypted(null))
        // 無冒號不算合法前綴
        assertFalse(SecretCodec.isEncrypted("enc"))
    }

    @Test
    fun unpack_returnsNullForPlaintextOrEmpty() {
        assertNull(SecretCodec.unpack(null))
        assertNull(SecretCodec.unpack(""))
        assertNull(SecretCodec.unpack("plaintext"))
    }

    @Test
    fun unpack_returnsNullForCorruptBase64() {
        assertNull(SecretCodec.unpack("enc:!!!not-base64!!!"))
    }

    @Test
    fun unpack_returnsNullForPayloadShorterThanIv() {
        // "AQID" = Base64(0x01 0x02 0x03)，解出後僅 3 bytes，短於 12-byte IV
        assertNull(SecretCodec.unpack("enc:AQID"))
    }
}