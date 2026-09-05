package com.tokyoxpa3.socksclient

import java.util.Base64

/**
 * 機密密文的封裝格式（純 JVM 可測，不依賴 android.*）：
 *   `enc:` 前綴 + Base64( 12-byte IV + ciphertext )
 * 前綴用於區分舊版明文（向後相容）；解密失敗或格式不符由呼叫端決定回退行為。
 */
object SecretCodec {
    const val PREFIX = "enc:"
    const val IV_LEN_BYTES = 12

    /** 是否為加密密文（帶 `enc:` 前綴）。純字串判斷，供 decrypt 決定走解密或明文回傳。 */
    fun isEncrypted(stored: String?): Boolean = stored?.startsWith(PREFIX) == true

    /** iv + ciphertext → `enc:` + Base64（無換行）。 */
    fun pack(iv: ByteArray, ciphertext: ByteArray): String {
        val out = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ciphertext, 0, out, iv.size, ciphertext.size)
        return PREFIX + Base64.getEncoder().encodeToString(out)
    }

    /** 解析密文 → (iv, ciphertext)；無前綴、Base64 損毀或長度不足 IV 回傳 null。 */
    fun unpack(stored: String?): Pair<ByteArray, ByteArray>? {
        if (!isEncrypted(stored)) return null
        return try {
            val raw = Base64.getDecoder().decode(stored!!.substring(PREFIX.length))
            if (raw.size < IV_LEN_BYTES) null
            else raw.copyOfRange(0, IV_LEN_BYTES) to raw.copyOfRange(IV_LEN_BYTES, raw.size)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}