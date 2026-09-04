package com.tokyoxpa3.socksclient

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 極簡 DNS 用戶端（純邏輯，僅封包組裝／解析，不做任何網路 I/O）。
 * 供軟重連在 VPN 隧道開啟期間，以 protected socket 直接向 DNS 伺服器查詢
 * 伺服器 hostname 的真實 IP——繞過隧道，避免被 Remote DNS 攔截成 fake IP。
 */
object DnsClient {

    private const val TYPE_A = 1
    private const val TYPE_AAAA = 28
    private const val CLASS_IN = 1

    /**
     * 組一個 A-record 查詢封包：隨機 ID、RD=1（期望遞迴）、單一 question。
     * 回傳的位元組可直接送給 DNS 伺服器的 53 port。
     */
    fun buildQuery(hostname: String, id: Int = 0x1234): ByteArray {
        val name = encodeName(hostname)
        val out = ByteBuffer.allocate(12 + name.size + 4).order(ByteOrder.BIG_ENDIAN)
        out.putShort((id and 0xFFFF).toShort())
        out.putShort(0x0100.toShort())   // RD=1
        out.putShort(0x0001.toShort())   // QDCOUNT=1
        out.putShort(0x0000.toShort())   // ANCOUNT
        out.putShort(0x0000.toShort())   // NSCOUNT
        out.putShort(0x0000.toShort())   // ARCOUNT
        out.put(name)
        out.putShort(TYPE_A.toShort())   // QTYPE=A
        out.putShort(CLASS_IN.toShort()) // QCLASS=IN
        return out.array()
    }

    /**
     * 從回應封包解析第一個 A（type 1）或 AAAA（type 28）answer 的位址字串。
     * 無 A/AAAA answer 時回傳 null。支援 DNS 名稱壓縮指標（0xC0xx）。
     */
    fun parseFirstAddress(response: ByteArray): String? {
        val buf = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN)
        if (buf.remaining() < 12) return null

        val id = buf.getShort().toInt() and 0xFFFF
        val flags = buf.getShort().toInt() and 0xFFFF
        val qdCount = buf.getShort().toInt() and 0xFFFF
        val anCount = buf.getShort().toInt() and 0xFFFF
        buf.getShort() // NSCOUNT
        buf.getShort() // ARCOUNT

        @Suppress("unused") val rcode = flags and 0x000F
        if (rcode != 0) return null
        // 與查詢 id 不符的回應（可能收到上一個查詢的遲到封包）
        // 此處不校驗，交由呼叫端決定；純解析只回報是否有可用 answer。
        @Suppress("unused") val _id = id

        // 跳過 question 區段
        for (q in 0 until qdCount) {
            if (!skipName(buf)) return null
            if (buf.remaining() < 4) return null
            buf.position(buf.position() + 4) // QTYPE + QCLASS
        }

        // 遍歷 answer 區段找第一個 A/AAAA
        for (a in 0 until anCount) {
            if (!skipName(buf)) return null
            if (buf.remaining() < 10) return null
            val type = buf.getShort().toInt() and 0xFFFF
            val cls = buf.getShort().toInt() and 0xFFFF
            buf.getInt() // TTL
            val rdLength = buf.getShort().toInt() and 0xFFFF
            if (buf.remaining() < rdLength) return null

            if (cls == CLASS_IN && type == TYPE_A && rdLength == 4) {
                val b0 = buf.get().toInt() and 0xFF
                val b1 = buf.get().toInt() and 0xFF
                val b2 = buf.get().toInt() and 0xFF
                val b3 = buf.get().toInt() and 0xFF
                return "$b0.$b1.$b2.$b3"
            } else if (cls == CLASS_IN && type == TYPE_AAAA && rdLength == 16) {
                val raw = ByteArray(16)
                buf.get(raw)
                return formatIpv6(raw)
            } else {
                // 其他記錄：跳過 RDLENGTH 位元組
                buf.position(buf.position() + rdLength)
            }
        }
        return null
    }

    // 將 hostname 編碼成 DNS label 序列（結尾以 0x00 長度 byte 結束）
    private fun encodeName(hostname: String): ByteArray {
        val labels = hostname.trimEnd('.').split('.')
        val out = ByteBuffer.allocate(hostname.length + 2).order(ByteOrder.BIG_ENDIAN)
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.UTF_8)
            out.put(bytes.size.toByte())
            out.put(bytes)
        }
        out.put(0)
        val result = ByteArray(out.position())
        out.rewind()
        out.get(result)
        return result
    }

    // 跳過一個 DNS 名稱（含壓縮指標），回傳是否成功
    private fun skipName(buf: ByteBuffer): Boolean {
        while (true) {
            if (buf.remaining() < 1) return false
            val len = buf.get().toInt() and 0xFF
            if (len == 0) return true
            if (len and 0xC0 == 0xC0) {
                // 壓縮指標：佔 2 bytes，跳到指標後即視為名稱結束
                if (buf.remaining() < 1) return false
                buf.get()
                return true
            }
            if (len and 0xC0 != 0) return false // 未知標籤型態
            if (buf.remaining() < len) return false
            buf.position(buf.position() + len)
        }
    }

    // 16 bytes 網路序 IPv6 → 冒號壓縮字串（精簡但不展開 0 壓縮，僅用於回傳原生 connect 用）
    private fun formatIpv6(raw: ByteArray): String {
        val sb = StringBuilder()
        for (i in 0 until 16 step 2) {
            val word = ((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)
            if (i > 0) sb.append(':')
            sb.append(String.format("%x", word))
        }
        return sb.toString()
    }
}
