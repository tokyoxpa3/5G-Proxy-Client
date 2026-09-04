package com.tokyoxpa3.socksclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DnsClientTest {

    // 組 name 標籤（無壓縮）
    private fun nameLabels(vararg labels: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (l in labels) {
            val b = l.toByteArray(Charsets.UTF_8)
            out.write(b.size)
            out.write(b)
        }
        out.write(0)
        return out.toByteArray()
    }

    // 組回應封包：單一 question + 單一 answer
    private fun buildResponse(
        id: Int,
        anCount: Int,
        questionName: ByteArray,
        answerName: ByteArray,
        answerType: Int,
        answerRdata: ByteArray
    ): ByteArray {
        val buf = ByteBuffer.allocate(12 + questionName.size + 4 + answerName.size + 10 + answerRdata.size)
            .order(ByteOrder.BIG_ENDIAN)
        buf.putShort(id.toShort())
        buf.putShort(0x8180.toShort()) // QR=1, RD=1, RA=1, rcode=0
        buf.putShort(1) // QDCOUNT
        buf.putShort(anCount.toShort()) // ANCOUNT
        buf.putShort(0)
        buf.putShort(0)
        buf.put(questionName)
        buf.putShort(1)   // QTYPE=A
        buf.putShort(1)   // QCLASS=IN
        if (anCount >= 1) {
            buf.put(answerName)
            buf.putShort(answerType.toShort())
            buf.putShort(1)   // CLASS=IN
            buf.putInt(60)    // TTL
            buf.putShort(answerRdata.size.toShort())
            buf.put(answerRdata)
        }
        return buf.array()
    }

    @Test
    fun buildQuery_hasValidHeaderAndQuestion() {
        val q = DnsClient.buildQuery("vpn.example.com", 0x1234)
        val buf = ByteBuffer.wrap(q).order(ByteOrder.BIG_ENDIAN)
        assertEquals(0x1234, buf.getShort().toInt() and 0xFFFF)
        assertEquals(0x0100, buf.getShort().toInt() and 0xFFFF) // RD=1
        assertEquals(1, buf.getShort().toInt() and 0xFFFF)      // QDCOUNT=1
        assertEquals(0, buf.getShort().toInt() and 0xFFFF)      // ANCOUNT
        assertEquals(0, buf.getShort().toInt() and 0xFFFF)
        assertEquals(0, buf.getShort().toInt() and 0xFFFF)
        // name: 3-byte label "vpn", 7-byte "example", 3-byte "com", 0x00
        assertEquals(3, buf.get().toInt() and 0xFF)
        assertEquals("vpn", String(ByteArray(3).also { buf.get(it) }))
        assertEquals(7, buf.get().toInt() and 0xFF)
        assertEquals("example", String(ByteArray(7).also { buf.get(it) }))
        assertEquals(3, buf.get().toInt() and 0xFF)
        assertEquals("com", String(ByteArray(3).also { buf.get(it) }))
        assertEquals(0, buf.get().toInt() and 0xFF)
        assertEquals(1, buf.getShort().toInt() and 0xFFFF)   // QTYPE=A
        assertEquals(1, buf.getShort().toInt() and 0xFFFF)   // QCLASS=IN
    }

    @Test
    fun parseFirstAddress_returnsIpv4ForARecord() {
        val name = nameLabels("vpn", "example", "com")
        val resp = buildResponse(0x1234, 1, name, name, 1, byteArrayOf(1, 2, 3, 4))
        assertEquals("1.2.3.4", DnsClient.parseFirstAddress(resp))
    }

    @Test
    fun parseFirstAddress_returnsIpv6ForAaaaRecord() {
        val name = nameLabels("vpn", "example", "com")
        val raw6 = ByteArray(16)
        raw6[0] = 0x20; raw6[1] = 0x01
        raw6[2] = 0x0d; raw6[3] = 0xb8.toByte()
        raw6[15] = 0x01
        val resp = buildResponse(0x1234, 1, name, name, 28, raw6)
        assertEquals("2001:db8:0:0:0:0:0:1", DnsClient.parseFirstAddress(resp))
    }

    @Test
    fun parseFirstAddress_returnsNullWhenNoAnswer() {
        val name = nameLabels("vpn", "example", "com")
        val resp = buildResponse(0x1234, 0, name, ByteArray(0), 0, ByteArray(0))
        assertNull(DnsClient.parseFirstAddress(resp))
    }

    @Test
    fun parseFirstAddress_handlesCompressedNamePointer() {
        val qname = nameLabels("vpn", "example", "com")
        // answer 的名稱用壓縮指標 0xC00C（指向封包 offset 12 的 qname）
        val compressedName = byteArrayOf(0xC0.toByte(), 0x0C)
        val buf = ByteBuffer.allocate(12 + qname.size + 4 + compressedName.size + 10 + 4)
            .order(ByteOrder.BIG_ENDIAN)
        buf.putShort(0x1234.toShort())
        buf.putShort(0x8180.toShort())
        buf.putShort(1) // QDCOUNT
        buf.putShort(1) // ANCOUNT
        buf.putShort(0)
        buf.putShort(0)
        buf.put(qname)
        buf.putShort(1) // QTYPE
        buf.putShort(1) // QCLASS
        buf.put(compressedName)
        buf.putShort(1) // TYPE=A
        buf.putShort(1) // CLASS=IN
        buf.putInt(60)
        buf.putShort(4)
        buf.put(byteArrayOf(10, 0, 0, 1))
        assertEquals("10.0.0.1", DnsClient.parseFirstAddress(buf.array()))
    }

    @Test
    fun parseFirstAddress_returnsNullOnRcodeError() {
        val name = nameLabels("vpn", "example", "com")
        val buf = ByteBuffer.allocate(12 + name.size + 4).order(ByteOrder.BIG_ENDIAN)
        buf.putShort(0x1234.toShort())
        buf.putShort(0x8183.toShort()) // rcode=3 (NXDOMAIN)
        buf.putShort(1)
        buf.putShort(0)
        buf.putShort(0)
        buf.putShort(0)
        buf.put(name)
        buf.putShort(1)
        buf.putShort(1)
        assertNull(DnsClient.parseFirstAddress(buf.array()))
    }
}
