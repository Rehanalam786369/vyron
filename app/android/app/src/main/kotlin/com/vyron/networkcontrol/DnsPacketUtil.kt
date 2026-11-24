package com.vyron.networkcontrol

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

data class DnsQuery(
    val id: Int,
    val domain: String,
    val qType: Int,
    val qClass: Int,
    val questionLength: Int
)

object DnsPacketUtil {

    /**
     * Parses the DNS query domain name and query type from raw DNS UDP payload.
     */
    fun parseQuery(data: ByteArray): DnsQuery? {
        if (data.size < 12) return null
        val id = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)

        // Read QNAME starting at offset 12
        var pos = 12
        val sb = StringBuilder()
        while (pos < data.size) {
            val len = data[pos].toInt() and 0xFF
            if (len == 0) {
                pos++ // skip terminating 0x00
                break
            }
            pos++
            if (pos + len > data.size) return null
            for (i in 0 until len) {
                sb.append(data[pos + i].toInt().toChar())
            }
            sb.append('.')
            pos += len
        }

        if (sb.isEmpty()) return null
        val domain = sb.toString().trimEnd('.').lowercase()

        // Read QTYPE and QCLASS
        if (pos + 4 > data.size) return null
        val qType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        val qClass = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)
        pos += 4

        return DnsQuery(
            id = id,
            domain = domain,
            qType = qType,
            qClass = qClass,
            questionLength = pos - 12
        )
    }

    /**
     * Builds a valid RFC 1035 DNS response blocking the domain.
     * Returns 0.0.0.0 for Type A (IPv4) queries or :: for Type AAAA (IPv6) queries with TTL 300.
     * For other query types (e.g. HTTPS, TXT), returns NXDOMAIN or empty NOERROR.
     */
    fun craftBlockedResponse(queryData: ByteArray): ByteArray {
        val query = parseQuery(queryData) ?: return craftNxDomain(queryData)
        val out = ByteArrayOutputStream()

        // 1. Transaction ID (2 bytes)
        out.write(queryData[0].toInt())
        out.write(queryData[1].toInt())

        // 2. Flags (2 bytes)
        // QR=1 (Response), Opcode=0000, AA=1, TC=0, RD=(copy from query)
        val rd = (queryData[2].toInt() and 0x01)
        val flagByte1 = 0x84 or rd // 10000100 | rd (QR=1, AA=1)
        // RA=1, Z=000, RCODE=0000 (NOERROR)
        val flagByte2 = 0x80 // 10000000 (RA=1, RCODE=0)
        out.write(flagByte1)
        out.write(flagByte2)

        // 3. Counts
        // QDCOUNT = 1
        out.write(0x00)
        out.write(0x01)
        // ANCOUNT = 1 (A or AAAA)
        if (query.qType == 1 || query.qType == 28) {
            out.write(0x00)
            out.write(0x01)
        } else {
            out.write(0x00)
            out.write(0x00)
        }
        // NSCOUNT = 0
        out.write(0x00)
        out.write(0x00)
        // ARCOUNT = 0
        out.write(0x00)
        out.write(0x00)

        // 4. Copy Question Section exactly as sent
        val questionTotalBytes = 12 + query.questionLength
        if (questionTotalBytes <= queryData.size) {
            out.write(queryData, 12, query.questionLength)
        }

        // 5. Answer Section (if Type A or AAAA)
        if (query.qType == 1) { // Type A -> 0.0.0.0
            // Pointer to QNAME at offset 12 (0xC00C)
            out.write(0xC0)
            out.write(0x0C)
            // Type A (0x0001)
            out.write(0x00)
            out.write(0x01)
            // Class IN (0x0001)
            out.write(0x00)
            out.write(0x01)
            // TTL 300 seconds (0x0000012C)
            out.write(0x00)
            out.write(0x00)
            out.write(0x01)
            out.write(0x2C)
            // Data length 4
            out.write(0x00)
            out.write(0x04)
            // IP 0.0.0.0
            out.write(0x00)
            out.write(0x00)
            out.write(0x00)
            out.write(0x00)
        } else if (query.qType == 28) { // Type AAAA -> ::
            // Pointer to QNAME at offset 12 (0xC00C)
            out.write(0xC0)
            out.write(0x0C)
            // Type AAAA (0x001C)
            out.write(0x00)
            out.write(0x1C)
            // Class IN (0x0001)
            out.write(0x00)
            out.write(0x01)
            // TTL 300 seconds
            out.write(0x00)
            out.write(0x00)
            out.write(0x01)
            out.write(0x2C)
            // Data length 16
            out.write(0x00)
            out.write(0x10)
            // IPv6 :: (16 zeros)
            for (i in 0 until 16) {
                out.write(0x00)
            }
        }

        return out.toByteArray()
    }

    /**
     * Standard NXDOMAIN fallback response.
     */
    fun craftNxDomain(queryData: ByteArray): ByteArray {
        if (queryData.size < 12) return ByteArray(0)
        val resp = queryData.clone()
        val rd = (queryData[2].toInt() and 0x01)
        resp[2] = (0x84 or rd).toByte() // QR=1, AA=1
        resp[3] = 0x83.toByte()          // RA=1, RCODE=3 (NXDOMAIN)
        resp[6] = 0x00.toByte()          // ANCOUNT = 0
        resp[7] = 0x00.toByte()
        resp[8] = 0x00.toByte()          // NSCOUNT = 0
        resp[9] = 0x00.toByte()
        resp[10] = 0x00.toByte()         // ARCOUNT = 0
        resp[11] = 0x00.toByte()
        return resp
    }

    /**
     * Checks whether a domain matches the blocklist (including all subdomains).
     */
    fun isDomainBlocked(
        rawDomain: String,
        blockedDomains: Set<String>,
        allowedDomains: Set<String>
    ): Boolean {
        val norm = rawDomain.lowercase().trim('.')

        // 1. Check allowed override first
        for (allow in allowedDomains) {
            val a = allow.lowercase().trim('.')
            if (norm == a || norm.endsWith(".$a")) {
                return false
            }
        }

        // 2. Check blocked domains
        for (block in blockedDomains) {
            val b = block.lowercase().trim('.')
            if (norm == b || norm.endsWith(".$b")) {
                return true
            }
        }

        return false
    }
}
