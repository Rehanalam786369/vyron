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

    private val DOH_BYPASS_DOMAINS = setOf(
        "use-application-dns.net",
        "dns.google",
        "dns.google.com",
        "cloudflare-dns.com",
        "mozilla.cloudflare-dns.com",
        "chrome.cloudflare-dns.com",
        "one.one.one.one",
        "dns.quad9.net",
        "dns9.quad9.net",
        "dns.nextdns.io",
        "dns.adguard.com",
        "dns.adguard-dns.com",
        "doh.opendns.com",
        "doh.cleanbrowsing.org",
        "mask.icloud.com",
        "mask-h2.icloud.com"
    )

    /**
     * Returns true if the domain is a browser DoH/Private-DNS bootstrap or canary endpoint.
     * Responding with NXDOMAIN forces browsers (Chrome, Firefox, Edge, Brave) to use our local DNS.
     */
    fun isDoHBypassDomain(rawDomain: String): Boolean {
        val norm = rawDomain.lowercase().trim('.')
        for (b in DOH_BYPASS_DOMAINS) {
            if (norm == b || norm.endsWith(".$b")) {
                return true
            }
        }
        return false
    }

    /**
     * Standard NXDOMAIN fallback response.
     */
    fun craftNxDomain(queryData: ByteArray): ByteArray = craftErrorResponse(queryData, 3)

    /**
     * Standard SERVFAIL fallback response for fast-fail when offline.
     */
    fun craftServFail(queryData: ByteArray): ByteArray = craftErrorResponse(queryData, 2)

    private fun craftErrorResponse(queryData: ByteArray, rcode: Int): ByteArray {
        if (queryData.size < 12) return ByteArray(0)
        val parsed = parseQuery(queryData)
        val qEnd = if (parsed != null && (12 + parsed.questionLength) <= queryData.size) {
            12 + parsed.questionLength
        } else {
            queryData.size
        }
        val out = ByteArrayOutputStream(qEnd)
        out.write(queryData[0].toInt())
        out.write(queryData[1].toInt())
        val rd = (queryData[2].toInt() and 0x01)
        out.write(0x84 or rd)           // QR=1, AA=1, copy RD
        out.write(0x80 or (rcode and 0x0F)) // RA=1, RCODE
        if (parsed != null) {
            out.write(0x00); out.write(0x01) // QDCOUNT = 1
        } else {
            out.write(0x00); out.write(0x00)
        }
        out.write(0x00); out.write(0x00) // ANCOUNT = 0
        out.write(0x00); out.write(0x00) // NSCOUNT = 0
        out.write(0x00); out.write(0x00) // ARCOUNT = 0
        if (parsed != null) {
            out.write(queryData, 12, parsed.questionLength)
        }
        return out.toByteArray()
    }

    fun rewriteTransactionId(respData: ByteArray, txByte0: Byte, txByte1: Byte): ByteArray {
        val copy = respData.clone()
        if (copy.size >= 2) {
            copy[0] = txByte0
            copy[1] = txByte1
        }
        return copy
    }

    fun extractCacheTtlSeconds(respData: ByteArray): Int {
        // Clamp cached DNS responses to 60s so rule updates apply rapidly and offline stays smooth
        if (respData.size < 12) return 0
        val rcode = respData[3].toInt() and 0x0F
        if (rcode != 0 && rcode != 3) return 0
        return 60
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

    /**
     * Wraps a DNS payload into a valid IPv4 UDP packet swapping src/dst IPs and ports.
     */
    fun buildReplyIpv4UdpPacket(origIpPacket: ByteArray, ipHeaderLen: Int, dnsPayload: ByteArray): ByteArray {
        val replyTotalLen = 20 + 8 + dnsPayload.size
        val reply = ByteArray(replyTotalLen)

        reply[0] = 0x45.toByte()
        reply[1] = 0x00.toByte()
        reply[2] = ((replyTotalLen shr 8) and 0xFF).toByte()
        reply[3] = (replyTotalLen and 0xFF).toByte()
        reply[4] = 0x12.toByte()
        reply[5] = 0x34.toByte()
        reply[6] = 0x40.toByte()
        reply[7] = 0x00.toByte()
        reply[8] = 64.toByte()
        reply[9] = 17.toByte()

        // Swap IPv4 addresses
        System.arraycopy(origIpPacket, 16, reply, 12, 4)
        System.arraycopy(origIpPacket, 12, reply, 16, 4)

        var ipChecksum = 0
        for (i in 0 until 10) {
            if (i == 5) continue
            val word = ((reply[i * 2].toInt() and 0xFF) shl 8) or (reply[i * 2 + 1].toInt() and 0xFF)
            ipChecksum += word
        }
        while ((ipChecksum shr 16) > 0) {
            ipChecksum = (ipChecksum and 0xFFFF) + (ipChecksum shr 16)
        }
        ipChecksum = ipChecksum.inv() and 0xFFFF
        reply[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        reply[11] = (ipChecksum and 0xFF).toByte()

        // Swap UDP ports
        reply[20] = origIpPacket[ipHeaderLen + 2]
        reply[21] = origIpPacket[ipHeaderLen + 3]
        reply[22] = origIpPacket[ipHeaderLen]
        reply[23] = origIpPacket[ipHeaderLen + 1]

        val udpLen = 8 + dnsPayload.size
        reply[24] = ((udpLen shr 8) and 0xFF).toByte()
        reply[25] = (udpLen and 0xFF).toByte()
        reply[26] = 0x00.toByte()
        reply[27] = 0x00.toByte()

        System.arraycopy(dnsPayload, 0, reply, 28, dnsPayload.size)
        return reply
    }

    /**
     * Wraps a DNS payload into a valid IPv6 UDP packet with mandatory RFC 2460 pseudo-header checksum.
     */
    fun buildReplyIpv6UdpPacket(origIpPacket: ByteArray, ipHeaderLen: Int, dnsPayload: ByteArray): ByteArray {
        val udpLen = 8 + dnsPayload.size
        val reply = ByteArray(40 + udpLen)

        reply[0] = 0x60.toByte()
        reply[1] = 0x00.toByte()
        reply[2] = 0x00.toByte()
        reply[3] = 0x00.toByte()
        reply[4] = ((udpLen shr 8) and 0xFF).toByte()
        reply[5] = (udpLen and 0xFF).toByte()
        reply[6] = 17.toByte() // Next header = UDP
        reply[7] = 64.toByte() // Hop limit

        // Swap 16-byte IPv6 addresses
        System.arraycopy(origIpPacket, 24, reply, 8, 16)
        System.arraycopy(origIpPacket, 8, reply, 24, 16)

        // Swap UDP ports
        reply[40] = origIpPacket[ipHeaderLen + 2]
        reply[41] = origIpPacket[ipHeaderLen + 3]
        reply[42] = origIpPacket[ipHeaderLen]
        reply[43] = origIpPacket[ipHeaderLen + 1]

        reply[44] = ((udpLen shr 8) and 0xFF).toByte()
        reply[45] = (udpLen and 0xFF).toByte()
        reply[46] = 0x00.toByte()
        reply[47] = 0x00.toByte()

        System.arraycopy(dnsPayload, 0, reply, 48, dnsPayload.size)

        // RFC 2460 IPv6 UDP checksum over pseudo-header + UDP packet
        var sum = 0L
        for (i in 8 until 40 step 2) {
            sum += ((reply[i].toInt() and 0xFF) shl 8) or (reply[i + 1].toInt() and 0xFF)
        }
        sum += ((udpLen ushr 16) and 0xFFFF)
        sum += (udpLen and 0xFFFF)
        sum += 17L

        var idx = 40
        while (idx + 1 < reply.size) {
            sum += ((reply[idx].toInt() and 0xFF) shl 8) or (reply[idx + 1].toInt() and 0xFF)
            idx += 2
        }
        if (idx < reply.size) {
            sum += ((reply[idx].toInt() and 0xFF) shl 8)
        }

        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        var csum = (sum.inv() and 0xFFFFL).toInt()
        if (csum == 0) csum = 0xFFFF
        reply[46] = ((csum shr 8) and 0xFF).toByte()
        reply[47] = (csum and 0xFF).toByte()

        return reply
    }
}
