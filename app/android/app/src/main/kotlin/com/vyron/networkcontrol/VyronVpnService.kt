package com.vyron.networkcontrol

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.nio.ByteBuffer
import java.util.Calendar
import java.util.Collections
import kotlin.concurrent.thread

class VyronVpnService : VpnService() {

    private lateinit var policyStore: PolicyStore
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val batchedLogs = Collections.synchronizedList(mutableListOf<JSONObject>())
    private var lastBlockedIps = setOf<String>()

    override fun onCreate() {
        super.onCreate()
        policyStore = PolicyStore(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "ACTION_STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        startForegroundNotification()
        startVpn()
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val channelId = "vyron_shield_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "VYRON Network Shield",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Zero-lag split-tunnel network protection"
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }

        val notifyIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notifyIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification: Notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
                .setContentTitle("VYRON Shield Active")
                .setContentText("Zero-lag split-tunnel network enforcement enabled")
                .setSmallIcon(android.R.drawable.ic_secure)
                .setContentIntent(pendingIntent)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("VYRON Shield Active")
                .setContentText("Zero-lag split-tunnel network enforcement enabled")
                .setSmallIcon(android.R.drawable.ic_secure)
                .setContentIntent(pendingIntent)
                .build()
        }

        startForeground(1001, notification)
    }

    private fun startVpn() {
        if (isRunning) return
        isRunning = true

        val blockedIps = policyStore.getBlockedIps()
        lastBlockedIps = blockedIps

        val builder = Builder().apply {
            setSession("VYRON Split-Tunnel")
            // Virtual TUN interface address
            addAddress("10.0.0.1", 32)
            // Virtual DNS server inside the TUN
            addDnsServer("10.0.0.2")
            // Route ONLY queries to virtual DNS into the TUN
            addRoute("10.0.0.2", 32)

            // Route explicitly blocked IPs into the TUN so they are dropped
            for (ip in blockedIps) {
                try {
                    addRoute(ip, 32)
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }

            // Exclude VYRON app traffic to prevent sync loops
            try {
                addDisallowedApplication(packageName)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        try {
            vpnInterface = builder.establish()
        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
            return
        }

        // Start packet routing worker thread
        thread(name = "VyronVpnPacketThread") {
            runPacketLoop()
        }

        // Start gentle 15-second background sync thread
        thread(name = "VyronVpnSyncThread") {
            runSyncLoop()
        }
    }

    private fun runPacketLoop() {
        val pfd = vpnInterface ?: return
        val inStream = FileInputStream(pfd.fileDescriptor)
        val outStream = FileOutputStream(pfd.fileDescriptor)
        val packet = ByteBuffer.allocate(32767)

        val upstreamDns = InetAddress.getByName("1.1.1.1")
        val upstreamSocket = DatagramSocket()
        protect(upstreamSocket)
        upstreamSocket.soTimeout = 2500

        while (isRunning) {
            try {
                packet.clear()
                val length = inStream.read(packet.array())
                if (length <= 0) continue

                packet.limit(length)

                // Inspect IPv4 Header (version 4 is (header[0] >> 4) == 4)
                val firstByte = packet.get(0).toInt()
                val version = (firstByte shr 4) and 0x0F
                if (version != 4) continue

                val headerLength = (firstByte and 0x0F) * 4
                val protocol = packet.get(9).toInt() and 0xFF

                // Check destination IP
                val destIp = String.format(
                    "%d.%d.%d.%d",
                    packet.get(16).toInt() and 0xFF,
                    packet.get(17).toInt() and 0xFF,
                    packet.get(18).toInt() and 0xFF,
                    packet.get(19).toInt() and 0xFF
                )

                // If destination IP is in blocked IPs, drop packet and log
                if (lastBlockedIps.contains(destIp)) {
                    queueLog("ip", destIp, "BLOCKED", "Matched direct blocked IP policy ($destIp)")
                    continue
                }

                // If UDP packet (protocol 17)
                if (protocol == 17 && length > headerLength + 8) {
                    val udpDestPort = ((packet.get(headerLength + 2).toInt() and 0xFF) shl 8) or
                            (packet.get(headerLength + 3).toInt() and 0xFF)

                    // If DNS query targeting virtual DNS server (10.0.0.2:53)
                    if (udpDestPort == 53) {
                        val dnsOffset = headerLength + 8
                        val dnsLength = length - dnsOffset

                        val dnsData = ByteArray(dnsLength)
                        System.arraycopy(packet.array(), dnsOffset, dnsData, 0, dnsLength)

                        val queriedDomain = parseDnsQuestion(dnsData)

                        if (queriedDomain != null) {
                            val isBlocked = isDomainBlocked(queriedDomain)

                            if (isBlocked) {
                                queueLog("domain", queriedDomain, "BLOCKED", "Matched domain block policy ($queriedDomain)")
                                val nxDomainResp = craftNxDomainResponse(dnsData)
                                if (nxDomainResp != null) {
                                    val replyPacket = buildReplyUdpPacket(packet.array(), headerLength, nxDomainResp)
                                    outStream.write(replyPacket)
                                }
                            } else {
                                // Forward to upstream DNS
                                try {
                                    val sendPacket = DatagramPacket(dnsData, dnsData.size, upstreamDns, 53)
                                    upstreamSocket.send(sendPacket)

                                    val respBuf = ByteArray(2048)
                                    val recvPacket = DatagramPacket(respBuf, respBuf.size)
                                    upstreamSocket.receive(recvPacket)

                                    val realRespData = ByteArray(recvPacket.length)
                                    System.arraycopy(recvPacket.data, 0, realRespData, 0, recvPacket.length)

                                    val replyPacket = buildReplyUdpPacket(packet.array(), headerLength, realRespData)
                                    outStream.write(replyPacket)
                                } catch (e: Exception) {
                                    // Timeout or network drop
                                }
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                if (!isRunning) break
            }
        }

        try {
            upstreamSocket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun isDomainBlocked(domain: String): Boolean {
        val norm = domain.lowercase().trim('.')

        // 1. Check active waivers
        val nowUtc = System.currentTimeMillis()
        for (w in policyStore.getActiveWaivers()) {
            if (w.targetType == "domain") {
                val wt = w.target.lowercase().trim('.')
                if (norm == wt || norm.endsWith(".$wt")) {
                    if (w.expiresAtEpochMs > nowUtc) {
                        return false // Waived
                    }
                }
            }
        }

        // 2. Check allowed domains (whitelist override)
        for (allow in policyStore.getAllowedDomains()) {
            val a = allow.trim('.')
            if (norm == a || norm.endsWith(".$a")) {
                return false
            }
        }

        // 3. Check blocked domains
        for (block in policyStore.getBlockedDomains()) {
            val b = block.trim('.')
            if (norm == b || norm.endsWith(".$b")) {
                return true
            }
        }

        return false
    }

    private fun parseDnsQuestion(dnsData: ByteArray): String? {
        if (dnsData.size < 12) return null
        var pos = 12
        val sb = StringBuilder()
        while (pos < dnsData.size) {
            val len = dnsData[pos].toInt() and 0xFF
            if (len == 0) break
            pos++
            if (pos + len > dnsData.size) return null
            for (i in 0 until len) {
                sb.append(dnsData[pos + i].toInt().toChar())
            }
            sb.append('.')
            pos += len
        }
        return if (sb.isNotEmpty()) sb.toString().trimEnd('.') else null
    }

    private fun craftNxDomainResponse(queryDnsData: ByteArray): ByteArray? {
        if (queryDnsData.size < 12) return null
        val response = queryDnsData.clone()

        // Flags byte 2: Response (1), Opcode (0000), AA (0), TC (0), RD (copied)
        response[2] = ((queryDnsData[2].toInt() or 0x80) and 0xFA.inv()).toByte()
        // Flags byte 3: RA (1), Z (000), RCODE = 3 (NXDOMAIN: 0011)
        response[3] = 0x83.toByte()

        return response
    }

    private fun buildReplyUdpPacket(origIpPacket: ByteArray, ipHeaderLen: Int, dnsPayload: ByteArray): ByteArray {
        val replyTotalLen = 20 + 8 + dnsPayload.size
        val reply = ByteArray(replyTotalLen)

        // IP Header
        reply[0] = 0x45.toByte() // Version 4, IHL 5
        reply[1] = 0x00.toByte()
        reply[2] = ((replyTotalLen shr 8) and 0xFF).toByte()
        reply[3] = (replyTotalLen and 0xFF).toByte()
        reply[4] = 0x12.toByte() // ID
        reply[5] = 0x34.toByte()
        reply[6] = 0x40.toByte() // Don't fragment
        reply[7] = 0x00.toByte()
        reply[8] = 64.toByte()   // TTL
        reply[9] = 17.toByte()   // Protocol UDP

        // Swap IPs: Source becomes original Dest (10.0.0.2), Dest becomes original Source (10.0.0.1)
        reply[12] = origIpPacket[16]
        reply[13] = origIpPacket[17]
        reply[14] = origIpPacket[18]
        reply[15] = origIpPacket[19]

        reply[16] = origIpPacket[12]
        reply[17] = origIpPacket[13]
        reply[18] = origIpPacket[14]
        reply[19] = origIpPacket[15]

        // Compute IP checksum
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

        // UDP Header
        // Swap Ports: Source is 53, Dest is client port
        reply[20] = 0x00.toByte()
        reply[21] = 0x35.toByte()
        reply[22] = origIpPacket[ipHeaderLen]
        reply[23] = origIpPacket[ipHeaderLen + 1]

        val udpLen = 8 + dnsPayload.size
        reply[24] = ((udpLen shr 8) and 0xFF).toByte()
        reply[25] = (udpLen and 0xFF).toByte()
        reply[26] = 0x00.toByte() // Checksum optional in IPv4 UDP
        reply[27] = 0x00.toByte()

        // Copy DNS payload
        System.arraycopy(dnsPayload, 0, reply, 28, dnsPayload.size)

        return reply
    }

    private fun queueLog(eventType: String, target: String, status: String, reason: String) {
        val obj = JSONObject().apply {
            put("event_type", eventType)
            put("target", target)
            put("status", status)
            put("reason", reason)
        }
        batchedLogs.add(obj)
    }

    private fun runSyncLoop() {
        while (isRunning) {
            try {
                syncWithServer()
            } catch (e: Exception) {
                // Ignore sync network failure
            }

            try {
                Thread.sleep(15000)
            } catch (e: InterruptedException) {
                break
            }
        }
    }

    private fun syncWithServer() {
        val serverUrl = policyStore.serverUrl.trimEnd('/')
        val token = policyStore.deviceToken
        if (token.isEmpty()) return

        // 1. Fetch Latest Policy
        try {
            val url = URL("$serverUrl/api/device/policy")
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.setRequestProperty("X-VYRON-TOKEN", token)
            conn.connectTimeout = 6000
            conn.readTimeout = 6000

            if (conn.responseCode == 200) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                policyStore.saveFullPolicyJson(body)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // 2. Upload Today's Usage Stats
        try {
            val usageList = collectTodayUsage()
            if (usageList.length() > 0) {
                val url = URL("$serverUrl/api/device/usage")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("X-VYRON-TOKEN", token)
                conn.doOutput = true
                conn.connectTimeout = 6000

                val payload = JSONObject().apply { put("usage", usageList) }
                OutputStreamWriter(conn.outputStream).use { it.write(payload.toString()) }
                conn.responseCode
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // 3. Flush Batched Logs
        if (batchedLogs.isNotEmpty()) {
            val toSend = ArrayList<JSONObject>()
            synchronized(batchedLogs) {
                toSend.addAll(batchedLogs)
                batchedLogs.clear()
            }

            if (toSend.isNotEmpty()) {
                try {
                    val url = URL("$serverUrl/api/device/logs")
                    val conn = url.openConnection() as HttpURLConnection
                    conn.requestMethod = "POST"
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.setRequestProperty("X-VYRON-TOKEN", token)
                    conn.doOutput = true
                    conn.connectTimeout = 6000

                    val payload = JSONObject().apply {
                        val arr = JSONArray()
                        toSend.forEach { arr.put(it) }
                        put("logs", arr)
                    }
                    OutputStreamWriter(conn.outputStream).use { it.write(payload.toString()) }
                    conn.responseCode
                } catch (e: Exception) {
                    // Re-queue logs if failed
                    batchedLogs.addAll(toSend)
                }
            }
        }
    }

    private fun collectTodayUsage(): JSONArray {
        val arr = JSONArray()
        try {
            val usageManager = getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return arr
            val cal = Calendar.getInstance().apply {
                set(Calendar.HOUR_OF_DAY, 0)
                set(Calendar.MINUTE, 0)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }
            val startOfDay = cal.timeInMillis
            val endOfDay = System.currentTimeMillis()

            val statsList = usageManager.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, startOfDay, endOfDay)
            for (stat in statsList) {
                val mins = (stat.totalTimeInForeground / 60000).toInt()
                if (mins > 0) {
                    arr.put(JSONObject().apply {
                        put("package_name", stat.packageName.lowercase())
                        put("minutes_used", mins)
                    })
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return arr
    }

    private fun stopVpn() {
        isRunning = false
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        vpnInterface = null
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
