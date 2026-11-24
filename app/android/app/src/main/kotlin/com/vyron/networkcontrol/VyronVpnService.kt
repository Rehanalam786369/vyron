package com.vyron.networkcontrol

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * Dual-Stack Split-Tunnel On-Phone Default DNS Firewall.
 *
 * Forces all browsers (Chrome, Brave, Firefox, Edge, Opera, Samsung Internet) and apps
 * across both IPv4 & IPv6 to use VYRON's local cached DNS engine on-device:
 * - Zero dependency on remote control-panel speed during web browsing
 * - Works online and offline using cached rules in PolicyStore
 * - Blocks DoH/DoT bypasses so no browser can circumvent filtering
 */
class VyronVpnService : VpnService() {

    companion object {
        @Volatile
        var isServiceRunning: Boolean = false
    }

    private lateinit var policyStore: PolicyStore
    private var vpnInterface: ParcelFileDescriptor? = null

    @Volatile
    private var isRunning = false
    private var lastBlockedIps = setOf<String>()
    private var localDnsServer: VyronLocalDnsServer? = null
    private var dnsExecutor: ExecutorService? = null
    private val outWriteLock = Any()

    private val policyUpdateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.vyron.ACTION_POLICY_UPDATED") {
                lastBlockedIps = policyStore.getBlockedIps()
                localDnsServer?.clearCache()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        policyStore = PolicyStore(this)
        val filter = IntentFilter("com.vyron.ACTION_POLICY_UPDATED")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(policyUpdateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(policyUpdateReceiver, filter)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "ACTION_STOP") {
            policyStore.autoStartVpn = false
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
                "VYRON On-Phone Default DNS",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "On-device DNS filtering for all browsers and apps"
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
                .setContentTitle("VYRON Default DNS Active")
                .setContentText("On-device DNS protection across all browsers (online & offline)")
                .setSmallIcon(android.R.drawable.ic_secure)
                .setContentIntent(pendingIntent)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("VYRON Default DNS Active")
                .setContentText("On-device DNS protection across all browsers")
                .setSmallIcon(android.R.drawable.ic_secure)
                .setContentIntent(pendingIntent)
                .build()
        }

        startForeground(1001, notification)
    }

    private fun startVpn() {
        if (isRunning) return
        isRunning = true
        policyStore.autoStartVpn = true

        val blockedIps = policyStore.getBlockedIps()
        lastBlockedIps = blockedIps

        val builder = Builder().apply {
            setSession("VYRON Default DNS")

            // 1. IPv4 Virtual TUN & Virtual DNS
            addAddress("10.0.0.1", 32)
            addDnsServer("10.0.0.2")
            addRoute("10.0.0.2", 32)

            // 2. IPv6 Virtual TUN & Virtual DNS (closes carrier/router IPv6 DNS bypasses)
            try {
                addAddress("fd00::1", 128)
                addDnsServer("fd00::2")
                addRoute("fd00::2", 128)
            } catch (_: Exception) {
            }

            // 3. Route active Wi-Fi / Cellular DNS servers (IPv4 & IPv6) into TUN
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                val activeNet = cm?.activeNetwork
                val linkProps = cm?.getLinkProperties(activeNet)
                linkProps?.dnsServers?.forEach { inetAddr ->
                    val ip = inetAddr.hostAddress ?: return@forEach
                    if (ip != "127.0.0.1" && ip != "::1" && ip != "10.0.0.1" && ip != "fd00::1") {
                        try {
                            val cleanIp = ip.substringBefore('%')
                            val prefix = if (cleanIp.contains(':')) 128 else 32
                            addRoute(cleanIp, prefix)
                        } catch (_: Exception) {
                        }
                    }
                }
            } catch (_: Exception) {
            }

            // 4. Route standard public DNS/DoH/DoT IPs into TUN to prevent browser bypasses
            val publicIpv4Dns = listOf(
                "8.8.8.8", "8.8.4.4",
                "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "149.112.112.112",
                "208.67.222.222", "208.67.220.220",
                "94.140.14.14", "94.140.15.15"
            )
            for (dnsIp in publicIpv4Dns) {
                try {
                    addRoute(dnsIp, 32)
                } catch (_: Exception) {
                }
            }

            val publicIpv6Dns = listOf(
                "2001:4860:4860::8888", "2001:4860:4860::8844",
                "2606:4700:4700::1111", "2606:4700:4700::1001",
                "2620:fe::fe", "2620:fe::9",
                "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"
            )
            for (dnsIp6 in publicIpv6Dns) {
                try {
                    addRoute(dnsIp6, 128)
                } catch (_: Exception) {
                }
            }

            // 5. Route explicitly blocked IPv4/IPv6 targets into TUN so direct IP access drops
            for (ip in blockedIps) {
                try {
                    val prefix = if (ip.contains(':')) 128 else 32
                    addRoute(ip, prefix)
                } catch (_: Exception) {
                }
            }

            // 6. Exclude VYRON app itself so background sync to Render never loops
            try {
                addDisallowedApplication(packageName)
            } catch (_: Exception) {
            }
        }

        try {
            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                isServiceRunning = false
                stopVpn()
                return
            }
            isServiceRunning = true
        } catch (e: Exception) {
            e.printStackTrace()
            isServiceRunning = false
            stopVpn()
            return
        }

        localDnsServer = VyronLocalDnsServer(this, policyStore).apply {
            start(1053)
        }
        dnsExecutor = Executors.newFixedThreadPool(8)

        thread(name = "VyronVpnPacketThread") {
            runPacketLoop()
        }

        thread(name = "VyronVpnSyncThread") {
            runSyncLoop()
        }
    }

    private fun runPacketLoop() {
        val pfd = vpnInterface ?: return
        val inStream = FileInputStream(pfd.fileDescriptor)
        val outStream = FileOutputStream(pfd.fileDescriptor)
        val packet = ByteBuffer.allocate(32767)

        while (isRunning) {
            try {
                packet.clear()
                val length = inStream.read(packet.array())
                if (length <= 0) continue

                val firstByte = packet.get(0).toInt()
                val version = (firstByte shr 4) and 0x0F

                if (version == 4 && length >= 28) {
                    val headerLength = (firstByte and 0x0F) * 4
                    if (headerLength < 20 || length < headerLength) continue
                    val protocol = packet.get(9).toInt() and 0xFF

                    val destIp = String.format(
                        "%d.%d.%d.%d",
                        packet.get(16).toInt() and 0xFF,
                        packet.get(17).toInt() and 0xFF,
                        packet.get(18).toInt() and 0xFF,
                        packet.get(19).toInt() and 0xFF
                    )

                    if (lastBlockedIps.contains(destIp)) {
                        VyronPolicySyncManager.queueLog("ip", destIp, "BLOCKED", "Matched direct blocked IP ($destIp)")
                        continue
                    }

                    if (protocol == 17 && length > headerLength + 8) {
                        val udpDestPort = ((packet.get(headerLength + 2).toInt() and 0xFF) shl 8) or
                            (packet.get(headerLength + 3).toInt() and 0xFF)
                        if (udpDestPort == 53) {
                            val rawCopy = ByteArray(length)
                            System.arraycopy(packet.array(), 0, rawCopy, 0, length)
                            dispatchDnsPacket(rawCopy, headerLength, isIpv6 = false, outStream = outStream)
                        }
                    }
                    // Non-port-53 packets routed into TUN (e.g. DoT 853 or DoH 443 to 8.8.8.8/1.1.1.1) are dropped cleanly
                } else if (version == 6 && length >= 48) {
                    val nextHeader = packet.get(6).toInt() and 0xFF
                    if (nextHeader == 17 && length > 48) {
                        val udpDestPort = ((packet.get(42).toInt() and 0xFF) shl 8) or
                            (packet.get(43).toInt() and 0xFF)
                        if (udpDestPort == 53) {
                            val rawCopy = ByteArray(length)
                            System.arraycopy(packet.array(), 0, rawCopy, 0, length)
                            dispatchDnsPacket(rawCopy, 40, isIpv6 = true, outStream = outStream)
                        }
                    }
                }
            } catch (_: Exception) {
                if (!isRunning) break
            }
        }
    }

    private fun dispatchDnsPacket(
        origPacket: ByteArray,
        ipHeaderLen: Int,
        isIpv6: Boolean,
        outStream: FileOutputStream
    ) {
        val dnsOffset = ipHeaderLen + 8
        val dnsLen = origPacket.size - dnsOffset
        if (dnsLen < 12) return

        val dnsData = ByteArray(dnsLen)
        System.arraycopy(origPacket, dnsOffset, dnsData, 0, dnsLen)

        val exec = dnsExecutor ?: return
        val dnsEngine = localDnsServer ?: return

        exec.execute {
            if (!isRunning) return@execute
            val dnsResp = dnsEngine.resolveDnsQuery(dnsData) { sock ->
                protect(sock)
            } ?: return@execute

            val replyPacket = if (isIpv6) {
                DnsPacketUtil.buildReplyIpv6UdpPacket(origPacket, ipHeaderLen, dnsResp)
            } else {
                DnsPacketUtil.buildReplyIpv4UdpPacket(origPacket, ipHeaderLen, dnsResp)
            }

            synchronized(outWriteLock) {
                if (isRunning) {
                    try {
                        outStream.write(replyPacket)
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }

    private fun runSyncLoop() {
        while (isRunning) {
            try {
                VyronPolicySyncManager.performSyncBlocking(this)
            } catch (_: Exception) {
            }

            try {
                Thread.sleep(30000)
            } catch (_: InterruptedException) {
                break
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        isServiceRunning = false
        try {
            unregisterReceiver(policyUpdateReceiver)
        } catch (_: Exception) {
        }
        try {
            dnsExecutor?.shutdownNow()
        } catch (_: Exception) {
        }
        dnsExecutor = null

        try {
            localDnsServer?.stop()
        } catch (_: Exception) {
        }
        localDnsServer = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
