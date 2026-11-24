package com.vyron.networkcontrol

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * Embedded On-Phone DNS Engine & Local UDP Server (127.0.0.1:1053).
 *
 * - 100% independent of slow cloud control-panel availability during DNS lookups.
 * - Evaluates blocked domains & DoH bypass canaries in-memory in <1ms (online or offline).
 * - Maintains a TTL response cache for fast repeated lookups.
 * - Uses active physical network DNS servers with 1.1.1.1 / 8.8.8.8 fallback.
 */
class VyronLocalDnsServer(private val context: Context, private val policyStore: PolicyStore) {

    private data class CachedDnsReply(
        val rawResponse: ByteArray,
        val expiresAtMs: Long
    )

    @Volatile
    private var isRunning = false
    private var socket: DatagramSocket? = null
    private var listenPort = 1053

    private val responseCache = ConcurrentHashMap<String, CachedDnsReply>()
    private val activePhysicalNetworks = ConcurrentHashMap.newKeySet<Network>()
    private val workerPool: ExecutorService = Executors.newFixedThreadPool(4)

    @Volatile
    private var currentUpstreamDns: List<InetAddress> = defaultPublicDns()

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private fun defaultPublicDns(): List<InetAddress> = listOf(
        InetAddress.getByName("1.1.1.1"),
        InetAddress.getByName("8.8.8.8")
    )

    fun clearCache() {
        responseCache.clear()
    }

    fun startNetworkMonitoring() {
        if (networkCallback != null) return
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            refreshUpstreamDns(cm, cm.activeNetwork)

            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()

            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    activePhysicalNetworks.add(network)
                    refreshUpstreamDns(cm, network)
                }

                override fun onLost(network: Network) {
                    activePhysicalNetworks.remove(network)
                    refreshUpstreamDns(cm, activePhysicalNetworks.firstOrNull())
                }

                override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                    activePhysicalNetworks.add(network)
                    refreshUpstreamDns(cm, network, linkProperties)
                }
            }
            cm.registerNetworkCallback(request, cb)
            networkCallback = cb
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun stopNetworkMonitoring() {
        try {
            networkCallback?.let { cb ->
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                cm?.unregisterNetworkCallback(cb)
            }
        } catch (_: Exception) {
        }
        networkCallback = null
        activePhysicalNetworks.clear()
    }

    private fun refreshUpstreamDns(
        cm: ConnectivityManager,
        network: Network?,
        knownLinkProps: LinkProperties? = null
    ) {
        try {
            val lp = knownLinkProps ?: (network ?: cm.activeNetwork)?.let { cm.getLinkProperties(it) }
            val list = mutableListOf<InetAddress>()
            lp?.dnsServers?.forEach { addr ->
                val host = addr.hostAddress ?: ""
                if (addr is Inet4Address && !addr.isLoopbackAddress &&
                    host != "10.0.0.1" && host != "10.0.0.2"
                ) {
                    list.add(addr)
                }
            }
            for (pub in defaultPublicDns()) {
                if (!list.contains(pub)) list.add(pub)
            }
            currentUpstreamDns = list
        } catch (_: Exception) {
        }
    }

    fun hasLikelyConnectivity(): Boolean {
        if (activePhysicalNetworks.isNotEmpty()) return true
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val net = cm?.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(net) ?: return false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        } catch (_: Exception) {
            true
        }
    }

    /**
     * Resolves a raw DNS UDP query completely on-device first:
     * 1. Browser DoH canary/bypass domains -> NXDOMAIN
     * 2. VYRON policy blocked domains (with active waivers) -> 0.0.0.0 / ::
     * 3. In-memory TTL cache -> cached reply
     * 4. Fast offline check -> SERVFAIL immediately without stalling
     * 5. Parallel protected UDP forward to carrier / 1.1.1.1 / 8.8.8.8
     */
    fun resolveDnsQuery(
        queryData: ByteArray,
        protectSocket: ((DatagramSocket) -> Unit)? = null
    ): ByteArray? {
        val query = DnsPacketUtil.parseQuery(queryData) ?: return null

        // 1. Force all browsers (Chrome, Firefox, Brave, Edge) onto VYRON's local DNS
        if (DnsPacketUtil.isDoHBypassDomain(query.domain)) {
            return DnsPacketUtil.craftNxDomain(queryData)
        }

        // 2. Enforce VYRON domain policy strictly from on-device cache (works online & offline)
        if (policyStore.isDomainBlockedWithWaiver(query.domain)) {
            VyronPolicySyncManager.queueLog(
                "domain",
                query.domain,
                "BLOCKED",
                "Blocked by VYRON On-Device DNS (${query.domain})"
            )
            return DnsPacketUtil.craftBlockedResponse(queryData)
        }

        // 3. Return cached allowed DNS response if still valid
        val cacheKey = "${query.domain}:${query.qType}:${query.qClass}"
        val nowMs = System.currentTimeMillis()
        val cached = responseCache[cacheKey]
        if (cached != null && cached.expiresAtMs > nowMs) {
            return DnsPacketUtil.rewriteTransactionId(cached.rawResponse, queryData[0], queryData[1])
        }

        // 4. Fail immediately if device has no physical network (prevents offline hangs)
        if (!hasLikelyConnectivity()) {
            return DnsPacketUtil.craftServFail(queryData)
        }

        // 5. Forward directly to active carrier/Wi-Fi DNS or 1.1.1.1 / 8.8.8.8 (NEVER hits Render)
        val targets = currentUpstreamDns
        var upstreamSocket: DatagramSocket? = null
        try {
            upstreamSocket = DatagramSocket().apply {
                soTimeout = 1200
            }
            protectSocket?.invoke(upstreamSocket)

            for (upstreamAddr in targets.take(2)) {
                try {
                    val sendPacket = DatagramPacket(queryData, queryData.size, upstreamAddr, 53)
                    upstreamSocket.send(sendPacket)

                    val respBuf = ByteArray(2048)
                    val recvPacket = DatagramPacket(respBuf, respBuf.size)
                    upstreamSocket.receive(recvPacket)

                    val realResp = ByteArray(recvPacket.length)
                    System.arraycopy(recvPacket.data, 0, realResp, 0, recvPacket.length)

                    val ttlSec = DnsPacketUtil.extractCacheTtlSeconds(realResp)
                    if (ttlSec > 0 && responseCache.size < 2000) {
                        responseCache[cacheKey] = CachedDnsReply(
                            rawResponse = realResp,
                            expiresAtMs = nowMs + ttlSec * 1000L
                        )
                    }
                    return realResp
                } catch (_: Exception) {
                    // Immediate failure or timeout; try secondary DNS server
                }
            }
        } catch (_: Exception) {
        } finally {
            try {
                upstreamSocket?.close()
            } catch (_: Exception) {
            }
        }

        return DnsPacketUtil.craftServFail(queryData)
    }

    /**
     * Starts local UDP DNS listener on 127.0.0.1:customPort (default 1053).
     */
    fun start(customPort: Int = 1053) {
        if (isRunning) return
        isRunning = true
        startNetworkMonitoring()

        thread(name = "VyronLocalDnsThread") {
            try {
                socket = try {
                    DatagramSocket(customPort, InetAddress.getByName("127.0.0.1"))
                } catch (_: Exception) {
                    DatagramSocket(1053, InetAddress.getByName("127.0.0.1"))
                }
                listenPort = socket?.localPort ?: 1053

                val buffer = ByteArray(2048)
                while (isRunning) {
                    try {
                        val requestPacket = DatagramPacket(buffer, buffer.size)
                        socket?.receive(requestPacket)

                        val queryData = ByteArray(requestPacket.length)
                        System.arraycopy(requestPacket.data, 0, queryData, 0, requestPacket.length)
                        val clientAddr = requestPacket.address
                        val clientPort = requestPacket.port

                        workerPool.execute {
                            val reply = resolveDnsQuery(queryData)
                            if (reply != null) {
                                try {
                                    val replyPacket = DatagramPacket(reply, reply.size, clientAddr, clientPort)
                                    socket?.send(replyPacket)
                                } catch (_: Exception) {
                                }
                            }
                        }
                    } catch (_: Exception) {
                        if (!isRunning) break
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            } finally {
                stop()
            }
        }
    }

    fun stop() {
        isRunning = false
        stopNetworkMonitoring()
        clearCache()
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        try {
            workerPool.shutdownNow()
        } catch (_: Exception) {
        }
    }

    fun getPort(): Int = listenPort
    fun isRunning(): Boolean = isRunning
}
