package com.vyron.networkcontrol

import android.content.Context
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread

/**
 * Embedded in-app DNS Server.
 * Runs on port 1053 (and attempts port 53).
 * Intercepts DNS queries locally and answers with 0.0.0.0 for blocked domains.
 */
class VyronLocalDnsServer(private val context: Context, private val policyStore: PolicyStore) {

    private var isRunning = false
    private var socket: DatagramSocket? = null
    private var listenPort = 1053

    fun start(customPort: Int = 1053) {
        if (isRunning) return
        isRunning = true

        thread(name = "VyronLocalDnsThread") {
            try {
                // Try preferred port first, fall back to 1053 or ephemeral
                socket = try {
                    DatagramSocket(customPort)
                } catch (e: Exception) {
                    DatagramSocket(1053)
                }
                listenPort = socket?.localPort ?: 1053

                val buffer = ByteArray(2048)
                val upstreamDns = InetAddress.getByName("1.1.1.1")
                val upstreamSocket = DatagramSocket()
                upstreamSocket.soTimeout = 3000

                while (isRunning) {
                    try {
                        val requestPacket = DatagramPacket(buffer, buffer.size)
                        socket?.receive(requestPacket)

                        val queryData = ByteArray(requestPacket.length)
                        System.arraycopy(requestPacket.data, 0, queryData, 0, requestPacket.length)

                        val query = DnsPacketUtil.parseQuery(queryData)
                        if (query != null) {
                            val blocked = policyStore.getBlockedDomains()
                            val allowed = policyStore.getAllowedDomains()

                            val isBlocked = DnsPacketUtil.isDomainBlocked(query.domain, blocked, allowed)

                            if (isBlocked) {
                                val blockedResponse = DnsPacketUtil.craftBlockedResponse(queryData)
                                val replyPacket = DatagramPacket(
                                    blockedResponse,
                                    blockedResponse.size,
                                    requestPacket.address,
                                    requestPacket.port
                                )
                                socket?.send(replyPacket)
                            } else {
                                // Forward to upstream DNS
                                try {
                                    val sendUpstream = DatagramPacket(
                                        queryData,
                                        queryData.size,
                                        upstreamDns,
                                        53
                                    )
                                    upstreamSocket.send(sendUpstream)

                                    val respBuf = ByteArray(2048)
                                    val recvUpstream = DatagramPacket(respBuf, respBuf.size)
                                    upstreamSocket.receive(recvUpstream)

                                    val replyPacket = DatagramPacket(
                                        recvUpstream.data,
                                        recvUpstream.length,
                                        requestPacket.address,
                                        requestPacket.port
                                    )
                                    socket?.send(replyPacket)
                                } catch (e: Exception) {
                                    // Upstream timeout
                                }
                            }
                        }
                    } catch (e: Exception) {
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
        try {
            socket?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        socket = null
    }

    fun getPort(): Int = listenPort
    fun isRunning(): Boolean = isRunning
}
