package com.vyron.networkcontrol

import android.app.usage.UsageStatsManager
import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.Calendar
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Background control-plane synchronization manager.
 * Fetches added/removed rules from the remote server only on a gentle schedule
 * with generous Render cold-start timeouts (45s), never delaying local DNS or UI.
 */
object VyronPolicySyncManager {

    private val isSyncing = AtomicBoolean(false)
    private val pendingLogs = Collections.synchronizedList(mutableListOf<JSONObject>())

    @Volatile
    private var lastAttemptMs: Long = 0L

    fun queueLog(eventType: String, target: String, status: String, reason: String) {
        if (pendingLogs.size > 200) return
        val obj = JSONObject().apply {
            put("event_type", eventType)
            put("target", target)
            put("status", status)
            put("reason", reason)
        }
        pendingLogs.add(obj)
    }

    fun syncIfDueAsync(context: Context, minIntervalMs: Long = 30000L) {
        val now = System.currentTimeMillis()
        if (now - lastAttemptMs < minIntervalMs) return
        syncNowAsync(context)
    }

    fun syncNowAsync(context: Context) {
        if (!isSyncing.compareAndSet(false, true)) return
        val appCtx = context.applicationContext
        lastAttemptMs = System.currentTimeMillis()

        thread(name = "VyronBackgroundSync") {
            try {
                performSyncBlocking(appCtx)
            } finally {
                isSyncing.set(false)
            }
        }
    }

    fun performSyncBlocking(context: Context) {
        val store = PolicyStore(context)
        val serverUrl = store.serverUrl.trimEnd('/')
        val token = store.deviceToken
        if (token.isEmpty()) return

        // 1. Pull updated rules (long timeout accommodates sleeping cloud instances)
        var conn: HttpURLConnection? = null
        try {
            val url = URL("$serverUrl/api/device/policy")
            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("X-VYRON-TOKEN", token)
                connectTimeout = 45000
                readTimeout = 45000
            }
            if (conn.responseCode == 200) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                store.saveFullPolicyJson(body)
            }
        } catch (_: Exception) {
            // Offline or server sleeping; locally cached PolicyStore rules keep enforcing seamlessly.
        } finally {
            conn?.disconnect()
        }

        // 2. Upload daily foreground app usage
        var usageConn: HttpURLConnection? = null
        try {
            val usageList = collectTodayUsage(context)
            if (usageList.length() > 0) {
                val url = URL("$serverUrl/api/device/usage")
                usageConn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("X-VYRON-TOKEN", token)
                    doOutput = true
                    connectTimeout = 30000
                    readTimeout = 30000
                }
                val payload = JSONObject().apply { put("usage", usageList) }
                OutputStreamWriter(usageConn.outputStream).use { it.write(payload.toString()) }
                usageConn.responseCode
            }
        } catch (_: Exception) {
        } finally {
            usageConn?.disconnect()
        }

        // 3. Flush batched block telemetry logs
        flushLogs(serverUrl, token)
    }

    private fun flushLogs(serverUrl: String, token: String) {
        if (pendingLogs.isEmpty()) return
        val toSend = ArrayList<JSONObject>()
        synchronized(pendingLogs) {
            toSend.addAll(pendingLogs)
            pendingLogs.clear()
        }
        if (toSend.isEmpty()) return

        var logConn: HttpURLConnection? = null
        try {
            val url = URL("$serverUrl/api/device/logs")
            logConn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("X-VYRON-TOKEN", token)
                doOutput = true
                connectTimeout = 30000
                readTimeout = 30000
            }
            val payload = JSONObject().apply {
                val arr = JSONArray()
                toSend.forEach { arr.put(it) }
                put("logs", arr)
            }
            OutputStreamWriter(logConn.outputStream).use { it.write(payload.toString()) }
            if (logConn.responseCode !in 200..299) {
                pendingLogs.addAll(toSend)
            }
        } catch (_: Exception) {
            if (pendingLogs.size < 200) {
                pendingLogs.addAll(toSend)
            }
        } finally {
            logConn?.disconnect()
        }
    }

    private fun collectTodayUsage(context: Context): JSONArray {
        val arr = JSONArray()
        try {
            val usageManager = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return arr
            val cal = Calendar.getInstance().apply {
                set(Calendar.HOUR_OF_DAY, 0)
                set(Calendar.MINUTE, 0)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }
            val statsList = usageManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                cal.timeInMillis,
                System.currentTimeMillis()
            )
            for (stat in statsList) {
                val mins = (stat.totalTimeInForeground / 60000).toInt()
                if (mins > 0) {
                    arr.put(JSONObject().apply {
                        put("package_name", stat.packageName.lowercase())
                        put("minutes_used", mins)
                    })
                }
            }
        } catch (_: Exception) {
        }
        return arr
    }
}
