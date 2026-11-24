package com.vyron.networkcontrol

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.Calendar

data class AppPolicyItem(
    val packageName: String,
    val appName: String,
    val policyMode: String, // ALLOW, BLOCK, SCHEDULE, DAILY_LIMIT
    val scheduleStart: String?, // HH:MM
    val scheduleEnd: String?,   // HH:MM
    val dailyLimitMinutes: Int?,
    val isActive: Boolean
)

data class ActiveWaiverItem(
    val targetType: String, // app, domain, ip
    val target: String,
    val expiresAtEpochMs: Long
)

class PolicyStore(private val context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences("vyron_policy_store", Context.MODE_PRIVATE)

    var serverUrl: String
        get() = prefs.getString("server_url", "https://vyron-sbkd.onrender.com") ?: "https://vyron-sbkd.onrender.com"
        set(value) = prefs.edit().putString("server_url", value).apply()

    var deviceToken: String
        get() = prefs.getString("device_token", "") ?: ""
        set(value) = prefs.edit().putString("device_token", value).apply()

    var guidedMode: Boolean
        get() = prefs.getBoolean("guided_mode", true)
        set(value) = prefs.edit().putBoolean("guided_mode", value).apply()

    var uninstallAllowed: Boolean
        get() = prefs.getBoolean("uninstall_allowed", false)
        set(value) = prefs.edit().putBoolean("uninstall_allowed", value).apply()

    var lastSyncEpochMs: Long
        get() = prefs.getLong("last_sync_epoch_ms", 0L)
        set(value) = prefs.edit().putLong("last_sync_epoch_ms", value).apply()

    var autoStartVpn: Boolean
        get() = prefs.getBoolean("auto_start_vpn", false)
        set(value) = prefs.edit().putBoolean("auto_start_vpn", value).apply()

    fun saveCredentials(url: String, token: String) {
        prefs.edit()
            .putString("server_url", url)
            .putString("device_token", token)
            .apply()
    }

    companion object {
        @Volatile
        private var memRawJson: String? = null
        @Volatile
        private var memBlockedDomains: Set<String> = emptySet()
        @Volatile
        private var memAllowedDomains: Set<String> = emptySet()
        @Volatile
        private var memBlockedIps: Set<String> = emptySet()
        @Volatile
        private var memAppPolicies: List<AppPolicyItem> = emptyList()
        @Volatile
        private var memActiveWaivers: List<ActiveWaiverItem> = emptyList()

        /**
         * Safely extracts a host candidate (e.g. "www.instagram.com") from a browser URL bar string.
         * Returns null for search queries, incomplete words without dots, or empty strings.
         */
        fun extractDomainFromBrowserText(rawText: String?): String? {
            if (rawText.isNullOrBlank()) return null
            val cleaned = rawText.trim().lowercase()
            if (cleaned.startsWith("about:") || cleaned.startsWith("chrome:") ||
                cleaned.startsWith("file:") || cleaned.startsWith("data:") ||
                cleaned.startsWith("javascript:")
            ) {
                return null
            }
            val noScheme = cleaned.removePrefix("https://").removePrefix("http://")
            val authority = noScheme
                .substringBefore('/')
                .substringBefore('?')
                .substringBefore('#')
                .substringBefore(':')
                .substringAfter('@')
                .trimEnd('.')

            if (authority.length < 3 || authority.length > 253 || !authority.contains('.')) return null
            if (authority.startsWith('.') || authority.contains("..")) return null
            for (ch in authority) {
                val ok = (ch in 'a'..'z') || (ch in '0'..'9') || ch == '-' || ch == '.'
                if (!ok) return null
            }
            return authority
        }
    }

    private fun ensureMemLoaded() {
        val raw = prefs.getString("cached_policy_json", null) ?: return
        if (raw == memRawJson) return
        synchronized(PolicyStore::class.java) {
            if (raw == memRawJson) return
            try {
                val root = JSONObject(raw)

                val appsList = mutableListOf<AppPolicyItem>()
                val appArr = root.optJSONArray("app_policies")
                if (appArr != null) {
                    for (i in 0 until appArr.length()) {
                        val obj = appArr.getJSONObject(i)
                        appsList.add(
                            AppPolicyItem(
                                packageName = obj.optString("package_name").lowercase(),
                                appName = obj.optString("app_name"),
                                policyMode = obj.optString("policy_mode", "ALLOW"),
                                scheduleStart = if (obj.has("schedule_start") && !obj.isNull("schedule_start")) obj.getString("schedule_start") else null,
                                scheduleEnd = if (obj.has("schedule_end") && !obj.isNull("schedule_end")) obj.getString("schedule_end") else null,
                                dailyLimitMinutes = if (obj.has("daily_limit_minutes") && !obj.isNull("daily_limit_minutes")) obj.getInt("daily_limit_minutes") else null,
                                isActive = obj.optBoolean("is_active", true)
                            )
                        )
                    }
                }

                val bDomains = mutableSetOf<String>()
                val aDomains = mutableSetOf<String>()
                val bIps = mutableSetOf<String>()
                val net = root.optJSONObject("network_rules")
                if (net != null) {
                    net.optJSONArray("blocked_domains")?.let { arr ->
                        for (i in 0 until arr.length()) bDomains.add(arr.getString(i).lowercase())
                    }
                    net.optJSONArray("allowed_domains")?.let { arr ->
                        for (i in 0 until arr.length()) aDomains.add(arr.getString(i).lowercase())
                    }
                    net.optJSONArray("blocked_ips")?.let { arr ->
                        for (i in 0 until arr.length()) bIps.add(arr.getString(i))
                    }
                }

                val waivers = mutableListOf<ActiveWaiverItem>()
                val wArr = root.optJSONArray("active_waivers")
                if (wArr != null) {
                    for (i in 0 until wArr.length()) {
                        val obj = wArr.getJSONObject(i)
                        waivers.add(
                            ActiveWaiverItem(
                                targetType = obj.optString("target_type", "app").lowercase(),
                                target = obj.optString("target").lowercase(),
                                expiresAtEpochMs = obj.optLong("expires_at_epoch_ms", 0L)
                            )
                        )
                    }
                }

                memAppPolicies = appsList
                memBlockedDomains = bDomains
                memAllowedDomains = aDomains
                memBlockedIps = bIps
                memActiveWaivers = waivers
                memRawJson = raw
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    fun saveFullPolicyJson(jsonStr: String) {
        try {
            val root = JSONObject(jsonStr)
            guidedMode = root.optBoolean("guided_mode", true)
            uninstallAllowed = root.optBoolean("uninstall_allowed", false)
            lastSyncEpochMs = System.currentTimeMillis()

            prefs.edit().putString("cached_policy_json", jsonStr).apply()
            ensureMemLoaded()

            // Broadcast policy update so VpnService, LocalDns, and AppGuard reload immediately
            val intent = Intent("com.vyron.ACTION_POLICY_UPDATED").apply {
                setPackage(context.packageName)
            }
            context.sendBroadcast(intent)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getAppPolicies(): List<AppPolicyItem> {
        ensureMemLoaded()
        return memAppPolicies
    }

    fun getBlockedDomains(): Set<String> {
        ensureMemLoaded()
        return memBlockedDomains
    }

    fun getAllowedDomains(): Set<String> {
        ensureMemLoaded()
        return memAllowedDomains
    }

    fun getBlockedIps(): Set<String> {
        ensureMemLoaded()
        return memBlockedIps
    }

    fun getActiveWaivers(): List<ActiveWaiverItem> {
        ensureMemLoaded()
        return memActiveWaivers
    }

    /**
     * Checks locally cached domain policy including emergency waivers (0ms offline-capable).
     */
    fun isDomainBlockedWithWaiver(domain: String): Boolean {
        val norm = domain.lowercase().trim('.')
        if (norm.isEmpty()) return false

        val nowUtc = System.currentTimeMillis()
        for (w in getActiveWaivers()) {
            if (w.targetType == "domain") {
                val wt = w.target.lowercase().trim('.')
                if (norm == wt || norm.endsWith(".$wt")) {
                    if (w.expiresAtEpochMs > nowUtc) {
                        return false
                    }
                }
            }
        }

        return DnsPacketUtil.isDomainBlocked(norm, getBlockedDomains(), getAllowedDomains())
    }

    /**
     * Evaluates whether an app is blocked, scheduled, or limited.
     * Returns: Pair<isBlocked: Boolean, reason: String>
     */
    fun evaluateApp(packageName: String, usedMinutesToday: Int): Pair<Boolean, String> {
        val pkg = packageName.lowercase()
        val nowUtc = System.currentTimeMillis()

        // 1. Check emergency waivers first (Overrides all limits!)
        for (w in getActiveWaivers()) {
            if (w.targetType == "app" && w.target == pkg && w.expiresAtEpochMs > nowUtc) {
                return Pair(false, "Active Emergency Waiver granted")
            }
        }

        // 2. Check policy
        val policy = getAppPolicies().firstOrNull { it.packageName == pkg } ?: return Pair(false, "Allowed")
        if (!policy.isActive) return Pair(false, "Policy paused")

        when (policy.policyMode) {
            "BLOCK" -> {
                return Pair(true, "Restricted by supervisor policy (Full Block)")
            }
            "SCHEDULE" -> {
                val start = policy.scheduleStart
                val end = policy.scheduleEnd
                if (start != null && end != null && isCurrentTimeInWindow(start, end)) {
                    return Pair(true, "Blocked by quiet hours schedule ($start – $end)")
                }
            }
            "DAILY_LIMIT" -> {
                val limit = policy.dailyLimitMinutes ?: 0
                if (limit > 0 && usedMinutesToday >= limit) {
                    return Pair(true, "Daily usage quota reached (${usedMinutesToday}m / ${limit}m limit)")
                }
            }
        }

        return Pair(false, "Allowed")
    }

    private fun isCurrentTimeInWindow(startStr: String, endStr: String): Boolean {
        try {
            val cal = Calendar.getInstance()
            val hour = cal.get(Calendar.HOUR_OF_DAY)
            val minute = cal.get(Calendar.MINUTE)
            val currentVal = hour * 100 + minute

            val startParts = startStr.split(":")
            val startVal = startParts[0].toInt() * 100 + startParts[1].toInt()

            val endParts = endStr.split(":")
            val endVal = endParts[0].toInt() * 100 + endParts[1].toInt()

            return if (startVal == endVal) {
                true
            } else if (startVal < endVal) {
                currentVal in startVal until endVal
            } else {
                // Overnight window
                currentVal >= startVal || currentVal < endVal
            }
        } catch (e: Exception) {
            return false
        }
    }
}
