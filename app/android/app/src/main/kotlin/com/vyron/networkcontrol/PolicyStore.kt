package com.vyron.networkcontrol

import android.content.Context
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

class PolicyStore(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences("vyron_policy_store", Context.MODE_PRIVATE)

    var serverUrl: String
        get() = prefs.getString("server_url", "http://10.0.2.2:5000") ?: "http://10.0.2.2:5000"
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

    fun saveFullPolicyJson(jsonStr: String) {
        try {
            val root = JSONObject(jsonStr)
            guidedMode = root.optBoolean("guided_mode", true)
            uninstallAllowed = root.optBoolean("uninstall_allowed", false)

            prefs.edit().putString("cached_policy_json", jsonStr).apply()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getAppPolicies(): List<AppPolicyItem> {
        val list = mutableListOf<AppPolicyItem>()
        val raw = prefs.getString("cached_policy_json", null) ?: return list
        try {
            val root = JSONObject(raw)
            val arr = root.optJSONArray("app_policies") ?: return list
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                list.add(
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
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
    }

    fun getBlockedDomains(): Set<String> {
        val set = mutableSetOf<String>()
        val raw = prefs.getString("cached_policy_json", null) ?: return set
        try {
            val root = JSONObject(raw)
            val net = root.optJSONObject("network_rules") ?: return set
            val arr = net.optJSONArray("blocked_domains") ?: return set
            for (i in 0 until arr.length()) {
                set.add(arr.getString(i).lowercase())
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return set
    }

    fun getAllowedDomains(): Set<String> {
        val set = mutableSetOf<String>()
        val raw = prefs.getString("cached_policy_json", null) ?: return set
        try {
            val root = JSONObject(raw)
            val net = root.optJSONObject("network_rules") ?: return set
            val arr = net.optJSONArray("allowed_domains") ?: return set
            for (i in 0 until arr.length()) {
                set.add(arr.getString(i).lowercase())
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return set
    }

    fun getBlockedIps(): Set<String> {
        val set = mutableSetOf<String>()
        val raw = prefs.getString("cached_policy_json", null) ?: return set
        try {
            val root = JSONObject(raw)
            val net = root.optJSONObject("network_rules") ?: return set
            val arr = net.optJSONArray("blocked_ips") ?: return set
            for (i in 0 until arr.length()) {
                set.add(arr.getString(i))
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return set
    }

    fun getActiveWaivers(): List<ActiveWaiverItem> {
        val list = mutableListOf<ActiveWaiverItem>()
        val raw = prefs.getString("cached_policy_json", null) ?: return list
        try {
            val root = JSONObject(raw)
            val arr = root.optJSONArray("active_waivers") ?: return list
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                list.add(
                    ActiveWaiverItem(
                        targetType = obj.optString("target_type", "app").lowercase(),
                        target = obj.optString("target").lowercase(),
                        expiresAtEpochMs = obj.optLong("expires_at_epoch_ms", 0L)
                    )
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return list
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
