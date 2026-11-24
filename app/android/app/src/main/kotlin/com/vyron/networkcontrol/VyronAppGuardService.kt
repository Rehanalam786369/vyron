package com.vyron.networkcontrol

import android.accessibilityservice.AccessibilityService
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.view.accessibility.AccessibilityEvent
import java.util.Calendar

class VyronAppGuardService : AccessibilityService() {

    private lateinit var policyStore: PolicyStore
    private var lastCheckedPackage: String = ""
    private var lastCheckTimeMs: Long = 0

    override fun onCreate() {
        super.onCreate()
        policyStore = PolicyStore(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || event.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            return
        }

        val pkgName = event.packageName?.toString() ?: return

        // Throttle rapid consecutive events for the same package
        val now = System.currentTimeMillis()
        if (pkgName == lastCheckedPackage && (now - lastCheckTimeMs) < 600) {
            return
        }
        lastCheckedPackage = pkgName
        lastCheckTimeMs = now

        // Ignore VYRON itself, launcher, keyboard, and system UI
        if (pkgName == packageName ||
            pkgName.contains("launcher") ||
            pkgName.contains("systemui") ||
            pkgName.contains("inputmethod") ||
            pkgName == "android"
        ) {
            return
        }

        // Query today's usage for this app
        val usedMinutes = getAppUsageToday(pkgName)

        val (isBlocked, reason) = policyStore.evaluateApp(pkgName, usedMinutes)
        if (isBlocked) {
            launchBlockScreen(pkgName, reason)
        }
    }

    private fun getAppUsageToday(targetPkg: String): Int {
        try {
            val usageManager = getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return 0
            val cal = Calendar.getInstance().apply {
                set(Calendar.HOUR_OF_DAY, 0)
                set(Calendar.MINUTE, 0)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }
            val startOfDay = cal.timeInMillis
            val endOfDay = System.currentTimeMillis()

            val statsList = usageManager.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, startOfDay, endOfDay)
            val appStat = statsList.firstOrNull { it.packageName == targetPkg }
            return if (appStat != null) {
                (appStat.totalTimeInForeground / 60000).toInt()
            } else {
                0
            }
        } catch (e: Exception) {
            return 0
        }
    }

    private fun launchBlockScreen(pkgName: String, reason: String) {
        val appName = try {
            val pm = packageManager
            val info = pm.getApplicationInfo(pkgName, 0)
            pm.getApplicationLabel(info).toString()
        } catch (e: Exception) {
            pkgName
        }

        val intent = Intent(this, BlockedOverlayActivity::class.java).apply {
            putExtra("EXTRA_PACKAGE_NAME", pkgName)
            putExtra("EXTRA_APP_NAME", appName)
            putExtra("EXTRA_REASON", reason)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        startActivity(intent)
    }

    override fun onInterrupt() {
        // Accessibility service interrupted
    }
}
