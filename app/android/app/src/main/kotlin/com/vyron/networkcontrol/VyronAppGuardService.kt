package com.vyron.networkcontrol

import android.accessibilityservice.AccessibilityService
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import java.util.Calendar

/**
 * Event-Driven Zero-Icon App & Browser Guard.
 * Runs natively inside Android Accessibility without showing any VPN key icon:
 * - Enforces app blocks, schedules, and daily quotas from local PolicyStore
 * - Inspects address bars of popular Android browsers (Chrome, Brave, Edge, Firefox,
 *   Samsung Internet, Opera, DuckDuckGo, etc.) to block restricted domains locally
 */
class VyronAppGuardService : AccessibilityService() {

    companion object {
        private val BROWSER_URL_IDS: Map<String, List<String>> = mapOf(
            "com.android.chrome" to listOf("com.android.chrome:id/url_bar"),
            "com.chrome.beta" to listOf("com.chrome.beta:id/url_bar"),
            "com.chrome.dev" to listOf("com.chrome.dev:id/url_bar"),
            "com.chrome.canary" to listOf("com.chrome.canary:id/url_bar"),
            "com.brave.browser" to listOf("com.brave.browser:id/url_bar"),
            "com.microsoft.emmx" to listOf("com.microsoft.emmx:id/url_bar"),
            "com.kiwibrowser.browser" to listOf("com.kiwibrowser.browser:id/url_bar"),
            "com.vivaldi.browser" to listOf("com.vivaldi.browser:id/url_bar"),
            "com.sec.android.app.sbrowser" to listOf("com.sec.android.app.sbrowser:id/location_bar_edit_text"),
            "com.sec.android.app.sbrowser.beta" to listOf("com.sec.android.app.sbrowser.beta:id/location_bar_edit_text"),
            "org.mozilla.firefox" to listOf(
                "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
                "org.mozilla.firefox:id/url_bar_title"
            ),
            "org.mozilla.firefox_beta" to listOf("org.mozilla.firefox_beta:id/mozac_browser_toolbar_url_view"),
            "org.mozilla.fenix" to listOf("org.mozilla.fenix:id/mozac_browser_toolbar_url_view"),
            "com.opera.browser" to listOf("com.opera.browser:id/url_field"),
            "com.opera.mini.native" to listOf("com.opera.mini.native:id/url_field"),
            "com.opera.gx" to listOf("com.opera.gx:id/url_field"),
            "com.duckduckgo.mobile.android" to listOf("com.duckduckgo.mobile.android:id/omnibarTextInput"),
            "com.mi.globalbrowser" to listOf("com.mi.globalbrowser:id/url", "com.mi.globalbrowser:id/address_bar"),
            "com.heytap.browser" to listOf("com.heytap.browser:id/url", "com.heytap.browser:id/address_bar"),
            "com.coloros.browser" to listOf("com.coloros.browser:id/url", "com.coloros.browser:id/address_bar"),
            "com.vivo.browser" to listOf("com.vivo.browser:id/url", "com.vivo.browser:id/address_bar")
        )
    }

    private lateinit var policyStore: PolicyStore
    private var lastCheckedPackage: String = ""
    private var lastCheckTimeMs: Long = 0
    private var lastBrowserScanMs: Long = 0
    private var lastBlockedDomain: String = ""
    private var lastDomainBlockMs: Long = 0

    private val syncHandler = Handler(Looper.getMainLooper())
    private val periodicSyncRunnable = object : Runnable {
        override fun run() {
            VyronPolicySyncManager.syncIfDueAsync(applicationContext, 45000L)
            syncHandler.postDelayed(this, 45000L)
        }
    }

    override fun onCreate() {
        super.onCreate()
        policyStore = PolicyStore(this)
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        syncHandler.removeCallbacks(periodicSyncRunnable)
        VyronPolicySyncManager.syncNowAsync(applicationContext)
        syncHandler.postDelayed(periodicSyncRunnable, 45000L)
    }

    override fun onDestroy() {
        syncHandler.removeCallbacks(periodicSyncRunnable)
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val evtType = event.eventType
        val pkgName = event.packageName?.toString()?.lowercase() ?: return

        // Ignore VYRON itself, launcher, keyboard, and system UI
        if (pkgName == packageName ||
            pkgName.contains("launcher") ||
            pkgName.contains("systemui") ||
            pkgName.contains("inputmethod") ||
            pkgName == "android"
        ) {
            return
        }

        val now = System.currentTimeMillis()

        if (evtType == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {
            // Skip all non-browser window content churn in <1 microsecond for zero battery drain
            val viewIds = BROWSER_URL_IDS[pkgName] ?: return
            if (now - lastBrowserScanMs < 400L) return
            lastBrowserScanMs = now
            inspectBrowserUrl(pkgName, viewIds, now)
            return
        }

        if (evtType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return

        // Throttle rapid consecutive state events for the same package
        if (pkgName == lastCheckedPackage && (now - lastCheckTimeMs) < 600L) {
            BROWSER_URL_IDS[pkgName]?.let { inspectBrowserUrl(pkgName, it, now) }
            return
        }
        lastCheckedPackage = pkgName
        lastCheckTimeMs = now

        // Gentle background policy pull if due (never blocks event thread)
        VyronPolicySyncManager.syncIfDueAsync(applicationContext, 45000L)

        // 1. Evaluate app lock / schedule / daily limit
        val usedMinutes = getAppUsageToday(pkgName)
        val (isBlocked, reason) = policyStore.evaluateApp(pkgName, usedMinutes)
        if (isBlocked) {
            VyronPolicySyncManager.queueLog("app", pkgName, "BLOCKED", reason)
            launchBlockScreen("app", pkgName, resolveAppLabel(pkgName), reason)
            return
        }

        // 2. If foreground package is a monitored browser, also inspect loaded URL
        BROWSER_URL_IDS[pkgName]?.let { viewIds ->
            lastBrowserScanMs = now
            inspectBrowserUrl(pkgName, viewIds, now)
        }
    }

    private fun inspectBrowserUrl(browserPkg: String, viewIds: List<String>, now: Long) {
        val root: AccessibilityNodeInfo = rootInActiveWindow ?: return
        for (viewId in viewIds) {
            val nodes = root.findAccessibilityNodeInfosByViewId(viewId)
            if (nodes.isNullOrEmpty()) continue

            for (node in nodes) {
                // Skip while user is mid-typing inside the address bar
                if (node.isFocused) continue
                val urlText = node.text?.toString() ?: continue
                val host = PolicyStore.extractDomainFromBrowserText(urlText) ?: continue

                if (policyStore.isDomainBlockedWithWaiver(host)) {
                    if (host == lastBlockedDomain && (now - lastDomainBlockMs) < 1500L) {
                        return
                    }
                    lastBlockedDomain = host
                    lastDomainBlockMs = now

                    VyronPolicySyncManager.queueLog(
                        "domain",
                        host,
                        "BLOCKED",
                        "Blocked in ${resolveAppLabel(browserPkg)} via Zero-Icon Guard ($host)"
                    )
                    // Navigate back off the restricted page, then show VYRON overlay
                    performGlobalAction(GLOBAL_ACTION_BACK)
                    launchBlockScreen(
                        targetType = "domain",
                        target = host,
                        displayName = host,
                        reason = "Website $host is restricted by supervisor policy"
                    )
                    return
                }
            }
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
            val statsList = usageManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                cal.timeInMillis,
                System.currentTimeMillis()
            )
            val appStat = statsList.firstOrNull { it.packageName.equals(targetPkg, ignoreCase = true) }
            return if (appStat != null) {
                (appStat.totalTimeInForeground / 60000).toInt()
            } else {
                0
            }
        } catch (_: Exception) {
            return 0
        }
    }

    private fun resolveAppLabel(pkgName: String): String {
        return try {
            val info = packageManager.getApplicationInfo(pkgName, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (_: Exception) {
            pkgName
        }
    }

    private fun launchBlockScreen(
        targetType: String,
        target: String,
        displayName: String,
        reason: String
    ) {
        val intent = Intent(this, BlockedOverlayActivity::class.java).apply {
            putExtra("EXTRA_TARGET_TYPE", targetType)
            putExtra("EXTRA_PACKAGE_NAME", target)
            putExtra("EXTRA_APP_NAME", displayName)
            putExtra("EXTRA_REASON", reason)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        startActivity(intent)
    }

    override fun onInterrupt() {
        // Accessibility service interrupted
    }
}
