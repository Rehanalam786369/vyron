package com.vyron.networkcontrol

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.app.usage.UsageStatsManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Process
import android.provider.Settings
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.util.Calendar

class MainActivity : FlutterActivity() {

    private val CHANNEL = "com.vyron.networkcontrol/engine"
    private var pendingVpnResult: MethodChannel.Result? = null
    private val VPN_REQUEST_CODE = 1002
    private lateinit var policyStore: PolicyStore

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        policyStore = PolicyStore(this)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "getInstalledApps" -> {
                    try {
                        val apps = getLaunchableApps()
                        result.success(apps)
                    } catch (e: Exception) {
                        result.error("APPS_ERROR", e.message, null)
                    }
                }

                "syncPolicyToNative" -> {
                    val json = call.argument<String>("policyJson") ?: ""
                    val serverUrl = call.argument<String>("serverUrl")
                    val deviceToken = call.argument<String>("deviceToken")

                    if (!serverUrl.isNullOrEmpty() && !deviceToken.isNullOrEmpty()) {
                        policyStore.saveCredentials(serverUrl, deviceToken)
                    }
                    policyStore.saveFullPolicyJson(json)
                    result.success(true)
                }

                "startProtection" -> {
                    val prepareIntent = VpnService.prepare(this)
                    if (prepareIntent != null) {
                        pendingVpnResult = result
                        startActivityForResult(prepareIntent, VPN_REQUEST_CODE)
                    } else {
                        startVpnService()
                        result.success(true)
                    }
                }

                "stopProtection" -> {
                    val stopIntent = Intent(this, VyronVpnService::class.java).apply {
                        action = "ACTION_STOP"
                    }
                    startService(stopIntent)
                    result.success(true)
                }

                "getPermissionStatus" -> {
                    val status = mapOf(
                        "vpnConsent" to (VpnService.prepare(this) == null),
                        "isProtectionRunning" to VyronVpnService.isServiceRunning,
                        "isDefaultBrowser" to isDefaultBrowser(),
                        "usageAccess" to hasUsageStatsPermission(),
                        "overlay" to (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Settings.canDrawOverlays(this) else true),
                        "accessibility" to isAccessibilityServiceEnabled(),
                        "deviceAdmin" to isDeviceAdminActive(),
                        "uninstallAllowed" to policyStore.uninstallAllowed
                    )
                    result.success(status)
                }

                "openPermissionSettings" -> {
                    val type = call.argument<String>("type") ?: ""
                    openSettingsFor(type)
                    result.success(true)
                }

                "requestDeviceAdmin" -> {
                    requestDeviceAdminActivation()
                    result.success(true)
                }

                "deactivateAdminAndUninstall" -> {
                    if (policyStore.uninstallAllowed) {
                        try {
                            val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                            val comp = ComponentName(this, VyronDeviceAdminReceiver::class.java)
                            dpm.removeActiveAdmin(comp)

                            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                                data = Uri.parse("package:$packageName")
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            startActivity(uninstallIntent)
                            result.success(true)
                        } catch (e: Exception) {
                            result.error("UNINSTALL_ERROR", e.message, null)
                        }
                    } else {
                        result.error("PERMISSION_DENIED", "Supervisor approval required from the VYRON Control Panel.", null)
                    }
                }

                "getTodayUsageStats" -> {
                    val stats = getTodayUsageMap()
                    result.success(stats)
                }

                "testDnsResolution" -> {
                    val domain = call.argument<String>("domain") ?: "instagram.com"
                    kotlin.concurrent.thread {
                        try {
                            val addrs = java.net.InetAddress.getAllByName(domain)
                            val ipList = addrs.map { it.hostAddress ?: "" }
                            runOnUiThread {
                                result.success(ipList)
                            }
                        } catch (e: Exception) {
                            runOnUiThread {
                                result.success(listOf("BLOCKED (Unresolved / ${e.message})"))
                            }
                        }
                    }
                }

                "openWifiSettings" -> {
                    try {
                        val intent = Intent(Settings.ACTION_WIFI_SETTINGS).apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        try {
                            val intent = Intent(Settings.ACTION_WIRELESS_SETTINGS).apply {
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            startActivity(intent)
                            result.success(true)
                        } catch (e2: Exception) {
                            result.error("SETTINGS_ERROR", e2.message, null)
                        }
                    }
                }

                "openPrivateDnsSettings" -> {
                    try {
                        val intent = Intent(Settings.ACTION_WIRELESS_SETTINGS).apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        try {
                            val intent = Intent(Settings.ACTION_SETTINGS).apply {
                                flags = Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            startActivity(intent)
                            result.success(true)
                        } catch (e2: Exception) {
                            result.error("SETTINGS_ERROR", e2.message, null)
                        }
                    }
                }

                "openSafeBrowser" -> {
                    val url = call.argument<String>("url") ?: "https://www.google.com"
                    val browserIntent = Intent(this, VyronBrowserActivity::class.java).apply {
                        data = Uri.parse(url)
                    }
                    startActivity(browserIntent)
                    result.success(true)
                }

                "openDefaultAppsSettings" -> {
                    try {
                        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
                        } else {
                            Intent(Settings.ACTION_SETTINGS)
                        }.apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        startActivity(Intent(Settings.ACTION_SETTINGS).apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK })
                        result.success(true)
                    }
                }

                "openVpnSettings" -> {
                    try {
                        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            Intent(Settings.ACTION_VPN_SETTINGS)
                        } else {
                            Intent(Settings.ACTION_WIRELESS_SETTINGS)
                        }.apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        startActivity(Intent(Settings.ACTION_SETTINGS).apply { flags = Intent.FLAG_ACTIVITY_NEW_TASK })
                        result.success(true)
                    }
                }

                else -> result.notImplemented()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::policyStore.isInitialized) {
            VyronPolicySyncManager.syncIfDueAsync(this, 15000L)
        }
    }

    private fun isDefaultBrowser(): Boolean {
        return try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com"))
            val ri = packageManager.resolveActivity(intent, android.content.pm.PackageManager.MATCH_DEFAULT_ONLY)
            ri?.activityInfo?.packageName == packageName
        } catch (_: Exception) {
            false
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, VyronVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                startVpnService()
                pendingVpnResult?.success(true)
            } else {
                pendingVpnResult?.error("VPN_DENIED", "User declined VPN permission", null)
            }
            pendingVpnResult = null
        }
    }

    private fun getLaunchableApps(): List<Map<String, Any>> {
        val list = mutableListOf<Map<String, Any>>()
        val pm = packageManager
        val intent = Intent(Intent.ACTION_MAIN, null).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }

        val resolveInfos = pm.queryIntentActivities(intent, 0)
        for (info in resolveInfos) {
            val pkg = info.activityInfo.packageName
            val label = info.loadLabel(pm).toString()
            val isSystem = (info.activityInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            list.add(
                mapOf(
                    "packageName" to pkg,
                    "appName" to label,
                    "isSystemApp" to isSystem
                )
            )
        }
        return list.sortedBy { it["appName"] as String }
    }

    private fun hasUsageStatsPermission(): Boolean {
        val appOps = getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?: return false
        return enabledServices.contains("VyronAppGuardService")
    }

    private fun isDeviceAdminActive(): Boolean {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager ?: return false
        val comp = ComponentName(this, VyronDeviceAdminReceiver::class.java)
        return dpm.isAdminActive(comp)
    }

    private fun openSettingsFor(type: String) {
        when (type) {
            "usage" -> {
                val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivity(intent)
            }
            "overlay" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                    startActivity(intent)
                }
            }
            "accessibility" -> {
                val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivity(intent)
            }
            "admin" -> {
                requestDeviceAdminActivation()
            }
        }
    }

    private fun requestDeviceAdminActivation() {
        val comp = ComponentName(this, VyronDeviceAdminReceiver::class.java)
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, comp)
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Protects VYRON against unauthorized tampering or uninstallation.")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(intent)
    }

    private fun getTodayUsageMap(): Map<String, Int> {
        val map = mutableMapOf<String, Int>()
        try {
            val usageManager = getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return map
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
                    map[stat.packageName.lowercase()] = mins
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return map
    }
}
