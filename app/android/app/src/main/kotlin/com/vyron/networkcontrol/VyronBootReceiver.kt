package com.vyron.networkcontrol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

/**
 * Restores background policy sync and on-phone DNS protection after device reboot.
 */
class VyronBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED || action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            VyronPolicySyncManager.syncNowAsync(context)

            val store = PolicyStore(context)
            if (store.autoStartVpn && VpnService.prepare(context) == null && !VyronVpnService.isServiceRunning) {
                try {
                    val vpnIntent = Intent(context, VyronVpnService::class.java)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(vpnIntent)
                    } else {
                        context.startService(vpnIntent)
                    }
                } catch (_: Exception) {
                    // Android 12+ may restrict background FGS start; Always-On VPN handles it natively if enabled
                }
            }
        }
    }
}
