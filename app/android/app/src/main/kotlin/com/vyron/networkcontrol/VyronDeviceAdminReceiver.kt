package com.vyron.networkcontrol

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent

class VyronDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        val policyStore = PolicyStore(context)
        return if (policyStore.uninstallAllowed) {
            "Temporary uninstall permission granted by supervisor."
        } else {
            "Disabling or uninstalling VYRON requires supervisor approval from the VYRON Control Panel."
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
    }
}
