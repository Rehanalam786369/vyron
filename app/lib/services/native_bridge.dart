import 'dart:convert';
import 'package:flutter/services.dart';

class NativeBridge {
  static const MethodChannel _channel = MethodChannel('com.vyron.networkcontrol/engine');

  // Query all launchable apps installed on device (100+ apps support)
  static Future<List<Map<String, dynamic>>> getInstalledApps() async {
    try {
      final List<dynamic>? result = await _channel.invokeMethod('getInstalledApps');
      if (result == null) return [];
      return result.map((item) => Map<String, dynamic>.from(item as Map)).toList();
    } on PlatformException catch (e) {
      throw Exception('Failed to get apps: ${e.message}');
    }
  }

  // Pass latest policy json to native Android PolicyStore
  static Future<bool> syncPolicyToNative(Map<String, dynamic> policyMap) async {
    try {
      final String jsonStr = jsonEncode(policyMap);
      final bool? success = await _channel.invokeMethod('syncPolicyToNative', {'policyJson': jsonStr});
      return success ?? false;
    } on PlatformException {
      return false;
    }
  }

  // Start Split-Tunnel VPN service
  static Future<bool> startProtection() async {
    try {
      final bool? success = await _channel.invokeMethod('startProtection');
      return success ?? false;
    } on PlatformException catch (e) {
      throw Exception(e.message ?? 'VPN start failed');
    }
  }

  // Stop Split-Tunnel VPN service
  static Future<bool> stopProtection() async {
    try {
      final bool? success = await _channel.invokeMethod('stopProtection');
      return success ?? false;
    } on PlatformException {
      return false;
    }
  }

  // Check setup permissions: vpnConsent, usageAccess, overlay, accessibility, deviceAdmin, uninstallAllowed
  static Future<Map<String, bool>> getPermissionStatus() async {
    try {
      final Map<dynamic, dynamic>? res = await _channel.invokeMethod('getPermissionStatus');
      if (res == null) return {};
      return res.map((k, v) => MapEntry(k.toString(), v == true));
    } on PlatformException {
      return {};
    }
  }

  // Deep-link to setting screen (usage, overlay, accessibility, admin)
  static Future<void> openPermissionSettings(String type) async {
    try {
      await _channel.invokeMethod('openPermissionSettings', {'type': type});
    } on PlatformException catch (e) {
      throw Exception('Could not open settings: ${e.message}');
    }
  }

  // Request Device Admin activation
  static Future<void> requestDeviceAdmin() async {
    try {
      await _channel.invokeMethod('requestDeviceAdmin');
    } on PlatformException catch (e) {
      throw Exception('Device admin request failed: ${e.message}');
    }
  }

  // Deactivate admin and open uninstall intent (only when uninstallAllowed == true)
  static Future<bool> deactivateAdminAndUninstall() async {
    try {
      final bool? res = await _channel.invokeMethod('deactivateAdminAndUninstall');
      return res ?? false;
    } on PlatformException catch (e) {
      throw Exception(e.message ?? 'Uninstall not permitted');
    }
  }

  // Query today's foreground usage minutes
  static Future<Map<String, int>> getTodayUsageStats() async {
    try {
      final Map<dynamic, dynamic>? res = await _channel.invokeMethod('getTodayUsageStats');
      if (res == null) return {};
      return res.map((k, v) => MapEntry(k.toString(), (v as num).toInt()));
    } on PlatformException {
      return {};
    }
  }
}
