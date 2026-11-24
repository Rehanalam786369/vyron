import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class ApiService {
  static const String keyServerUrl = 'vyron_server_url';
  static const String keyDeviceToken = 'vyron_device_token';
  static const String keyDeviceId = 'vyron_device_id';
  static const String keyDeviceName = 'vyron_device_name';

  static String defaultServerUrl = 'https://vyron-sbkd.onrender.com';

  // Load configured server URL
  static Future<String> getServerUrl() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(keyServerUrl) ?? defaultServerUrl;
  }

  // Save server URL
  static Future<void> setServerUrl(String url) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(keyServerUrl, url.trim().replaceAll(RegExp(r'/+$'), ''));
  }

  // Get saved device token
  static Future<String?> getDeviceToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(keyDeviceToken);
  }

  // Check if paired
  static Future<bool> isPaired() async {
    final token = await getDeviceToken();
    return token != null && token.isNotEmpty;
  }

  // Clear credentials
  static Future<void> clearAuth() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(keyDeviceToken);
    await prefs.remove(keyDeviceId);
    await prefs.remove(keyDeviceName);
  }

  // 1. Pair Device using Pairing Key
  static Future<Map<String, dynamic>> pairDevice({
    required String serverUrl,
    required String pairingKey,
    required String deviceModel,
  }) async {
    await setServerUrl(serverUrl);
    final cleanUrl = await getServerUrl();
    final uri = Uri.parse('$cleanUrl/api/device/pair');

    final response = await http
        .post(
          uri,
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'pairing_key': pairingKey.trim().toUpperCase(),
            'device_model': deviceModel.trim(),
          }),
        )
        .timeout(const Duration(seconds: 10));

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    if (response.statusCode == 200) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(keyDeviceToken, data['device_token'] as String);
      await prefs.setInt(keyDeviceId, data['device_id'] as int);
      await prefs.setString(keyDeviceName, data['device_name'] as String);
      return data;
    } else {
      throw Exception(data['error'] ?? 'Pairing failed (${response.statusCode})');
    }
  }

  // 2. Batch-Sync Installed Apps (100+ apps support)
  static Future<int> syncInstalledApps(List<Map<String, dynamic>> apps) async {
    final cleanUrl = await getServerUrl();
    final token = await getDeviceToken();
    if (token == null) throw Exception('Device not paired');

    final uri = Uri.parse('$cleanUrl/api/device/apps/sync');
    final response = await http
        .post(
          uri,
          headers: {
            'Content-Type': 'application/json',
            'X-VYRON-TOKEN': token,
          },
          body: jsonEncode({'apps': apps}),
        )
        .timeout(const Duration(seconds: 15));

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      return (data['synced_count'] as int?) ?? apps.length;
    } else {
      throw Exception('App sync failed: ${response.body}');
    }
  }

  // 3. Fetch Latest Governance Policy
  static Future<Map<String, dynamic>> fetchPolicy() async {
    final cleanUrl = await getServerUrl();
    final token = await getDeviceToken();
    if (token == null) throw Exception('Device not paired');

    final uri = Uri.parse('$cleanUrl/api/device/policy');
    final response = await http
        .get(
          uri,
          headers: {'X-VYRON-TOKEN': token},
        )
        .timeout(const Duration(seconds: 10));

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Policy fetch failed: ${response.statusCode}');
    }
  }

  // 4. Request Emergency Waiver
  static Future<Map<String, dynamic>> requestEmergencyWaiver({
    required String targetType,
    required String target,
    required String displayName,
    int durationMinutes = 10,
    String reason = 'Emergency access needed',
  }) async {
    final cleanUrl = await getServerUrl();
    final token = await getDeviceToken();
    if (token == null) throw Exception('Device not paired');

    final uri = Uri.parse('$cleanUrl/api/device/waivers/request');
    final response = await http
        .post(
          uri,
          headers: {
            'Content-Type': 'application/json',
            'X-VYRON-TOKEN': token,
          },
          body: jsonEncode({
            'target_type': targetType,
            'target': target,
            'display_name': displayName,
            'duration_minutes': durationMinutes,
            'reason': reason,
          }),
        )
        .timeout(const Duration(seconds: 10));

    if (response.statusCode == 201) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Waiver request failed: ${response.body}');
    }
  }
}
