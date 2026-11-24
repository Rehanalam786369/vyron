import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/native_bridge.dart';
import 'pairing_screen.dart';

class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key});

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  Map<String, bool> _permissions = {};
  Map<String, dynamic> _policy = {};
  Map<String, int> _usage = {};
  bool _isLoading = false;
  bool _isProtectionRunning = false;
  final _testDomainController = TextEditingController(text: 'instagram.com');
  String? _dnsTestResult;
  bool _isTestingDns = false;

  @override
  void dispose() {
    _testDomainController.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    _refreshAll();
  }

  Future<void> _refreshAll() async {
    setState(() => _isLoading = true);
    await _checkPermissions();
    await _fetchPolicyAndUsage();
    if (mounted) {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _checkPermissions() async {
    final perms = await NativeBridge.getPermissionStatus();
    if (!mounted) return;
    setState(() {
      _permissions = perms;
      _isProtectionRunning = perms['isProtectionRunning'] == true;
    });
  }

  Future<void> _fetchPolicyAndUsage() async {
    // 1. Load locally cached policy immediately (0ms, works offline & when server is slow)
    final cachedPol = await ApiService.getCachedPolicy();
    final usageStats = await NativeBridge.getTodayUsageStats();
    if (cachedPol.isNotEmpty && mounted) {
      setState(() {
        _policy = cachedPol;
        _usage = usageStats;
      });
    }

    // 2. Fetch fresh rules from remote control panel quietly in background
    try {
      final pol = await ApiService.fetchPolicy();
      final serverUrl = await ApiService.getServerUrl();
      final token = await ApiService.getDeviceToken();
      await NativeBridge.syncPolicyToNative(pol, serverUrl: serverUrl, deviceToken: token);

      if (!mounted) return;
      setState(() {
        _policy = pol;
        _usage = usageStats;
      });
    } catch (_) {
      // Offline or slow server wake-up; cached policy stays enforced locally!
    }
  }

  Future<void> _toggleProtection() async {
    if (_isProtectionRunning) {
      await NativeBridge.stopProtection();
      setState(() => _isProtectionRunning = false);
      _showSnackbar('On-Phone Default DNS paused. Default Browser & App Guard remain active.');
    } else {
      try {
        final success = await NativeBridge.startProtection();
        if (success) {
          setState(() => _isProtectionRunning = true);
          _showSnackbar('On-Phone Default DNS Engine activated for ALL browsers & apps!');
        }
      } catch (e) {
        _showSnackbar('Could not start on-phone DNS engine: $e', isError: true);
      }
    }
  }

  Future<void> _resyncApps() async {
    setState(() => _isLoading = true);
    try {
      final apps = await NativeBridge.getInstalledApps();
      final count = await ApiService.syncInstalledApps(apps);
      _showSnackbar('Synchronized $count installed apps with supervisor!');
      await _fetchPolicyAndUsage();
    } catch (e) {
      _showSnackbar('App sync failed: $e', isError: true);
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _handleEmergencyWaiver(String pkg, String name) async {
    final reasonController = TextEditingController();
    final shouldRequest = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF0F172A),
        title: Text('Request 10m Waiver: $name', style: const TextStyle(color: Colors.white, fontSize: 16)),
        content: TextField(
          controller: reasonController,
          style: const TextStyle(color: Colors.white),
          decoration: const InputDecoration(
            hintText: 'Reason for supervisor (e.g. Need study notes)...',
            hintStyle: TextStyle(color: Color(0xFF64748B)),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel', style: TextStyle(color: Color(0xFF94A3B8))),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF7E22CE)),
            child: const Text('Send Request', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (shouldRequest == true) {
      try {
        final rawReason = reasonController.text.trim();
        final reason = rawReason.isEmpty ? 'Emergency access needed' : rawReason;
        await ApiService.requestEmergencyWaiver(
          targetType: 'app',
          target: pkg,
          displayName: name,
          durationMinutes: 10,
          reason: reason,
        );
        _showSnackbar('Waiver request sent to parent. Waiting for approval!');
      } catch (e) {
        _showSnackbar('Waiver request failed: $e', isError: true);
      }
    }
  }

  Future<void> _handleUninstall() async {
    try {
      final latest = await ApiService.fetchPolicy();
      final allowed = latest['uninstall_allowed'] == true;

      if (!allowed) {
        if (!mounted) return;
        showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            backgroundColor: const Color(0xFF0F172A),
            title: const Text('Supervisor Approval Required', style: TextStyle(color: Color(0xFFFB7185), fontSize: 16)),
            content: const Text(
              'Uninstall protection is active.\n\nAsk your parent/supervisor to open the VYRON Control Panel and click "Unlock Uninstall (10m)".',
              style: TextStyle(color: Color(0xFFCBD5E1), fontSize: 13),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Understood', style: TextStyle(color: Color(0xFF38BDF8))),
              )
            ],
          ),
        );
      } else {
        await NativeBridge.deactivateAdminAndUninstall();
      }
    } catch (e) {
      _showSnackbar('Could not verify uninstall permission: $e', isError: true);
    }
  }

  Future<void> _handleDisconnect() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF0F172A),
        title: const Text('Unpair This Phone?', style: TextStyle(color: Colors.white, fontSize: 16)),
        content: const Text('This will disconnect this device from your supervisor account.', style: TextStyle(color: Color(0xFF94A3B8))),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFE11D48)),
            child: const Text('Unpair', style: TextStyle(color: Colors.white)),
          )
        ],
      ),
    );

    if (confirm == true) {
      await NativeBridge.stopProtection();
      await ApiService.clearAuth();
      if (!mounted) return;
      Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => const PairingScreen()));
    }
  }

  void _showSnackbar(String msg, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: isError ? const Color(0xFFE11D48) : const Color(0xFF059669),
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  Future<void> _testDns(String domain) async {
    final clean = domain.trim().toLowerCase();
    if (clean.isEmpty) return;
    setState(() {
      _isTestingDns = true;
      _dnsTestResult = 'Resolving $clean...';
    });
    final ips = await NativeBridge.testDnsResolution(clean);
    setState(() {
      _isTestingDns = false;
      if (ips.isEmpty) {
        _dnsTestResult = 'BLOCKED (NXDOMAIN / No IP)';
      } else if (ips.any((ip) => ip == '0.0.0.0' || ip.contains('BLOCKED'))) {
        _dnsTestResult = '0.0.0.0 — BLOCKED by VYRON Shield';
      } else {
        _dnsTestResult = 'ALLOWED — ${ips.join(', ')}';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final appPolicies = (_policy['app_policies'] as List<dynamic>?) ?? [];
    final activeWaivers = (_policy['active_waivers'] as List<dynamic>?) ?? [];
    final netRules = (_policy['network_rules'] as Map<String, dynamic>?) ?? {};
    final blockedDomains = (netRules['blocked_domains'] as List<dynamic>?) ?? [];
    final blockedIps = (netRules['blocked_ips'] as List<dynamic>?) ?? [];

    return Scaffold(
      backgroundColor: const Color(0xFF070A12),
      appBar: AppBar(
        backgroundColor: const Color(0xFF0A0E1A),
        elevation: 0,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: const Color(0xFF06B6D4),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Text('V', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800, color: Colors.white)),
            ),
            const SizedBox(width: 10),
            const Text('VYRON SHIELD', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800, letterSpacing: 1.2)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.sync, color: Color(0xFF38BDF8)),
            onPressed: _refreshAll,
            tooltip: 'Sync with server',
          ),
          IconButton(
            icon: const Icon(Icons.logout, color: Color(0xFF94A3B8)),
            onPressed: _handleDisconnect,
            tooltip: 'Unpair device',
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _refreshAll,
        color: const Color(0xFF06B6D4),
        child: SingleChildScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // CARD 1 (PRIMARY): ZERO-ICON COMFORT GUARD (APP LOCKS + CHROME/BROWSER URL GUARD)
              Container(
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: (_permissions['accessibility'] == true)
                        ? [const Color(0xFF064E3B), const Color(0xFF0F172A)]
                        : [const Color(0xFF4C1D95), const Color(0xFF0F172A)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: (_permissions['accessibility'] == true)
                        ? const Color(0xFF10B981)
                        : const Color(0xFFA855F7),
                  ),
                  boxShadow: [
                    BoxShadow(color: Colors.black.withAlpha(120), blurRadius: 15)
                  ],
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Icon(
                              Icons.verified_user,
                              size: 20,
                              color: (_permissions['accessibility'] == true)
                                  ? const Color(0xFF34D399)
                                  : const Color(0xFFC084FC),
                            ),
                            const SizedBox(width: 8),
                            const Text(
                              'ZERO-ICON GUARD',
                              style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.white, letterSpacing: 1),
                            ),
                          ],
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: (_permissions['accessibility'] == true)
                                ? const Color(0x3310B981)
                                : const Color(0x33F59E0B),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            (_permissions['accessibility'] == true) ? 'NO VPN ICON • ACTIVE' : 'SETUP REQUIRED',
                            style: TextStyle(
                              fontSize: 9,
                              fontWeight: FontWeight.w800,
                              color: (_permissions['accessibility'] == true)
                                  ? const Color(0xFF34D399)
                                  : const Color(0xFFFBBF24),
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Blocks restricted apps AND restricted websites inside Chrome, Brave, Edge, Firefox, Samsung Internet, Opera & VYRON Browser cleanly—with ZERO status bar icons, ZERO offline popups, and 0ms local lookup.',
                      style: TextStyle(fontSize: 12, color: Color(0xFFE2E8F0), height: 1.4),
                    ),
                    const SizedBox(height: 12),
                    if (_permissions['accessibility'] != true) ...[
                      ElevatedButton.icon(
                        icon: const Icon(Icons.security, size: 16),
                        label: const Text('Enable Zero-Icon Guard (1-Tap)', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                        onPressed: () => NativeBridge.openPermissionSettings('accessibility'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF7E22CE),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 14),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                      ),
                    ] else ...[
                      Row(
                        children: [
                          Expanded(
                            child: ElevatedButton.icon(
                              icon: const Icon(Icons.open_in_browser, size: 15),
                              label: const Text('VYRON Browser', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold)),
                              onPressed: () => NativeBridge.openSafeBrowser(),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF059669),
                                foregroundColor: Colors.white,
                                padding: const EdgeInsets.symmetric(vertical: 11),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: OutlinedButton.icon(
                              icon: const Icon(Icons.settings_applications, size: 15, color: Color(0xFF34D399)),
                              label: Text(
                                _permissions['isDefaultBrowser'] == true ? 'Default Set ✓' : 'Set Default Browser',
                                style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold),
                              ),
                              onPressed: NativeBridge.openDefaultAppsSettings,
                              style: OutlinedButton.styleFrom(
                                side: const BorderSide(color: Color(0xFF10B981)),
                                padding: const EdgeInsets.symmetric(vertical: 11),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 16),

              // CARD 2 (OPTIONAL FALLBACK): ON-DEVICE PACKET DNS ENGINE (VPN)
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: _isProtectionRunning ? const Color(0xFF38BDF8) : const Color(0xFF334155),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Row(
                          children: [
                            Icon(Icons.dns, size: 18, color: Color(0xFF38BDF8)),
                            SizedBox(width: 8),
                            Text(
                              'DEEP DNS SHIELD (OPTIONAL VPN)',
                              style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.white, letterSpacing: 0.8),
                            ),
                          ],
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                          decoration: BoxDecoration(
                            color: _isProtectionRunning ? const Color(0x3338BDF8) : const Color(0x3364748B),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            _isProtectionRunning ? 'ACTIVE' : 'OFF (NO ICON)',
                            style: TextStyle(
                              fontSize: 9,
                              fontWeight: FontWeight.bold,
                              color: _isProtectionRunning ? const Color(0xFF38BDF8) : const Color(0xFF34D399),
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Optional full-device packet DNS filter for background non-browser apps (uses local cache, online & offline). Note: Android OS displays a status-bar key icon whenever active.',
                      style: TextStyle(fontSize: 11, color: Color(0xFF94A3B8), height: 1.35),
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: ElevatedButton.icon(
                            icon: Icon(_isProtectionRunning ? Icons.pause_circle : Icons.shield_outlined, size: 15),
                            label: Text(
                              _isProtectionRunning ? 'Turn Off VPN (Hide Icon)' : 'Turn On Deep DNS VPN',
                              style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                            ),
                            onPressed: _toggleProtection,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: _isProtectionRunning ? const Color(0xFF991B1B) : const Color(0xFF1E293B),
                              foregroundColor: Colors.white,
                              side: BorderSide(color: _isProtectionRunning ? const Color(0xFFEF4444) : const Color(0xFF475569)),
                              padding: const EdgeInsets.symmetric(vertical: 10),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        OutlinedButton.icon(
                          icon: const Icon(Icons.lock_clock, size: 14, color: Color(0xFF94A3B8)),
                          label: const Text('Always-On', style: TextStyle(color: Colors.white, fontSize: 11)),
                          onPressed: NativeBridge.openVpnSettings,
                          style: OutlinedButton.styleFrom(
                            side: const BorderSide(color: Color(0xFF334155)),
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 20),

              // System Setup Checklist
              const Text(
                'DEVICE GOVERNANCE SERVICES',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF94A3B8), letterSpacing: 1),
              ),
              const SizedBox(height: 8),

              _buildPermCard('Accessibility Guard (App Locks)', _permissions['accessibility'] == true, () => NativeBridge.openPermissionSettings('accessibility')),
              _buildPermCard('Usage Access (App Quotas)', _permissions['usageAccess'] == true, () => NativeBridge.openPermissionSettings('usage')),
              _buildPermCard('Device Admin (Uninstall Lock)', _permissions['deviceAdmin'] == true, () => NativeBridge.requestDeviceAdmin()),

              const SizedBox(height: 20),

              // Actions Row
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      icon: const Icon(Icons.apps, size: 16, color: Color(0xFF38BDF8)),
                      label: const Text('Re-sync Apps', style: TextStyle(color: Colors.white, fontSize: 12)),
                      onPressed: _isLoading ? null : _resyncApps,
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: Color(0xFF334155)),
                        padding: const EdgeInsets.symmetric(vertical: 12),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: OutlinedButton.icon(
                      icon: const Icon(Icons.refresh, size: 16, color: Color(0xFF38BDF8)),
                      label: const Text('Check Policy', style: TextStyle(color: Colors.white, fontSize: 12)),
                      onPressed: _refreshAll,
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: Color(0xFF334155)),
                        padding: const EdgeInsets.symmetric(vertical: 12),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // DNS Shield & Domain Blocking Status Card
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0x660284C7)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Row(
                          children: [
                            Icon(Icons.dns, size: 18, color: Color(0xFF38BDF8)),
                            SizedBox(width: 8),
                            Text(
                              'DNS DOMAIN SHIELD',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.bold,
                                color: Colors.white,
                                letterSpacing: 1,
                              ),
                            ),
                          ],
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: const Color(0x4D0369A1),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            '${blockedDomains.length} DOMAINS${blockedIps.isNotEmpty ? ', ${blockedIps.length} IPS' : ''} BLOCKED',
                            style: const TextStyle(
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                              color: Color(0xFF38BDF8),
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    if (blockedDomains.isEmpty)
                      const Text(
                        'No domains currently blocked. Add block rules in the VYRON Control Panel.',
                        style: TextStyle(color: Color(0xFF64748B), fontSize: 12),
                      )
                    else
                      Wrap(
                        spacing: 6,
                        runSpacing: 6,
                        children: blockedDomains.map((d) {
                          return Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: const Color(0x804C0519),
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: const Color(0x80E11D48)),
                            ),
                            child: Text(
                              d.toString(),
                              style: const TextStyle(
                                fontSize: 11,
                                color: Color(0xFFFB7185),
                                fontFamily: 'monospace',
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          );
                        }).toList(),
                      ),
                    const SizedBox(height: 14),
                    const Divider(color: Color(0xFF1E293B)),
                    const SizedBox(height: 8),

                    // Live DNS Test Tool
                    const Text(
                      'TEST DNS RESOLUTION (VERIFY ZERO-LEAK BLOCK):',
                      style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF94A3B8)),
                    ),
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: _testDomainController,
                            style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'),
                            decoration: InputDecoration(
                              hintText: 'e.g. instagram.com',
                              hintStyle: const TextStyle(color: Color(0xFF475569)),
                              filled: true,
                              fillColor: const Color(0xFF070A12),
                              contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(8),
                                borderSide: const BorderSide(color: Color(0xFF334155)),
                              ),
                              enabledBorder: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(8),
                                borderSide: const BorderSide(color: Color(0xFF334155)),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        ElevatedButton(
                          onPressed: _isTestingDns ? null : () => _testDns(_testDomainController.text),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: const Color(0xFF0284C7),
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          ),
                          child: _isTestingDns
                              ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                              : const Text('Test Block', style: TextStyle(color: Colors.white, fontSize: 12)),
                        ),
                      ],
                    ),
                    if (_dnsTestResult != null) ...[
                      const SizedBox(height: 8),
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: _dnsTestResult!.contains('BLOCKED')
                              ? const Color(0x4D065F46)
                              : const Color(0x4D4C0519),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: _dnsTestResult!.contains('BLOCKED') ? const Color(0xFF059669) : const Color(0xFFE11D48),
                          ),
                        ),
                        child: Text(
                          _dnsTestResult!,
                          style: TextStyle(
                            fontSize: 11,
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.bold,
                            color: _dnsTestResult!.contains('BLOCKED') ? const Color(0xFF34D399) : const Color(0xFFFB7185),
                          ),
                        ),
                      ),
                    ],

                    const SizedBox(height: 12),
                    // Android Private DNS Notice & Shortcut
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFF0B1329),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: const Color(0xFF1E293B)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Row(
                            children: [
                              Icon(Icons.info_outline, size: 14, color: Color(0xFFF59E0B)),
                              SizedBox(width: 6),
                              Text(
                                'Android "Private DNS" Notice',
                                style: TextStyle(color: Color(0xFFF59E0B), fontSize: 11, fontWeight: FontWeight.bold),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          const Text(
                            'If Android OS Private DNS is active with a third-party DoT provider, Android bypasses local DNS filters. Set Private DNS to "Off" (or Automatic) for 100% enforcement.',
                            style: TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
                          ),
                          const SizedBox(height: 6),
                          InkWell(
                            onTap: () => NativeBridge.openPrivateDnsSettings(),
                            child: const Text(
                              'Open Network / Private DNS Settings →',
                              style: TextStyle(color: Color(0xFF38BDF8), fontSize: 11, fontWeight: FontWeight.bold),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Active App Governance Policies (Transparent list for user)
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text(
                    'GOVERNED APPLICATIONS',
                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF94A3B8), letterSpacing: 1),
                  ),
                  Text('${appPolicies.length} POLICIES', style: const TextStyle(fontSize: 11, color: Color(0xFF38BDF8), fontFamily: 'monospace')),
                ],
              ),
              const SizedBox(height: 8),

              if (appPolicies.isEmpty)
                Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(color: const Color(0xFF0F172A), borderRadius: BorderRadius.circular(12)),
                  child: const Center(
                    child: Text('No active restrictions configured on this device.', style: TextStyle(color: Color(0xFF64748B), fontSize: 13)),
                  ),
                )
              else
                ...appPolicies.map((p) {
                  final pkg = (p['package_name'] as String? ?? '').toLowerCase();
                  final rawName = p['app_name'] as String? ?? '';
                  final name = rawName.trim().isEmpty ? pkg : rawName;
                  final mode = (p['policy_mode'] as String? ?? 'ALLOW');
                  final usedMins = _usage[pkg] ?? 0;
                  final limitMins = (p['daily_limit_minutes'] as num?)?.toInt() ?? 0;

                  String modeText = mode;
                  Color modeColor = const Color(0xFF94A3B8);

                  if (mode == 'BLOCK') {
                    modeText = 'Restricted 24/7';
                    modeColor = const Color(0xFFFB7185);
                  } else if (mode == 'SCHEDULE') {
                    modeText = 'Quiet Hours: ${p['schedule_start']} – ${p['schedule_end']}';
                    modeColor = const Color(0xFFC084FC);
                  } else if (mode == 'DAILY_LIMIT') {
                    modeText = '$usedMins mins used / $limitMins min limit';
                    modeColor = usedMins >= limitMins ? const Color(0xFFFB7185) : const Color(0xFF38BDF8);
                  }

                  // Check if currently waived
                  final isWaived = activeWaivers.any((w) => w['target_type'] == 'app' && w['target'] == pkg);

                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0F172A),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: const Color(0xFF1E293B)),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(name, style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 14)),
                              const SizedBox(height: 2),
                              Text(modeText, style: TextStyle(color: modeColor, fontSize: 12, fontFamily: 'monospace')),
                            ],
                          ),
                        ),
                        if (isWaived)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(color: const Color(0xFF065F46), borderRadius: BorderRadius.circular(6)),
                            child: const Text('WAIVED', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF34D399))),
                          )
                        else if (mode != 'ALLOW')
                          TextButton(
                            onPressed: () => _handleEmergencyWaiver(pkg, name),
                            child: const Text('10m Waiver', style: TextStyle(color: Color(0xFFC084FC), fontSize: 12, fontWeight: FontWeight.bold)),
                          ),
                      ],
                    ),
                  );
                }),

              const SizedBox(height: 32),

              // Uninstall Section
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF0B1120),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0xFF1E293B)),
                ),
                child: Column(
                  children: [
                    const Text(
                      'UNINSTALLATION GOVERNANCE',
                      style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 1),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Uninstalling requires parental permission on the VYRON Control Panel.',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontSize: 11, color: Color(0xFF94A3B8)),
                    ),
                    const SizedBox(height: 12),
                    ElevatedButton(
                      onPressed: _handleUninstall,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF1E293B),
                        foregroundColor: const Color(0xFFFB7185),
                      ),
                      child: const Text('Uninstall VYRON Client', style: TextStyle(fontSize: 12)),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPermCard(String title, bool isGranted, VoidCallback onEnable) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: const Color(0xFF0F172A),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF1E293B)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Icon(
                isGranted ? Icons.check_circle : Icons.warning_amber_rounded,
                size: 16,
                color: isGranted ? const Color(0xFF10B981) : const Color(0xFFF59E0B),
              ),
              const SizedBox(width: 10),
              Text(title, style: const TextStyle(color: Colors.white, fontSize: 13)),
            ],
          ),
          if (!isGranted)
            TextButton(
              onPressed: onEnable,
              style: TextButton.styleFrom(padding: EdgeInsets.zero, minimumSize: const Size(50, 30)),
              child: const Text('Enable', style: TextStyle(color: Color(0xFF38BDF8), fontSize: 12, fontWeight: FontWeight.bold)),
            )
          else
            const Text('Active', style: TextStyle(color: Color(0xFF10B981), fontSize: 12, fontWeight: FontWeight.bold)),
        ],
      ),
    );
  }
}
