import 'package:flutter/material.dart';
import '../services/api_service.dart';
import '../services/native_bridge.dart';
import 'status_screen.dart';

class PairingScreen extends StatefulWidget {
  const PairingScreen({super.key});

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  final _serverUrlController = TextEditingController(text: 'http://10.0.2.2:5000');
  final _keyController = TextEditingController(text: 'VYR-');
  bool _isLoading = false;
  String? _statusText;

  @override
  void initState() {
    super.initState();
    _loadSavedServer();
  }

  Future<void> _loadSavedServer() async {
    final saved = await ApiService.getServerUrl();
    setState(() {
      _serverUrlController.text = saved;
    });
  }

  Future<void> _handlePairing() async {
    final serverUrl = _serverUrlController.text.trim();
    final key = _keyController.text.trim().toUpperCase();

    if (serverUrl.isEmpty || key.isEmpty) {
      _showSnackbar('Please enter both the server URL and Pairing Key', isError: true);
      return;
    }

    setState(() {
      _isLoading = true;
      _statusText = 'Contacting VYRON Control Panel...';
    });

    try {
      // 1. Pair with Server
      final pairData = await ApiService.pairDevice(
        serverUrl: serverUrl,
        pairingKey: key,
        deviceModel: 'Android Handover Device',
      );

      // 2. Scan installed launchable apps
      setState(() {
        _statusText = 'Scanning installed applications (100+ apps)...';
      });
      final apps = await NativeBridge.getInstalledApps();

      // 3. Upload apps to Control Panel
      setState(() {
        _statusText = 'Synchronizing ${apps.length} apps with server...';
      });
      await ApiService.syncInstalledApps(apps);

      // 4. Fetch initial policy & sync to native Android engine
      setState(() {
        _statusText = 'Enabling zero-lag system governance...';
      });
      final policy = await ApiService.fetchPolicy();
      await NativeBridge.syncPolicyToNative(policy);

      if (!mounted) return;
      _showSnackbar('Device paired successfully as ${pairData['device_name']}!');

      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => const StatusScreen()),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _statusText = null;
      });
      _showSnackbar(e.toString().replaceAll('Exception: ', ''), isError: true);
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF070A12),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 440),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Logo Badge
                  Center(
                    child: Container(
                      width: 64,
                      height: 64,
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [Color(0xFF06B6D4), Color(0xFF6366F1)],
                        ),
                        borderRadius: BorderRadius.circular(16),
                        boxShadow: [
                          BoxShadow(
                            color: const Color(0xFF06B6D4).withAlpha(100),
                            blurRadius: 20,
                          )
                        ],
                      ),
                      child: const Center(
                        child: Text(
                          'V',
                          style: TextStyle(
                            fontSize: 32,
                            fontWeight: FontWeight.w800,
                            color: Colors.white,
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Title
                  const Text(
                    'VYRON',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 28,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 2,
                      color: Colors.white,
                    ),
                  ),
                  const Text(
                    'Beyond Connections. Total Control.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 12,
                      color: Color(0xFF94A3B8),
                      fontFamily: 'monospace',
                    ),
                  ),
                  const SizedBox(height: 32),

                  // Card Box
                  Container(
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0F172A),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: const Color(0xFF38BDF8).withAlpha(70),
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withAlpha(160),
                          blurRadius: 25,
                        )
                      ],
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'DEVICE IDENTITY CARD',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                            color: Color(0xFF38BDF8),
                            letterSpacing: 1.2,
                          ),
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Pair with Supervisor Panel',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 20),

                        // Server URL
                        const Text(
                          'SERVER HOST / URL',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
                            color: Color(0xFF94A3B8),
                          ),
                        ),
                        const SizedBox(height: 6),
                        TextField(
                          controller: _serverUrlController,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 13,
                            fontFamily: 'monospace',
                          ),
                          decoration: InputDecoration(
                            filled: true,
                            fillColor: const Color(0xFF070A12),
                            contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                            hintText: 'http://10.0.2.2:5000',
                            hintStyle: const TextStyle(color: Color(0xFF475569)),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide: const BorderSide(color: Color(0xFF334155)),
                            ),
                            enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide: const BorderSide(color: Color(0xFF334155)),
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide: const BorderSide(color: Color(0xFF38BDF8)),
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),

                        // Pairing Key
                        const Text(
                          'PAIRING KEY (FROM CONTROL PANEL)',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
                            color: Color(0xFF94A3B8),
                          ),
                        ),
                        const SizedBox(height: 6),
                        TextField(
                          controller: _keyController,
                          textCapitalization: TextCapitalization.characters,
                          style: const TextStyle(
                            color: Color(0xFF38BDF8),
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 2,
                            fontFamily: 'monospace',
                          ),
                          decoration: InputDecoration(
                            filled: true,
                            fillColor: const Color(0xFF070A12),
                            contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                            hintText: 'VYR-XXXX-XXXX',
                            hintStyle: const TextStyle(color: Color(0xFF475569)),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide: const BorderSide(color: Color(0xFF334155)),
                            ),
                            enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide: const BorderSide(color: Color(0xFF334155)),
                            ),
                            focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(10),
                              borderSide: const BorderSide(color: Color(0xFF38BDF8)),
                            ),
                          ),
                        ),
                        const SizedBox(height: 24),

                        // Submit Button
                        SizedBox(
                          width: double.infinity,
                          height: 48,
                          child: ElevatedButton(
                            onPressed: _isLoading ? null : _handlePairing,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color(0xFF0284C7),
                              foregroundColor: Colors.white,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                            child: _isLoading
                                ? const SizedBox(
                                    width: 22,
                                    height: 22,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2.5,
                                      color: Colors.white,
                                    ),
                                  )
                                : const Text(
                                    'Link & Authorize Device',
                                    style: TextStyle(
                                      fontSize: 14,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                          ),
                        ),

                        if (_statusText != null) ...[
                          const SizedBox(height: 14),
                          Center(
                            child: Text(
                              _statusText!,
                              textAlign: TextAlign.center,
                              style: const TextStyle(
                                fontSize: 11,
                                color: Color(0xFF38BDF8),
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),

                  const SizedBox(height: 24),
                  const Text(
                    '100% Closed Privacy Loop · Zero Cloud Logging',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 11,
                      color: Color(0xFF64748B),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
