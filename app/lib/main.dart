import 'package:flutter/material.dart';
import 'screens/pairing_screen.dart';
import 'screens/status_screen.dart';
import 'services/api_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final bool isPaired = await ApiService.isPaired();
  runApp(VyronApp(isPaired: isPaired));
}

class VyronApp extends StatelessWidget {
  final bool isPaired;

  const VyronApp({super.key, required this.isPaired});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VYRON',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF070A12),
        primaryColor: const Color(0xFF06B6D4),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF06B6D4),
          secondary: Color(0xFF7E22CE),
          surface: Color(0xFF0F172A),
          error: Color(0xFFF43F5E),
        ),
        fontFamily: 'Roboto',
      ),
      home: isPaired ? const StatusScreen() : const PairingScreen(),
    );
  }
}
