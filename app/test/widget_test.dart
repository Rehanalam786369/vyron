import 'package:flutter_test/flutter_test.dart';
import 'package:app/main.dart';

void main() {
  testWidgets('VyronApp smoke test loads PairingScreen when unpaired', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const VyronApp(isPaired: false));

    // Verify that the pairing screen renders
    expect(find.text('VYRON'), findsOneWidget);
    expect(find.text('DEVICE IDENTITY CARD'), findsOneWidget);
  });
}
