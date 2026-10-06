import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('scan returns a result for every enabled signal', (
    WidgetTester tester,
  ) async {
    final options = ScanOptions();
    final report = await FlutterAntiVirtuals.instance.scan(options);
    expect(report.results.keys, containsAll(options.enabledSignals));
  });

  testWidgets('check evaluates a single signal', (WidgetTester tester) async {
    final result = await FlutterAntiVirtuals.instance.check(
      AntiVirtualSignal.vpn,
    );
    expect(result.supported, isTrue);
  });
}
