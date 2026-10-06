import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('scan returns a result for every requested signal', (
    WidgetTester tester,
  ) async {
    final report = await FlutterAntiVirtuals.instance.scan(
      const ScanOptions(
        signals: {AntiVirtualSignal.vpn, AntiVirtualSignal.proxy},
      ),
    );
    expect(
      report.results.keys,
      containsAll([AntiVirtualSignal.vpn, AntiVirtualSignal.proxy]),
    );
  });
}
