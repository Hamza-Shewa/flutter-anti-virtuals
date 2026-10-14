import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// CI runs these on an Android emulator and the iOS Simulator with
/// `--dart-define=EXPECT_EMULATOR=true`. On a real device, leave it out.
const onEmulator = bool.fromEnvironment('EXPECT_EMULATOR');

/// Pumps until [finder] matches. The scan runs natively, so the frames have
/// to keep coming while it does.
Future<void> pumpUntil(WidgetTester tester, Finder finder) async {
  final end = DateTime.now().add(const Duration(seconds: 30));
  while (DateTime.now().isBefore(end)) {
    await tester.pump(const Duration(milliseconds: 200));
    if (finder.evaluate().isNotEmpty) return;
  }
  fail('Timed out waiting for $finder');
}

/// `testWidgets` that logs its name when it starts, so the device log shows
/// which test was running if one never finishes.
void integrationTest(
  String description,
  WidgetTesterCallback body, {
  bool skip = false,
}) {
  integrationTest(description, (tester) async {
    debugPrint('integration test: $description');
    await body(tester);
  }, skip: skip);
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  integrationTest('scan answers every enabled signal and no check fails', (
    tester,
  ) async {
    final options = ScanOptions();
    final report = await FlutterAntiVirtuals.instance.scan(options);
    debugPrint(jsonEncode(report.toJson()));
    expect(report.results.keys, containsAll(options.enabledSignals));
    expect(report.failed, isEmpty, reason: 'checks that threw natively');
  });

  integrationTest('check evaluates a single signal', (tester) async {
    final result = await FlutterAntiVirtuals.instance.check(
      AntiVirtualSignal.vpn,
    );
    expect(result.supported, isTrue);
  });

  integrationTest('the emulator is detected', (tester) async {
    final result = await FlutterAntiVirtuals.instance.check(
      AntiVirtualSignal.emulator,
    );
    expect(result.detected, isTrue, reason: '${result.details}');
  }, skip: !onEmulator);

  integrationTest('verify signs the scan with the nonce in the payload', (
    tester,
  ) async {
    const nonce = 'integration-test-nonce-0001';
    final signed = await FlutterAntiVirtuals.instance.verify(nonce: nonce);
    final payload = jsonDecode(signed.payload) as Map<String, Object?>;
    expect(payload['nonce'], nonce);
    expect(
      payload['platform'],
      defaultTargetPlatform == TargetPlatform.iOS ? 'iOS' : 'android',
    );
    expect(signed.signature.signature, isNotEmpty);
    expect(signed.signature.publicKey, isNotEmpty);
  });

  integrationTest('screen protection can be switched on and off', (
    tester,
  ) async {
    await tester.pumpWidget(const MaterialApp(home: Text('protected')));
    await tester.pumpAndSettle();
    expect(await FlutterAntiVirtuals.instance.protectScreen(), isTrue);
    await FlutterAntiVirtuals.instance.unprotectScreen();
  });

  integrationTest(
    'the guard blocks on the emulator signal and lets in without it',
    (tester) async {
      Widget guard(Set<AntiVirtualSignal> blockOn) => MaterialApp(
        home: AntiVirtualGuard(
          blockOn: blockOn,
          locale: const Locale('en'),
          liveMonitoring: false,
          child: const Text('inside'),
        ),
      );

      await tester.pumpWidget(guard(const {AntiVirtualSignal.emulator}));
      await pumpUntil(tester, find.text('Try again'));
      expect(find.text('inside'), findsNothing);

      // A policy change is decided on the last report, without a new scan.
      await tester.pumpWidget(guard(const {}));
      await pumpUntil(tester, find.text('inside'));
    },
    skip: !onEmulator,
  );
}
