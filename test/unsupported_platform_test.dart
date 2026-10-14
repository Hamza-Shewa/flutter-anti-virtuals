import 'package:flutter/foundation.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_anti_virtuals/src/platform/unsupported_platform.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late FlutterAntiVirtualsPlatform original;

  setUp(() {
    original = FlutterAntiVirtualsPlatform.instance;
    FlutterAntiVirtualsUnsupported.registerWith();
  });

  tearDown(() {
    FlutterAntiVirtualsPlatform.instance = original;
    debugDefaultTargetPlatformOverride = null;
  });

  test('registerWith installs the fallback', () {
    expect(
      FlutterAntiVirtualsPlatform.instance,
      isA<FlutterAntiVirtualsUnsupported>(),
    );
  });

  test(
    'every requested signal is unsupported and the report is clean',
    () async {
      final options = ScanOptions(checkVpn: false);
      final report = await FlutterAntiVirtuals.instance.scan(options);
      expect(report.results.keys.toSet(), options.enabledSignals);
      expect(report.results.values.every((r) => !r.supported), isTrue);
      expect(report.isClean, isTrue);
      expect(report.failed, isEmpty);
    },
  );

  test('screen protection reports nothing applied', () async {
    expect(await FlutterAntiVirtuals.instance.protectScreen(), isFalse);
    expect(await FlutterAntiVirtuals.instance.unprotectScreen(), isFalse);
  });

  test('signing and attestation throw UnsupportedError', () {
    final platform = FlutterAntiVirtualsPlatform.instance;
    expect(() => platform.signPayload('n' * 16, '{}'), throwsUnsupportedError);
    expect(
      () => platform.requestAttestation('{}', const AttestationOptions()),
      throwsUnsupportedError,
    );
  });

  test('verify() still refuses desktop platforms', () {
    debugDefaultTargetPlatformOverride = TargetPlatform.linux;
    expect(
      () => FlutterAntiVirtuals.instance.verify(nonce: 'n' * 16),
      throwsUnsupportedError,
    );
  });

  test('the environment never reports changes', () async {
    expect(
      await FlutterAntiVirtualsPlatform.instance.environmentChanges.isEmpty,
      isTrue,
    );
  });
}
