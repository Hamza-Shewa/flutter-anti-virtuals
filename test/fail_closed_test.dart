import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class _Platform extends FlutterAntiVirtualsPlatform
    with MockPlatformInterfaceMixin {
  Map<AntiVirtualSignal, SignalResult> results = {};
  final protections = <ScreenProtectionOptions?>[];

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async =>
      AntiVirtualReport({
        for (final s in options.enabledSignals)
          s: results[s] ?? const SignalResult(detected: false),
      });

  @override
  Future<bool> setScreenProtection(ScreenProtectionOptions? options) async {
    protections.add(options);
    return true;
  }

  @override
  Future<DeviceSignature> signPayload(String nonce, String payload) async =>
      const DeviceSignature(
        signature: 'c2ln',
        publicKey: 'a2V5',
        algorithm: 'SHA256withECDSA',
        protection: KeyProtection.hardware,
        attested: false,
      );
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late _Platform platform;
  late FlutterAntiVirtualsPlatform original;

  setUp(() {
    original = FlutterAntiVirtualsPlatform.instance;
    platform = _Platform();
    FlutterAntiVirtualsPlatform.instance = platform;
  });

  tearDown(() => FlutterAntiVirtualsPlatform.instance = original);

  group('failed checks are unknown, not clean', () {
    test('a failed native check is parsed as failed', () {
      final result = SignalResult.fromMap({
        'detected': false,
        'supported': false,
        'failed': true,
        'error': 'SecurityException',
      });
      expect(result.failed, isTrue);
      expect(result.error, 'SecurityException');
      expect(result.detected, isFalse);
    });

    test('a requested signal missing from the native map is failed', () {
      final report = AntiVirtualReport.fromMap(
        {
          'vpn': {'detected': false},
        },
        requested: {AntiVirtualSignal.vpn, AntiVirtualSignal.proxy},
      );
      expect(report.failed, {AntiVirtualSignal.proxy});
      expect(report.detected, isEmpty);
      expect(report.isClean, isFalse);
      expect(report.toJson()['proxy'], containsPair('failed', true));
    });

    test(
      'a null native reply throws instead of an empty clean report',
      () async {
        FlutterAntiVirtualsPlatform.instance = original;
        const channel = MethodChannel('flutter_anti_virtuals');
        final messenger =
            TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
        messenger.setMockMethodCallHandler(channel, (call) async => null);
        addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
        await expectLater(
          FlutterAntiVirtuals.instance.scan(),
          throwsA(
            isA<PlatformException>().having((e) => e.code, 'code', 'no_result'),
          ),
        );
      },
    );

    test('the signed payload marks a failed check', () async {
      platform.results = {
        AntiVirtualSignal.vpn: const SignalResult.failed('boom'),
      };
      final signed = await FlutterAntiVirtuals.instance.verify(
        nonce: 'nonce-from-the-backend-0001',
        options: ScanOptions().onlyChecking(AntiVirtualSignal.vpn),
      );
      final payload = jsonDecode(signed.payload) as Map<String, Object?>;
      expect(payload['signals'], {
        'vpn': {'detected': false, 'supported': true, 'failed': true},
      });
    });

    test('verify refuses platforms other than Android and iOS', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
      addTearDown(() => debugDefaultTargetPlatformOverride = null);
      await expectLater(
        FlutterAntiVirtuals.instance.verify(
          nonce: 'nonce-from-the-backend-0001',
        ),
        throwsUnsupportedError,
      );
    });

    test('results compare by value', () {
      expect(
        const SignalResult(detected: true, details: ['a']),
        const SignalResult(detected: true, details: ['a']),
      );
      expect(
        const SignalResult.failed('x'),
        isNot(const SignalResult(detected: false)),
      );
    });
  });

  group('guard', () {
    const appKey = Key('app');
    Widget app(AntiVirtualGuard guard) => MaterialApp(home: guard);

    testWidgets('failClosed blocks on a failed blocking check', (tester) async {
      platform.results = {
        AntiVirtualSignal.vpn: const SignalResult.failed('boom'),
      };
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            failClosed: true,
            child: Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey, skipOffstage: false), findsNothing);
      expect(find.text(AntiVirtualMessages.english.scanFailed), findsOneWidget);
    });

    testWidgets('without failClosed a failed check does not block', (
      tester,
    ) async {
      platform.results = {
        AntiVirtualSignal.vpn: const SignalResult.failed('boom'),
      };
      await tester.pumpWidget(
        app(const AntiVirtualGuard(child: Text('app', key: appKey))),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
    });

    testWidgets('a failed non-blocking check does not block', (tester) async {
      platform.results = {
        AntiVirtualSignal.adb: const SignalResult.failed('boom'),
      };
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            failClosed: true,
            child: Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
    });

    const installedOnly = SignalResult(
      detected: true,
      details: ['mock app com.lexa.fakegps'],
      installedApps: ['mock app com.lexa.fakegps'],
    );

    testWidgets('an installed tool alone does not block by default', (
      tester,
    ) async {
      platform.results = {AntiVirtualSignal.mockLocation: installedOnly};
      AntiVirtualReport? reported;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            onReport: (r) => reported = r,
            child: const Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
      expect(reported!.detected, contains(AntiVirtualSignal.mockLocation));
    });

    testWidgets('blockOnInstalledApps blocks on an installed tool', (
      tester,
    ) async {
      platform.results = {AntiVirtualSignal.mockLocation: installedOnly};
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            blockOnInstalledApps: true,
            child: Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey, skipOffstage: false), findsNothing);
    });

    testWidgets('an active mock fix blocks even with an installed tool', (
      tester,
    ) async {
      platform.results = {
        AntiVirtualSignal.mockLocation: const SignalResult(
          detected: true,
          details: ['mock location from provider gps', 'mock app x'],
          installedApps: ['mock app x'],
        ),
      };
      await tester.pumpWidget(
        app(const AntiVirtualGuard(child: Text('app', key: appKey))),
      );
      await tester.pump();
      expect(find.byKey(appKey, skipOffstage: false), findsNothing);
    });

    testWidgets('a guard leaving does not undo protectScreen()', (
      tester,
    ) async {
      await FlutterAntiVirtuals.instance.protectScreen(
        const ScreenProtectionOptions(hideOverlayWindows: false),
      );
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            protectScreen: ScreenProtectionOptions(secureWindow: false),
            child: Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      expect(platform.protections.last, const ScreenProtectionOptions());
      await tester.pumpWidget(const SizedBox());
      await tester.pump();
      expect(
        platform.protections.last,
        const ScreenProtectionOptions(hideOverlayWindows: false),
      );
      await FlutterAntiVirtuals.instance.unprotectScreen();
      expect(platform.protections.last, isNull);
    });
  });
}
