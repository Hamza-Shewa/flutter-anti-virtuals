import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class _Platform extends FlutterAntiVirtualsPlatform
    with MockPlatformInterfaceMixin {
  Set<AntiVirtualSignal> detected = {};
  Object? error;
  int scans = 0;
  final changes = StreamController<void>.broadcast(sync: true);

  @override
  Stream<void> get environmentChanges => changes.stream;

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async {
    scans++;
    if (error != null) throw error!;
    return AntiVirtualReport({
      for (final s in options.enabledSignals)
        s: SignalResult(detected: detected.contains(s)),
    });
  }
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

  group('AntiVirtualMonitor', () {
    test('scans on start and allows a clean device', () async {
      final monitor = AntiVirtualMonitor();
      addTearDown(monitor.dispose);
      expect(monitor.value, isA<GuardScanning>());
      monitor.start();
      await pumpEventQueue();
      expect(monitor.value, isA<GuardAllowed>());
      expect(monitor.value.report!.isClean, isTrue);
      expect(platform.scans, 1);
    });

    test('blocks on a blocking detection, in signal order', () async {
      platform.detected = {
        AntiVirtualSignal.mockLocation,
        AntiVirtualSignal.vpn,
      };
      final monitor = AntiVirtualMonitor()..start();
      addTearDown(monitor.dispose);
      await pumpEventQueue();
      final state = monitor.value as GuardBlocked;
      expect(state.matches, [
        AntiVirtualSignal.vpn,
        AntiVirtualSignal.mockLocation,
      ]);
      expect(state.unverified, isFalse);
    });

    test('a failed scan fails open unless failClosed', () async {
      platform.error = StateError('boom');
      final errors = <Object>[];
      final open = AntiVirtualMonitor(onError: (e, _) => errors.add(e))
        ..start();
      final closed = AntiVirtualMonitor(
        failClosed: true,
        onError: (e, _) => errors.add(e),
      )..start();
      addTearDown(open.dispose);
      addTearDown(closed.dispose);
      await pumpEventQueue();
      expect(open.value, isA<GuardAllowed>());
      expect(open.value.error, isA<StateError>());
      expect((closed.value as GuardBlocked).unverified, isTrue);
      expect(errors, hasLength(2));
    });

    test('changing the policy re-decides without scanning', () async {
      platform.detected = {AntiVirtualSignal.rooted};
      final monitor = AntiVirtualMonitor()..start();
      addTearDown(monitor.dispose);
      await pumpEventQueue();
      expect(monitor.value, isA<GuardAllowed>());
      monitor.blockOn = {AntiVirtualSignal.rooted};
      expect((monitor.value as GuardBlocked).matches, [
        AntiVirtualSignal.rooted,
      ]);
      expect(platform.scans, 1);
    });

    test('reports every scan on the stream and onReport', () async {
      final seen = <AntiVirtualReport>[];
      final monitor = AntiVirtualMonitor(onReport: seen.add)..start();
      addTearDown(monitor.dispose);
      final streamed = monitor.reports.take(2).toList();
      await pumpEventQueue();
      platform.detected = {AntiVirtualSignal.vpn};
      await monitor.rescan();
      expect(await streamed, hasLength(2));
      expect(seen.last.detected, {AntiVirtualSignal.vpn});
      expect(monitor.value.isBlocked, isTrue);
    });

    test('a new ScanOptions value rescans, an equal one does not', () async {
      final monitor = AntiVirtualMonitor()..start();
      addTearDown(monitor.dispose);
      await pumpEventQueue();
      monitor.options = ScanOptions();
      await pumpEventQueue();
      expect(platform.scans, 1);
      monitor.options = ScanOptions(checkVpn: false);
      await pumpEventQueue();
      expect(platform.scans, 2);
    });
  });

  group('retry', () {
    Widget app(AntiVirtualGuard guard) => MaterialApp(home: guard);
    const appKey = Key('app');

    testWidgets('the built-in screen scans again and lets the app in', (
      tester,
    ) async {
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(
        app(const AntiVirtualGuard(child: Text('app', key: appKey))),
      );
      await tester.pump();
      expect(find.text('Try again'), findsOneWidget);
      platform.detected = {};
      await tester.tap(find.text('Try again'));
      await tester.pump();
      await tester.pump();
      expect(platform.scans, 2);
      expect(find.byKey(appKey), findsOneWidget);
    });

    testWidgets('showRetry: false hides the button', (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            showRetry: false,
            child: Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      expect(find.text('Try again'), findsNothing);
    });

    testWidgets('a custom screen can rescan through the guard', (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            blockedBuilder: (context, matches) => TextButton(
              onPressed: () => AntiVirtualGuard.rescan(context),
              child: const Text('check again'),
            ),
            child: const Text('app', key: appKey),
          ),
        ),
      );
      await tester.pump();
      platform.detected = {};
      await tester.tap(find.text('check again'));
      await tester.pump();
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
    });

    test('every shipped language has a retry label', () {
      expect(AntiVirtualMessages.arabic.retry, isNot('Try again'));
      expect(AntiVirtualMessages.french.retry, 'Réessayer');
      expect(AntiVirtualMessages.spanish.retry, 'Reintentar');
      expect(
        AntiVirtualMessages.english.copyWith(retry: 'Check again').retry,
        'Check again',
      );
    });
  });
}
