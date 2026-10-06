import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class _FakePlatform extends FlutterAntiVirtualsPlatform
    with MockPlatformInterfaceMixin {
  Set<AntiVirtualSignal> detected = {};
  Object? error;
  int scans = 0;
  Completer<void>? gate;

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async {
    scans++;
    await gate?.future;
    if (error != null) throw error!;
    return AntiVirtualReport({
      for (final s in options.enabledSignals)
        s: SignalResult(detected: detected.contains(s)),
    });
  }
}

void main() {
  late _FakePlatform platform;
  late FlutterAntiVirtualsPlatform original;

  setUp(() {
    original = FlutterAntiVirtualsPlatform.instance;
    platform = _FakePlatform();
    FlutterAntiVirtualsPlatform.instance = platform;
  });

  tearDown(() => FlutterAntiVirtualsPlatform.instance = original);

  Widget app(AntiVirtualGuard guard) => MaterialApp(home: guard);

  const appKey = Key('app');
  const appChild = Text('my app', key: appKey);

  testWidgets('clean device: app is shown after the scan', (tester) async {
    await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
    expect(find.byKey(appKey), findsNothing);
    await tester.pump();
    expect(find.byKey(appKey), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsNothing);
    expect(platform.scans, 1);
  });

  testWidgets('waitForScan: false shows the app immediately', (tester) async {
    platform.gate = Completer<void>();
    await tester.pumpWidget(
      app(const AntiVirtualGuard(waitForScan: false, child: appChild)),
    );
    expect(find.byKey(appKey), findsOneWidget);
    platform.gate!.complete();
    await tester.pump();
  });

  testWidgets('custom builder receives the blocking matches in order', (
    tester,
  ) async {
    platform.detected = {AntiVirtualSignal.mockLocation, AntiVirtualSignal.vpn};
    List<AntiVirtualSignal>? seen;
    await tester.pumpWidget(
      app(
        AntiVirtualGuard(
          blockedBuilder: (context, matches) {
            seen = matches;
            return const Text('blocked!');
          },
          child: appChild,
        ),
      ),
    );
    await tester.pump();
    expect(seen, [AntiVirtualSignal.vpn, AntiVirtualSignal.mockLocation]);
    expect(find.text('blocked!'), findsOneWidget);
    expect(find.byKey(appKey), findsNothing); // hidden, not interactive
    expect(
      find.byKey(appKey, skipOffstage: false),
      findsOneWidget,
    ); // kept alive
  });

  testWidgets('signals outside blockOn do not block but reach onReport', (
    tester,
  ) async {
    platform.detected = {AntiVirtualSignal.developerOptions};
    AntiVirtualReport? report;
    await tester.pumpWidget(
      app(AntiVirtualGuard(onReport: (r) => report = r, child: appChild)),
    );
    await tester.pump();
    expect(find.byKey(appKey), findsOneWidget);
    expect(report!.isDetected(AntiVirtualSignal.developerOptions), isTrue);
  });

  testWidgets('default screen shows English messages for each match', (
    tester,
  ) async {
    platform.detected = {AntiVirtualSignal.vpn, AntiVirtualSignal.mockLocation};
    await tester.pumpWidget(
      app(const AntiVirtualGuard(locale: Locale('en'), child: appChild)),
    );
    await tester.pump();
    expect(find.text(AntiVirtualMessages.english.title), findsOneWidget);
    expect(
      find.text(AntiVirtualMessages.english.messageFor(AntiVirtualSignal.vpn)),
      findsOneWidget,
    );
    expect(
      find.text(
        AntiVirtualMessages.english.messageFor(AntiVirtualSignal.mockLocation),
      ),
      findsOneWidget,
    );
    expect(find.textContaining('close in'), findsNothing);
  });

  testWidgets('default screen follows the locale and is RTL for Arabic', (
    tester,
  ) async {
    platform.detected = {AntiVirtualSignal.vpn};
    await tester.pumpWidget(
      app(const AntiVirtualGuard(locale: Locale('ar'), child: appChild)),
    );
    await tester.pump();
    expect(find.text(AntiVirtualMessages.arabic.title), findsOneWidget);
    final title = find.text(AntiVirtualMessages.arabic.title);
    expect(Directionality.of(tester.element(title)), TextDirection.rtl);
  });

  testWidgets('unsupported locale falls back to English', (tester) async {
    platform.detected = {AntiVirtualSignal.vpn};
    await tester.pumpWidget(
      app(const AntiVirtualGuard(locale: Locale('ja'), child: appChild)),
    );
    await tester.pump();
    expect(find.text(AntiVirtualMessages.english.title), findsOneWidget);
  });

  testWidgets('custom messages replace the built-ins', (tester) async {
    platform.detected = {AntiVirtualSignal.vpn};
    await tester.pumpWidget(
      app(
        AntiVirtualGuard(
          messages: AntiVirtualMessages.english.copyWith(
            title: 'Nope',
            signals: {AntiVirtualSignal.vpn: 'Turn off your VPN please'},
          ),
          child: appChild,
        ),
      ),
    );
    await tester.pump();
    expect(find.text('Nope'), findsOneWidget);
    expect(find.text('Turn off your VPN please'), findsOneWidget);
  });

  testWidgets('forceExit counts down and exits after the default 5s', (
    tester,
  ) async {
    platform.detected = {AntiVirtualSignal.vpn};
    var exited = 0;
    await tester.pumpWidget(
      app(
        AntiVirtualGuard(
          forceExit: true,
          exitApp: () async => exited++,
          locale: const Locale('en'),
          child: appChild,
        ),
      ),
    );
    await tester.pump();
    expect(find.text('The app will close in 5 seconds.'), findsOneWidget);
    await tester.pump(const Duration(seconds: 2));
    expect(find.text('The app will close in 3 seconds.'), findsOneWidget);
    expect(exited, 0);
    await tester.pump(const Duration(seconds: 3));
    expect(exited, 1);
  });

  testWidgets('forceExitAfter is adjustable', (tester) async {
    platform.detected = {AntiVirtualSignal.vpn};
    var exited = 0;
    await tester.pumpWidget(
      app(
        AntiVirtualGuard(
          forceExit: true,
          forceExitAfter: const Duration(seconds: 2),
          exitApp: () async => exited++,
          child: appChild,
        ),
      ),
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    expect(exited, 0);
    await tester.pump(const Duration(seconds: 1));
    expect(exited, 1);
  });

  testWidgets('without forceExit the app never exits', (tester) async {
    platform.detected = {AntiVirtualSignal.vpn};
    var exited = 0;
    await tester.pumpWidget(
      app(AntiVirtualGuard(exitApp: () async => exited++, child: appChild)),
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 30));
    expect(exited, 0);
  });

  testWidgets(
    'resume rescans; clearing the problem unblocks and cancels exit',
    (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      var exited = 0;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            forceExit: true,
            exitApp: () async => exited++,
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsNothing);

      platform.detected = {};
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(platform.scans, 2);
      expect(find.byKey(appKey), findsOneWidget);
      await tester.pump(const Duration(seconds: 10));
      expect(exited, 0);
    },
  );

  testWidgets('rescanOnResume: false does not scan again', (tester) async {
    await tester.pumpWidget(
      app(const AntiVirtualGuard(rescanOnResume: false, child: appChild)),
    );
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(platform.scans, 1);
  });

  testWidgets('a failing scan reports onError and lets the app through', (
    tester,
  ) async {
    platform.error = StateError('no plugin');
    Object? reported;
    await tester.pumpWidget(
      app(AntiVirtualGuard(onError: (e, _) => reported = e, child: appChild)),
    );
    await tester.pump();
    expect(reported, isA<StateError>());
    expect(find.byKey(appKey), findsOneWidget);
  });
}
