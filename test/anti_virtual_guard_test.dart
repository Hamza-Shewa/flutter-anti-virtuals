import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
  final changes = StreamController<void>.broadcast(sync: true);

  @override
  Stream<void> get environmentChanges => changes.stream;

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

void goBackground(WidgetTester tester) {
  for (final s in [
    AppLifecycleState.inactive,
    AppLifecycleState.hidden,
    AppLifecycleState.paused,
  ]) {
    tester.binding.handleAppLifecycleStateChanged(s);
  }
}

void goForeground(WidgetTester tester) {
  for (final s in [
    AppLifecycleState.hidden,
    AppLifecycleState.inactive,
    AppLifecycleState.resumed,
  ]) {
    tester.binding.handleAppLifecycleStateChanged(s);
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
    // Blocked from the start: the app is never built.
    expect(find.byKey(appKey, skipOffstage: false), findsNothing);
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
    expect(find.textContaining('will close'), findsNothing);
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
      goBackground(tester);
      goForeground(tester);
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
    goBackground(tester);
    goForeground(tester);
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

  void pauseAndResume(WidgetTester tester) {
    goBackground(tester);
    goForeground(tester);
  }

  group('review fixes', () {
    testWidgets('the app is not built until the first scan is clean', (
      tester,
    ) async {
      platform.gate = Completer<void>();
      var builds = 0;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            child: Builder(
              builder: (_) {
                builds++;
                return appChild;
              },
            ),
          ),
        ),
      );
      await tester.pump();
      expect(builds, 0);
      platform.gate!.complete();
      await tester.pump();
      expect(builds, 1);
    });

    testWidgets('a blocked first scan never builds the app', (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      var builds = 0;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            child: Builder(
              builder: (_) {
                builds++;
                return appChild;
              },
            ),
          ),
        ),
      );
      await tester.pump();
      expect(builds, 0);
    });

    testWidgets('blocking later drops focus and pauses animations', (
      tester,
    ) async {
      final focus = FocusNode();
      addTearDown(focus.dispose);
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            unmountWhileBlocked: false,
            child: Scaffold(body: TextField(focusNode: focus)),
          ),
        ),
      );
      await tester.pump();
      focus.requestFocus();
      await tester.pump();
      expect(focus.hasFocus, isTrue);

      platform.detected = {AntiVirtualSignal.proxy};
      pauseAndResume(tester);
      await tester.pump();
      expect(focus.hasFocus, isFalse);
      final field = find.byType(TextField, skipOffstage: false);
      expect(TickerMode.valuesOf(tester.element(field)).enabled, isFalse);
      focus.requestFocus();
      await tester.pump();
      expect(focus.hasFocus, isFalse); // cannot regain focus while blocked
    });

    testWidgets('a throwing onReport does not let a blocked device in', (
      tester,
    ) async {
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            onReport: (_) => throw StateError('boom'),
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(tester.takeException(), isA<StateError>());
      expect(find.byKey(appKey), findsNothing);
      expect(find.text(AntiVirtualMessages.english.title), findsOneWidget);
    });

    testWidgets('the countdown pauses in the background and restarts', (
      tester,
    ) async {
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
      goBackground(tester);
      await tester.pump(const Duration(seconds: 30));
      expect(exited, 0);
      goForeground(tester);
      await tester.pump();
      expect(find.text('The app will close in 5 seconds.'), findsOneWidget);
      await tester.pump(const Duration(seconds: 5));
      expect(exited, 1);
    });

    testWidgets('the device language is used under MaterialApp.builder', (
      tester,
    ) async {
      tester.platformDispatcher.localesTestValue = const [Locale('ar', 'LY')];
      addTearDown(tester.platformDispatcher.clearLocalesTestValue);
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(
        MaterialApp(
          builder: (context, child) => AntiVirtualGuard(child: child!),
          home: appChild,
        ),
      );
      await tester.pump();
      expect(find.text(AntiVirtualMessages.arabic.title), findsOneWidget);
    });

    testWidgets('Hebrew falls back to English text laid out left to right', (
      tester,
    ) async {
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(
        app(const AntiVirtualGuard(locale: Locale('he'), child: appChild)),
      );
      await tester.pump();
      final title = find.text(AntiVirtualMessages.english.title);
      expect(title, findsOneWidget);
      expect(Directionality.of(tester.element(title)), TextDirection.ltr);
    });

    testWidgets('changing forceExit later cancels the exit', (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      var exited = 0;
      Widget build(bool forceExit) => app(
        AntiVirtualGuard(
          forceExit: forceExit,
          exitApp: () async => exited++,
          child: appChild,
        ),
      );
      await tester.pumpWidget(build(true));
      await tester.pump();
      await tester.pumpWidget(build(false));
      await tester.pump(const Duration(seconds: 10));
      expect(exited, 0);
      expect(find.textContaining('will close'), findsNothing);
    });

    testWidgets('changing blockOn later re-evaluates the last report', (
      tester,
    ) async {
      platform.detected = {AntiVirtualSignal.vpn};
      Widget build(Set<AntiVirtualSignal> blockOn) =>
          app(AntiVirtualGuard(blockOn: blockOn, child: appChild));
      await tester.pumpWidget(build({AntiVirtualSignal.vpn}));
      await tester.pump();
      expect(find.byKey(appKey), findsNothing);
      await tester.pumpWidget(build({AntiVirtualSignal.proxy}));
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
      expect(platform.scans, 1); // no new scan needed
    });

    testWidgets('changing options scans again', (tester) async {
      final first = ScanOptions();
      final second = ScanOptions(checkVpn: false);
      await tester.pumpWidget(
        app(AntiVirtualGuard(options: first, child: appChild)),
      );
      await tester.pump();
      await tester.pumpWidget(
        app(AntiVirtualGuard(options: second, child: appChild)),
      );
      await tester.pump();
      expect(platform.scans, 2);
    });

    testWidgets('a failed rescan keeps the last known block', (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      var exited = 0;
      Object? reported;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            forceExit: true,
            exitApp: () async => exited++,
            onError: (e, _) => reported = e,
            child: appChild,
          ),
        ),
      );
      await tester.pump();

      platform.error = StateError('rescan failed');
      pauseAndResume(tester);
      await tester.pump();
      expect(reported, isA<StateError>());
      expect(find.byKey(appKey, skipOffstage: false), findsNothing);
      expect(find.text(AntiVirtualMessages.english.title), findsOneWidget);
      await tester.pump(const Duration(seconds: 5));
      expect(exited, 1); // still on the clock
    });

    testWidgets('errors are reported when there is no onError', (tester) async {
      platform.error = StateError('no handler');
      await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
      await tester.pump();
      expect(tester.takeException(), isA<StateError>());
      expect(find.byKey(appKey), findsOneWidget); // first scan fails open
    });

    testWidgets('failClosed blocks when the first scan fails', (tester) async {
      platform.error = StateError('hooked');
      List<AntiVirtualSignal>? seen;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            failClosed: true,
            onError: (_, _) {},
            blockedBuilder: (context, matches) {
              seen = matches;
              return const Text('closed');
            },
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(seen, isEmpty);
      expect(find.text('closed'), findsOneWidget);
      expect(find.byKey(appKey, skipOffstage: false), findsNothing);
    });

    testWidgets('failClosed default screen explains the failure', (
      tester,
    ) async {
      platform.error = StateError('hooked');
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            failClosed: true,
            locale: const Locale('en'),
            onError: (_, _) {},
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(find.text(AntiVirtualMessages.english.scanFailed), findsOneWidget);
      expect(find.text(AntiVirtualMessages.english.subtitle), findsNothing);
    });

    testWidgets('failClosed blocks a clean device when a rescan fails', (
      tester,
    ) async {
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            failClosed: true,
            onError: (_, _) {},
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
      platform.error = StateError('hooked');
      pauseAndResume(tester);
      await tester.pump();
      expect(find.byKey(appKey), findsNothing);
    });

    testWidgets('inline ScanOptions do not rescan on parent rebuilds', (
      tester,
    ) async {
      late StateSetter rebuild;
      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              rebuild = setState;
              return AntiVirtualGuard(
                options: ScanOptions(checkSignatureMismatch: false),
                child: appChild,
              );
            },
          ),
        ),
      );
      await tester.pump();
      for (var i = 0; i < 5; i++) {
        rebuild(() {});
        await tester.pump();
      }
      expect(platform.scans, 1);
      expect(find.byKey(appKey), findsOneWidget);
    });

    testWidgets('rebuilds during scans do not starve the first result', (
      tester,
    ) async {
      late StateSetter rebuild;
      platform.gate = Completer<void>();
      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              rebuild = setState;
              return AntiVirtualGuard(
                options: ScanOptions(checkSignatureMismatch: false),
                child: appChild,
              );
            },
          ),
        ),
      );
      for (var i = 0; i < 3; i++) {
        rebuild(() {});
        await tester.pump();
        final gate = platform.gate!;
        platform.gate = Completer<void>();
        gate.complete();
        await tester.pump();
      }
      expect(find.byKey(appKey), findsOneWidget);
    });

    testWidgets('the shade or quick settings rescan once the scan is stale', (
      tester,
    ) async {
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            rescanDebounce: Duration.zero,
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);

      platform.detected = {AntiVirtualSignal.vpn}; // toggled in quick settings
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(platform.scans, 2);
      expect(find.byKey(appKey), findsNothing);
    });

    testWidgets('rescanInterval scans periodically while in the foreground', (
      tester,
    ) async {
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            rescanInterval: Duration(seconds: 10),
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      platform.detected = {AntiVirtualSignal.proxy};
      await tester.pump(const Duration(seconds: 10));
      await tester.pump();
      expect(platform.scans, 2);
      expect(find.byKey(appKey), findsNothing);
      goBackground(tester);
      await tester.pump(const Duration(seconds: 30));
      expect(platform.scans, 2); // not while backgrounded
    });

    testWidgets('forceExit still restarts when rescanOnResume is false', (
      tester,
    ) async {
      platform.detected = {AntiVirtualSignal.vpn};
      var exited = 0;
      await tester.pumpWidget(
        app(
          AntiVirtualGuard(
            forceExit: true,
            rescanOnResume: false,
            exitApp: () async => exited++,
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      goBackground(tester);
      goForeground(tester);
      await tester.pump(const Duration(seconds: 10));
      expect(exited, 1);
    });

    testWidgets('a locale change updates the default screen', (tester) async {
      platform.detected = {AntiVirtualSignal.vpn};
      await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
      await tester.pump();
      expect(find.text(AntiVirtualMessages.english.title), findsOneWidget);
      tester.platformDispatcher.localesTestValue = const [Locale('fr')];
      addTearDown(tester.platformDispatcher.clearLocalesTestValue);
      await tester.pump();
      expect(find.text(AntiVirtualMessages.french.title), findsOneWidget);
    });

    testWidgets('the app is removed while blocked by default and restored', (
      tester,
    ) async {
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            rescanDebounce: Duration.zero,
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
      platform.detected = {AntiVirtualSignal.vpn};
      goBackground(tester);
      goForeground(tester);
      await tester.pump();
      expect(find.byKey(appKey, skipOffstage: false), findsNothing);
      platform.detected = {};
      goBackground(tester);
      goForeground(tester);
      await tester.pump();
      expect(find.byKey(appKey), findsOneWidget);
    });

    testWidgets('unmountWhileBlocked: false keeps the app mounted', (
      tester,
    ) async {
      await tester.pumpWidget(
        app(
          const AntiVirtualGuard(
            unmountWhileBlocked: false,
            rescanDebounce: Duration.zero,
            child: appChild,
          ),
        ),
      );
      await tester.pump();
      platform.detected = {AntiVirtualSignal.vpn};
      goBackground(tester);
      goForeground(tester);
      await tester.pump();
      expect(find.byKey(appKey), findsNothing);
      expect(find.byKey(appKey, skipOffstage: false), findsOneWidget);
    });

    group('live monitoring', () {
      Future<void> settle(WidgetTester tester) =>
          tester.pump(const Duration(milliseconds: 600));

      testWidgets('a VPN switched on in the foreground blocks the app', (
        tester,
      ) async {
        await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
        await tester.pump();
        expect(find.byKey(appKey), findsOneWidget);
        expect(platform.scans, 1);

        platform.detected = {AntiVirtualSignal.vpn};
        platform.changes.add(null);
        await settle(tester);
        expect(platform.scans, 2);
        expect(find.byKey(appKey, skipOffstage: false), findsNothing);
        expect(find.text(AntiVirtualMessages.english.title), findsOneWidget);

        platform.detected = {};
        platform.changes.add(null);
        await settle(tester);
        expect(find.byKey(appKey), findsOneWidget);
      });

      testWidgets('a burst of changes causes one scan', (tester) async {
        await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
        await tester.pump();
        for (var i = 0; i < 5; i++) {
          platform.changes.add(null);
          await tester.pump(const Duration(milliseconds: 100));
        }
        await settle(tester);
        expect(platform.scans, 2);
      });

      testWidgets('liveDebounce is adjustable', (tester) async {
        await tester.pumpWidget(
          app(
            const AntiVirtualGuard(
              liveDebounce: Duration(seconds: 2),
              child: appChild,
            ),
          ),
        );
        await tester.pump();
        platform.changes.add(null);
        await settle(tester);
        expect(platform.scans, 1);
        await tester.pump(const Duration(seconds: 2));
        expect(platform.scans, 2);
      });

      testWidgets('liveMonitoring: false ignores changes', (tester) async {
        await tester.pumpWidget(
          app(const AntiVirtualGuard(liveMonitoring: false, child: appChild)),
        );
        await tester.pump();
        platform.changes.add(null);
        await settle(tester);
        expect(platform.scans, 1);
        expect(platform.changes.hasListener, isFalse);
      });

      testWidgets('changes in the background wait for the resume rescan', (
        tester,
      ) async {
        await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
        await tester.pump();
        goBackground(tester);
        platform.changes.add(null);
        await settle(tester);
        expect(platform.scans, 1);
        goForeground(tester);
        await tester.pump();
        expect(platform.scans, 2);
      });

      testWidgets('a change during a scan is rescanned afterwards', (
        tester,
      ) async {
        await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
        await tester.pump();
        platform.gate = Completer<void>();
        platform.changes.add(null);
        await settle(tester); // scan 2 starts and waits on the gate
        platform.detected = {AntiVirtualSignal.proxy};
        platform.changes.add(null);
        await settle(tester); // queued, because one is running
        platform.gate!.complete();
        await tester.pump();
        await tester.pump();
        expect(platform.scans, 3);
        expect(find.byKey(appKey, skipOffstage: false), findsNothing);
      });

      testWidgets('a missing event channel is ignored, other errors reported', (
        tester,
      ) async {
        final errors = <Object>[];
        await tester.pumpWidget(
          app(
            AntiVirtualGuard(
              onError: (error, _) => errors.add(error),
              child: appChild,
            ),
          ),
        );
        await tester.pump();
        platform.changes.addError(MissingPluginException());
        await tester.pump();
        expect(errors, isEmpty);
        platform.changes.addError(PlatformException(code: 'watch_failed'));
        await tester.pump();
        expect(errors.single, isA<PlatformException>());
        expect(find.byKey(appKey), findsOneWidget);
      });

      testWidgets('stops listening when removed', (tester) async {
        await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
        await tester.pump();
        expect(platform.changes.hasListener, isTrue);
        await tester.pumpWidget(const SizedBox());
        expect(platform.changes.hasListener, isFalse);
      });
    });

    testWidgets('waitForScan switched off mid-scan shows the app', (
      tester,
    ) async {
      platform.gate = Completer<void>();
      Widget build(bool wait) =>
          app(AntiVirtualGuard(waitForScan: wait, child: appChild));
      await tester.pumpWidget(build(true));
      await tester.pump();
      expect(find.byKey(appKey), findsNothing);
      await tester.pumpWidget(build(false));
      expect(find.byKey(appKey), findsOneWidget);
      platform.gate!.complete();
      await tester.pump();
    });

    testWidgets('brief interruptions do not rescan', (tester) async {
      await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
      await tester.pump();
      // Notification shade / permission dialog: inactive, never backgrounded.
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(platform.scans, 1);
    });

    testWidgets('a running scan is kept, then refreshed once', (tester) async {
      platform.gate = Completer<void>();
      await tester.pumpWidget(app(const AntiVirtualGuard(child: appChild)));
      await tester.pump();
      pauseAndResume(tester);
      pauseAndResume(tester);
      await tester.pump();
      expect(platform.scans, 1); // not restarted while running
      platform.gate!.complete();
      await tester.pump();
      await tester.pump();
      expect(platform.scans, 2); // one refresh for the missed return
    });
  });

  group('AntiVirtualMessages', () {
    test('countdown uses proper singular and plural forms', () {
      expect(
        AntiVirtualMessages.english.closingMessage(1),
        'The app will close in 1 second.',
      );
      expect(
        AntiVirtualMessages.english.closingMessage(5),
        'The app will close in 5 seconds.',
      );
      expect(
        AntiVirtualMessages.french.closingMessage(1),
        contains('1 seconde.'),
      );
      expect(
        AntiVirtualMessages.spanish.closingMessage(1),
        contains('1 segundo.'),
      );
    });

    test('Arabic countdown has distinct forms for 1, 2, 3-10 and 11+', () {
      String forN(int n) => AntiVirtualMessages.arabic.closingMessage(n);
      expect(forN(1), contains('ثانية واحدة'));
      expect(forN(2), contains('ثانيتين'));
      expect(forN(5), contains('5 ثوانٍ'));
      expect(forN(10), contains('10 ثوانٍ'));
      expect(forN(11), contains('11 ثانية'));
    });

    test('copyWith keeps and can override the text direction', () {
      expect(
        AntiVirtualMessages.arabic.copyWith(title: 'x').textDirection,
        TextDirection.rtl,
      );
      expect(
        AntiVirtualMessages.english
            .copyWith(textDirection: TextDirection.rtl)
            .textDirection,
        TextDirection.rtl,
      );
    });

    test('supported languages come from the shipped messages', () {
      expect(
        AntiVirtualMessages.supportedLanguages,
        unorderedEquals(['en', 'ar', 'fr', 'es']),
      );
      expect(AntiVirtualMessages.arabic.textDirection, TextDirection.rtl);
      expect(AntiVirtualMessages.english.textDirection, TextDirection.ltr);
    });
  });
}
