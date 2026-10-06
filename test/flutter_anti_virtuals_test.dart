import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_method_channel.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';

class _SilentPlatform extends FlutterAntiVirtualsPlatform {}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_anti_virtuals');
  MethodCall? lastCall;

  setUp(() {
    lastCall = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          lastCall = call;
          return <String, Object?>{
            'vpn': {
              'detected': true,
              'details': ['tun0'],
            },
            'mockLocation': {'detected': false},
            'sideloaded': {'supported': false, 'detected': false},
            'unknownKey': {'detected': true},
          };
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('environmentChanges', () {
    const events = EventChannel('flutter_anti_virtuals/changes');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    late MockStreamHandlerEventSink sink;
    var listens = 0;
    var cancels = 0;

    setUp(() {
      listens = 0;
      cancels = 0;
      messenger.setMockStreamHandler(
        events,
        MockStreamHandler.inline(
          onListen: (arguments, s) {
            listens++;
            sink = s;
          },
          onCancel: (arguments) => cancels++,
        ),
      );
    });

    tearDown(() => messenger.setMockStreamHandler(events, null));

    test('listeners share one native subscription', () async {
      final platform = MethodChannelFlutterAntiVirtuals();
      var a = 0;
      var b = 0;
      final first = platform.environmentChanges.listen((_) => a++);
      final second = platform.environmentChanges.listen((_) => b++);
      await Future<void>.delayed(Duration.zero);
      expect(listens, 1);
      sink.success('network');
      await Future<void>.delayed(Duration.zero);
      expect([a, b], [1, 1]);

      await first.cancel();
      await Future<void>.delayed(Duration.zero);
      expect(cancels, 0); // the second listener still needs events
      sink.success('network');
      await Future<void>.delayed(Duration.zero);
      expect([a, b], [1, 2]);

      await second.cancel();
      await Future<void>.delayed(Duration.zero);
      expect(cancels, 1);
    });

    test('FlutterAntiVirtuals exposes the stream', () async {
      final listener = FlutterAntiVirtuals.instance.environmentChanges.listen(
        (_) {},
      );
      await Future<void>.delayed(Duration.zero);
      expect(listens, 1);
      await listener.cancel();
    });

    test('a missing native side is quiet and never emits', () async {
      messenger.setMockStreamHandler(events, null);
      final reported = <FlutterErrorDetails>[];
      final previous = FlutterError.onError;
      FlutterError.onError = reported.add;
      addTearDown(() => FlutterError.onError = previous);
      final platform = MethodChannelFlutterAntiVirtuals();
      var emitted = 0;
      final listener = platform.environmentChanges.listen((_) => emitted++);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      await listener.cancel();
      expect(reported, isEmpty);
      expect(emitted, 0);
    });

    test('a native failure to start watching is a stream error', () async {
      messenger.setMockStreamHandler(
        events,
        MockStreamHandler.inline(
          onListen: (arguments, sink) =>
              throw PlatformException(code: 'watch_failed'),
        ),
      );
      final platform = MethodChannelFlutterAntiVirtuals();
      final errors = <Object>[];
      final listener = platform.environmentChanges.listen(
        (_) {},
        onError: errors.add,
      );
      await Future<void>.delayed(const Duration(milliseconds: 10));
      await listener.cancel();
      expect(errors.single, isA<PlatformException>());
    });
  });

  test('platforms without live monitoring never emit', () async {
    final platform = _SilentPlatform();
    expect(await platform.environmentChanges.toList(), isEmpty);
  });

  test('method channel is the default instance', () {
    expect(
      FlutterAntiVirtualsPlatform.instance,
      isA<MethodChannelFlutterAntiVirtuals>(),
    );
  });

  test('scan parses the report and ignores unknown signals', () async {
    final report = await FlutterAntiVirtuals.instance.scan();
    expect(report.detected, {AntiVirtualSignal.vpn});
    expect(report[AntiVirtualSignal.vpn]!.details, ['tun0']);
    expect(report[AntiVirtualSignal.sideloaded]!.supported, isFalse);
    expect(report.isClean, isFalse);
    expect(report.toJson()['vpn'], containsPair('detected', true));
  });

  test('options are serialised for the platform', () async {
    await FlutterAntiVirtuals.instance.scan(
      ScanOptions(
        checkVpn: false,
        checkAdb: false,
        expectedSignatureSha256: ['AB12'],
        maxClockSkew: const Duration(seconds: 30),
      ),
    );
    final args = lastCall!.arguments as Map;
    expect(lastCall!.method, 'scan');
    expect(args['signals'], isNot(contains('vpn')));
    expect(args['signals'], isNot(contains('adb')));
    expect(args['signals'], contains('proxy'));
    expect(args['signals'], contains('signatureMismatch'));
    expect(args['expectedSignatureSha256'], ['ab12']);
    expect(args['maxClockSkewMs'], 30000);
  });

  test('check evaluates only the requested signal', () async {
    final result = await FlutterAntiVirtuals.instance.check(
      AntiVirtualSignal.vpn,
    );
    expect(result.detected, isTrue);
    expect((lastCall!.arguments as Map)['signals'], ['vpn']);
  });

  test('default trusted installers exclude the manual APK installer', () {
    expect(
      ScanOptions.defaultTrustedInstallers,
      isNot(contains('com.google.android.packageinstaller')),
    );
    expect(
      ScanOptions.defaultTrustedInstallers,
      containsAll(['com.android.vending', 'com.sec.android.app.samsungapps']),
    );
  });

  group('ScanOptions', () {
    test('every check is on by default; signature needs hashes to run', () {
      final options = ScanOptions();
      expect(
        options.enabledSignals,
        AntiVirtualSignal.values.toSet()
          ..remove(AntiVirtualSignal.signatureMismatch),
      );
      expect(
        ScanOptions(expectedSignatureSha256: ['aa']).enabledSignals,
        AntiVirtualSignal.values.toSet(),
      );
    });

    test('checkSignatureMismatch: true without hashes asserts', () {
      expect(
        () => ScanOptions(checkSignatureMismatch: true),
        throwsA(isA<AssertionError>()),
      );
      expect(
        ScanOptions(
          checkSignatureMismatch: true,
          expectedSignatureSha256: ['aa'],
        ).enabledSignals,
        contains(AntiVirtualSignal.signatureMismatch),
      );
    });

    test('checkSignatureMismatch: false skips even with hashes', () {
      final options = ScanOptions(
        checkSignatureMismatch: false,
        expectedSignatureSha256: ['aa'],
      );
      expect(
        options.enabledSignals,
        isNot(contains(AntiVirtualSignal.signatureMismatch)),
      );
    });

    test('installer check needs trusted installers', () {
      expect(
        () => ScanOptions(trustedInstallers: const []),
        throwsA(isA<AssertionError>()),
      );
      expect(
        ScanOptions(
          checkUntrustedInstaller: false,
          trustedInstallers: const [],
        ).enabledSignals,
        isNot(contains(AntiVirtualSignal.untrustedInstaller)),
      );
    });

    test('options compare by value', () {
      expect(ScanOptions(), ScanOptions());
      expect(ScanOptions().hashCode, ScanOptions().hashCode);
      expect(
        ScanOptions(expectedSignatureSha256: ['aa']),
        ScanOptions(expectedSignatureSha256: ['aa']),
      );
      expect(ScanOptions(checkVpn: false), isNot(ScanOptions()));
      expect(ScanOptions(checkEmulator: false), isNot(ScanOptions()));
      expect(
        ScanOptions(checkEmulator: false).enabledSignals,
        isNot(contains(AntiVirtualSignal.emulator)),
      );
      expect(
        ScanOptions().onlyChecking(AntiVirtualSignal.emulator).toMap()['signals'],
        ['emulator'],
      );
      expect(
        ScanOptions(maxClockSkew: const Duration(seconds: 1)),
        isNot(ScanOptions()),
      );
    });

    test('onlyChecking keeps configuration and disables the rest', () {
      final only = ScanOptions(
        expectedSignatureSha256: ['aa'],
        maxClockSkew: const Duration(seconds: 9),
      ).onlyChecking(AntiVirtualSignal.adb);
      expect(only.enabledSignals, {AntiVirtualSignal.adb});
      expect(only.expectedSignatureSha256, ['aa']);
      expect(only.maxClockSkew, const Duration(seconds: 9));
    });

    test('single signature check without hashes asserts', () async {
      await expectLater(
        FlutterAntiVirtuals.instance.check(AntiVirtualSignal.signatureMismatch),
        throwsA(isA<AssertionError>()),
      );
    });
  });

  test('channel errors propagate instead of looking clean', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          throw PlatformException(code: 'boom');
        });
    await expectLater(
      FlutterAntiVirtuals.instance.scan(),
      throwsA(isA<PlatformException>()),
    );
  });
}
