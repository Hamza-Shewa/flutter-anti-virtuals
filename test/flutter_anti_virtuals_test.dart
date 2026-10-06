import 'package:flutter/services.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_method_channel.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';

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
      const ScanOptions(
        signals: {AntiVirtualSignal.proxy},
        expectedSignatureSha256: ['AB12'],
        maxClockSkew: Duration(seconds: 30),
      ),
    );
    final args = lastCall!.arguments as Map;
    expect(lastCall!.method, 'scan');
    expect(args['signals'], ['proxy']);
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

  test('copyWith keeps unchanged fields', () {
    const original = ScanOptions(
      expectedSignatureSha256: ['aa'],
      maxClockSkew: Duration(seconds: 9),
    );
    final copy = original.copyWith(signals: {AntiVirtualSignal.adb});
    expect(copy.expectedSignatureSha256, ['aa']);
    expect(copy.maxClockSkew, const Duration(seconds: 9));
    expect(copy.signals, {AntiVirtualSignal.adb});
  });

  test('channel errors propagate instead of looking clean', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          throw PlatformException(code: 'boom');
        });
    expect(
      FlutterAntiVirtuals.instance.scan(),
      throwsA(isA<PlatformException>()),
    );
  });
}
