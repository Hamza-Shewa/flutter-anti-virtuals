import 'dart:convert';

import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';

class _Platform extends FlutterAntiVirtualsPlatform {
  final List<(String, String)> signed = [];
  Object? signError;

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async =>
      const AntiVirtualReport({
        AntiVirtualSignal.vpn: SignalResult(
          detected: true,
          supported: true,
          details: ['tun0'],
        ),
        AntiVirtualSignal.rooted: SignalResult.unsupported(),
      });

  @override
  Future<DeviceSignature> signPayload(String nonce, String payload) async {
    if (signError != null) throw signError!;
    signed.add((nonce, payload));
    return const DeviceSignature(
      signature: 'c2ln',
      publicKey: 'a2V5',
      algorithm: 'SHA256withECDSA',
      protection: KeyProtection.hardware,
      attested: true,
      certificateChain: ['Y2VydDE=', 'Y2VydDI='],
    );
  }
}

void main() {
  late _Platform platform;
  const nonce = 'nonce-from-the-backend-0001';

  setUp(() {
    platform = _Platform();
    FlutterAntiVirtualsPlatform.instance = platform;
  });

  test('signs a payload that carries the nonce and the scan', () async {
    final before = DateTime.now().toUtc().millisecondsSinceEpoch;
    final signed = await FlutterAntiVirtuals.instance.verify(nonce: nonce);

    expect(platform.signed, hasLength(1));
    expect(platform.signed.single.$1, nonce);
    expect(platform.signed.single.$2, signed.payload);

    final payload = jsonDecode(signed.payload) as Map<String, Object?>;
    expect(payload['v'], 1);
    expect(payload['nonce'], nonce);
    expect(payload['issuedAt'] as int, greaterThanOrEqualTo(before));
    expect(payload['platform'], signed.platform);
    expect(payload['signals'], {
      'vpn': {'detected': true, 'supported': true},
      'rooted': {'detected': false, 'supported': false},
    });
    // The localized and device-specific details are not part of the signature.
    expect(signed.payload, isNot(contains('tun0')));
    expect(signed.report.isDetected(AntiVirtualSignal.vpn), isTrue);
  });

  test('toJson is what a backend needs to verify it', () async {
    final json = (await FlutterAntiVirtuals.instance.verify(
      nonce: nonce,
    )).toJson();

    expect(json['signature'], 'c2ln');
    expect(json['publicKey'], 'a2V5');
    expect(json['algorithm'], 'SHA256withECDSA');
    expect(json['protection'], 'hardware');
    expect(json['attested'], isTrue);
    expect(json['certificateChain'], ['Y2VydDE=', 'Y2VydDI=']);
    expect(jsonDecode(json['payload']! as String), isA<Map<String, Object?>>());
  });

  test('refuses a short nonce before scanning or signing', () {
    expect(
      () => FlutterAntiVirtuals.instance.verify(nonce: 'short'),
      throwsArgumentError,
    );
    expect(platform.signed, isEmpty);
  });

  test('a signing failure is an error, not an unsigned report', () {
    platform.signError = StateError('no key');
    expect(
      () => FlutterAntiVirtuals.instance.verify(nonce: nonce),
      throwsStateError,
    );
  });

  test('device signatures decode unknown protection as software', () {
    final signature = DeviceSignature.fromMap(<Object?, Object?>{
      'signature': 'a',
      'publicKey': 'b',
      'algorithm': 'c',
      'protection': 'something-new',
    });
    expect(signature.protection, KeyProtection.software);
    expect(signature.attested, isFalse);
    expect(signature.certificateChain, isEmpty);
  });
}
