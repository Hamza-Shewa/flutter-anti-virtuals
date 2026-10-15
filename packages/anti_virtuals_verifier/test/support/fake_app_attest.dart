import 'dart:convert';
import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:pointycastle/export.dart' as pc;

import 'cbor_writer.dart';
import 'der_writer.dart';
import 'fake_device.dart';

const teamId = 'ABCDE12345';
const bundleId = 'com.example.app';
const appId = '$teamId.$bundleId';

final productionAaguid = Uint8List.fromList([
  ...'appattest'.codeUnits,
  ...List.filled(7, 0),
]);
final developmentAaguid = Uint8List.fromList('appattestdevelop'.codeUnits);

/// Apple's App Attest service in a test: its own root and intermediate, and
/// keys that produce attestations and assertions the way an iPhone does.
final class FakeAppAttest {
  FakeAppAttest({int seed = 3}) : _random = pc.FortunaRandom() {
    _random.seed(pc.KeyParameter(Uint8List.fromList(List.filled(32, seed))));
    _root = TestKey.generate(_random);
    _intermediate = TestKey.generate(_random);
    rootCertificate = testCertificate(
      serial: 1,
      issuer: 'Test App Attestation Root CA',
      subject: 'Test App Attestation Root CA',
      subjectSpki: _root.spki,
      signer: _root,
    );
    intermediateCertificate = testCertificate(
      serial: 2,
      issuer: 'Test App Attestation Root CA',
      subject: 'Test App Attestation CA 1',
      subjectSpki: _intermediate.spki,
      signer: _root,
    );
  }

  final pc.FortunaRandom _random;
  late final TestKey _root;
  late final TestKey _intermediate;
  late final Uint8List rootCertificate;
  late final Uint8List intermediateCertificate;

  /// Pass as `appAttestRoots`.
  List<PublicKey> get roots => [PublicKey.fromSpki(_root.spki)];

  /// A new key, as `DCAppAttestService.generateKey` makes one.
  FakeAppAttestKey newKey() =>
      FakeAppAttestKey._(this, TestKey.generate(_random));
}

final class FakeAppAttestKey {
  FakeAppAttestKey._(this._service, this.key);

  final FakeAppAttest _service;
  final TestKey key;

  /// The counter of the next assertion.
  int counter = 1;

  Uint8List get keyIdBytes => sha256(key.point);

  /// Base64, as `generateKey` returns it.
  String get keyId => base64.encode(keyIdBytes);

  /// The attestation object for [clientDataHash]. The arguments tamper with
  /// one part each.
  Uint8List attestation(
    List<int> clientDataHash, {
    String forAppId = appId,
    int attestationCounter = 0,
    Uint8List? aaguid,
    Uint8List? credentialId,
    List<int>? nonceFor,
    Map<String, Object?>? extensions,
    DateTime? notAfter,
    bool chainToRoot = true,
  }) {
    final authData = authenticatorData(
      forAppId: forAppId,
      counter: attestationCounter,
      aaguid: aaguid ?? productionAaguid,
      credentialId: credentialId ?? keyIdBytes,
      publicKey: key,
      extensions: extensions,
    );
    final nonce = sha256([...authData, ...(nonceFor ?? clientDataHash)]);
    final signer = chainToRoot ? _service._intermediate : key;
    final leaf = testCertificate(
      serial: 3,
      issuer: 'Test App Attestation CA 1',
      subject: _hex(keyIdBytes),
      subjectSpki: key.spki,
      signer: signer,
      notBefore: DateTime.utc(2026),
      notAfter: notAfter ?? DateTime.utc(2027),
      extensions: {
        '1.2.840.113635.100.8.2': DerWriter.sequence([
          DerWriter.explicit(1, DerWriter.octets(nonce)),
        ]),
      },
    );
    return CborWriter.encode({
      'fmt': 'apple-appattest',
      'attStmt': {
        'x5c': [leaf, _service.intermediateCertificate],
        'receipt': Uint8List.fromList(utf8.encode('test receipt')),
      },
      'authData': authData,
    });
  }

  /// The assertion object for [clientDataHash] with the next [counter],
  /// signed by this key or [signWith].
  Uint8List assertion(
    List<int> clientDataHash, {
    int? withCounter,
    String forAppId = appId,
    TestKey? signWith,
    Map<String, Object?>? extensions,
  }) {
    final authData = authenticatorData(
      forAppId: forAppId,
      counter: withCounter ?? counter++,
      extensions: extensions,
    );
    final nonce = sha256([...authData, ...clientDataHash]);
    return CborWriter.encode({
      'signature': (signWith ?? key).sign(nonce),
      'authenticatorData': authData,
    });
  }

  /// The `attestation` map the plugin puts in `SignedReport.toJson()`.
  Map<String, Object?> attestationMap(
    String payload, {
    Uint8List Function(List<int> clientDataHash)? object,
    String? deviceCheckToken,
  }) {
    final hash = sha256(utf8.encode(payload));
    return {
      'type': 'appAttest',
      'token': base64.encode(object?.call(hash) ?? attestation(hash)),
      'keyId': keyId,
      'assertion': false,
      'deviceCheckToken': ?deviceCheckToken,
    };
  }

  Map<String, Object?> assertionMap(
    String payload, {
    Uint8List Function(List<int> clientDataHash)? object,
  }) {
    final hash = sha256(utf8.encode(payload));
    return {
      'type': 'appAttest',
      'token': base64.encode(object?.call(hash) ?? assertion(hash)),
      'keyId': keyId,
      'assertion': true,
    };
  }
}

/// Authenticator data with attested credential data when [publicKey] is
/// given.
Uint8List authenticatorData({
  required String forAppId,
  required int counter,
  Uint8List? aaguid,
  Uint8List? credentialId,
  TestKey? publicKey,
  Map<String, Object?>? extensions,
}) {
  final out = BytesBuilder()
    ..add(sha256(utf8.encode(forAppId)))
    ..addByte((publicKey != null ? 0x40 : 0) | (extensions != null ? 0x80 : 0))
    ..add([
      (counter >> 24) & 0xff,
      (counter >> 16) & 0xff,
      (counter >> 8) & 0xff,
      counter & 0xff,
    ]);
  if (publicKey != null) {
    final point = publicKey.point;
    out
      ..add(aaguid!)
      ..add([credentialId!.length >> 8, credentialId.length & 0xff])
      ..add(credentialId)
      ..add(
        CborWriter.encode({
          1: 2,
          3: -7,
          -1: 1,
          -2: Uint8List.fromList(point.sublist(1, 33)),
          -3: Uint8List.fromList(point.sublist(33)),
        }),
      );
  }
  if (extensions != null) out.add(CborWriter.encode(extensions));
  return out.toBytes();
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
