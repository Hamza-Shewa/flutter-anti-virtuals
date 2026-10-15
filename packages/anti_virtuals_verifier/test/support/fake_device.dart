import 'dart:convert';
import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:pointycastle/export.dart' as pc;

import 'der_writer.dart';

const _ecPublicKey = '1.2.840.10045.2.1';
const _p256 = '1.2.840.10045.3.1.7';
const _ecdsaSha256 = '1.2.840.10045.4.3.2';
const _keyAttestation = '1.3.6.1.4.1.11129.2.1.17';

const packageName = 'com.example.app';
const signingDigest =
    'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';

/// A P-256 key pair for test certificates and signatures.
final class TestKey {
  TestKey(this.private, this.public);

  factory TestKey.generate(pc.SecureRandom random) {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(pc.ECCurve_secp256r1()),
          random,
        ),
      );
    final pair = generator.generateKeyPair();
    return TestKey(pair.privateKey, pair.publicKey);
  }

  final pc.ECPrivateKey private;
  final pc.ECPublicKey public;

  Uint8List get point => public.Q!.getEncoded(false);

  Uint8List get spki => DerWriter.sequence([
    DerWriter.sequence([DerWriter.oid(_ecPublicKey), DerWriter.oid(_p256)]),
    DerWriter.bitString(point),
  ]);

  /// Deterministic ECDSA (RFC 6979) over SHA-256, DER encoded.
  Uint8List sign(List<int> message) {
    final signer = pc.ECDSASigner(
      pc.SHA256Digest(),
      pc.HMac(pc.SHA256Digest(), 64),
    )..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(private));
    final signature =
        signer.generateSignature(Uint8List.fromList(message)) as pc.ECSignature;
    return DerWriter.sequence([
      DerWriter.integer(signature.r),
      DerWriter.integer(signature.s),
    ]);
  }
}

Uint8List testName(String commonName) => DerWriter.sequence([
  DerWriter.set([
    DerWriter.sequence([
      DerWriter.oid('2.5.4.3'),
      DerWriter.utf8String(commonName),
    ]),
  ]),
]);

/// A certificate signed by [signer] with ECDSA SHA-256.
Uint8List testCertificate({
  required int serial,
  required String issuer,
  required String subject,
  required Uint8List subjectSpki,
  required TestKey signer,
  Map<String, Uint8List> extensions = const {},
  DateTime? notBefore,
  DateTime? notAfter,
}) {
  final tbs = DerWriter.sequence([
    DerWriter.explicit(0, DerWriter.integer(2)),
    DerWriter.integer(serial),
    DerWriter.sequence([DerWriter.oid(_ecdsaSha256)]),
    testName(issuer),
    DerWriter.sequence([
      DerWriter.utcTime(notBefore ?? DateTime.utc(2020)),
      DerWriter.utcTime(notAfter ?? DateTime.utc(2048)),
    ]),
    testName(subject),
    subjectSpki,
    if (extensions.isNotEmpty)
      DerWriter.explicit(
        3,
        DerWriter.sequence([
          for (final MapEntry(:key, :value) in extensions.entries)
            DerWriter.sequence([DerWriter.oid(key), DerWriter.octets(value)]),
        ]),
      ),
  ]);
  return DerWriter.sequence([
    tbs,
    DerWriter.sequence([DerWriter.oid(_ecdsaSha256)]),
    DerWriter.bitString(signer.sign(tbs)),
  ]);
}

/// The KeyDescription a real device writes, with the fields that matter
/// configurable and a few others filled in the way devices do.
Uint8List keyDescription({
  required List<int> challenge,
  int securityLevel = 1,
  String package = packageName,
  String digest = signingDigest,
  int bootState = 0,
  bool locked = true,
  int patchLevel = 202409,
}) {
  final applicationId = DerWriter.sequence([
    DerWriter.set([
      DerWriter.sequence([
        DerWriter.octets(utf8.encode(package)),
        DerWriter.integer(42),
      ]),
    ]),
    DerWriter.set([DerWriter.octets(_hexBytes(digest))]),
  ]);
  return DerWriter.sequence([
    DerWriter.integer(300),
    DerWriter.enumerated(securityLevel),
    DerWriter.integer(300),
    DerWriter.enumerated(securityLevel),
    DerWriter.octets(challenge),
    DerWriter.octets(const []),
    DerWriter.sequence([
      DerWriter.explicit(701, DerWriter.integer(1700000000000)),
      DerWriter.explicit(709, DerWriter.octets(applicationId)),
    ]),
    DerWriter.sequence([
      DerWriter.explicit(1, DerWriter.set([DerWriter.integer(2)])),
      DerWriter.explicit(2, DerWriter.integer(3)),
      DerWriter.explicit(503, DerWriter.nullValue()),
      DerWriter.explicit(
        704,
        DerWriter.sequence([
          DerWriter.octets(List.filled(32, 7)),
          DerWriter.boolean(locked),
          DerWriter.enumerated(bootState),
          DerWriter.octets(List.filled(32, 9)),
        ]),
      ),
      DerWriter.explicit(705, DerWriter.integer(140000)),
      DerWriter.explicit(706, DerWriter.integer(patchLevel)),
    ]),
  ]);
}

Uint8List _hexBytes(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

/// A device with an attestation chain under its own test root.
final class FakeDevice {
  FakeDevice({int seed = 1}) : _random = pc.FortunaRandom() {
    _random.seed(pc.KeyParameter(Uint8List.fromList(List.filled(32, seed))));
    _root = TestKey.generate(_random);
    _intermediate = TestKey.generate(_random);
    rootCertificate = testCertificate(
      serial: 1,
      issuer: 'Test Root',
      subject: 'Test Root',
      subjectSpki: _root.spki,
      signer: _root,
    );
    intermediateCertificate = testCertificate(
      serial: 0x2c8cdddfd5e03bfc,
      issuer: 'Test Root',
      subject: 'Test Intermediate',
      subjectSpki: _intermediate.spki,
      signer: _root,
    );
  }

  final pc.FortunaRandom _random;
  late final TestKey _root;
  late final TestKey _intermediate;
  late final Uint8List rootCertificate;
  late final Uint8List intermediateCertificate;

  /// Trust anchors to pass as `trustedRoots`.
  List<PublicKey> get roots => [PublicKey.fromSpki(_root.spki)];

  /// The JSON `SignedReport.toJson()` produces on Android. The arguments
  /// tamper with one part each.
  Map<String, Object?> androidReport({
    required String nonce,
    required DateTime issuedAt,
    Map<String, Object?> signals = const {
      'vpn': {'detected': false, 'supported': true},
    },
    Uint8List? description,
    bool withChain = true,
    bool attestOtherKey = false,
    Map<String, Object?>? attestation,
  }) {
    final key = TestKey.generate(_random);
    final attestedKey = attestOtherKey ? TestKey.generate(_random) : key;
    final payload = payloadText(nonce, issuedAt, 'android', signals);
    final leaf = testCertificate(
      serial: 3,
      issuer: 'Test Intermediate',
      subject: 'Android Keystore Key',
      subjectSpki: attestedKey.spki,
      signer: _intermediate,
      extensions: {
        _keyAttestation:
            description ??
            keyDescription(challenge: sha256(utf8.encode(nonce))),
      },
    );
    return {
      'payload': payload,
      'signature': base64.encode(key.sign(utf8.encode(payload))),
      'algorithm': 'SHA256withECDSA',
      'publicKey': base64.encode(key.spki),
      'protection': 'hardware',
      'attested': withChain,
      'certificateChain': withChain
          ? [
              for (final der in [
                leaf,
                intermediateCertificate,
                rootCertificate,
              ])
                base64.encode(der),
            ]
          : <String>[],
      'attestation': ?attestation,
    };
  }

  /// The JSON an iPhone sends: a raw P-256 point and no chain. [attestation]
  /// builds the App Attest map from the payload.
  Map<String, Object?> iosReport({
    required String nonce,
    required DateTime issuedAt,
    Map<String, Object?>? Function(String payload)? attestation,
  }) {
    final key = TestKey.generate(_random);
    final payload = payloadText(nonce, issuedAt, 'iOS', const {
      'vpn': {'detected': false, 'supported': true},
    });
    final appAttest = attestation?.call(payload);
    return {
      'payload': payload,
      'signature': base64.encode(key.sign(utf8.encode(payload))),
      'algorithm': 'SHA256withECDSA',
      'publicKey': base64.encode(key.point),
      'protection': 'hardware',
      'attested': false,
      'certificateChain': <String>[],
      'attestation': ?appAttest,
    };
  }
}

String payloadText(
  String nonce,
  DateTime issuedAt,
  String platform,
  Map<String, Object?> signals,
) => jsonEncode({
  'v': 1,
  'nonce': nonce,
  'issuedAt': issuedAt.millisecondsSinceEpoch,
  'platform': platform,
  'signals': signals,
});

Uint8List sha256(List<int> bytes) =>
    pc.SHA256Digest().process(Uint8List.fromList(bytes));
