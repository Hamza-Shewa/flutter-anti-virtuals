import 'dart:convert';
import 'dart:typed_data';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:pointycastle/export.dart' as pc;

import 'der_writer.dart';
import 'fake_device.dart';

const _signedData = '1.2.840.113549.1.7.2';
const _data = '1.2.840.113549.1.7.1';
const _sha256 = '2.16.840.1.101.3.4.2.1';
const _ecdsaSha256 = '1.2.840.10045.4.3.2';
const _contentType = '1.2.840.113549.1.9.3';
const _messageDigest = '1.2.840.113549.1.9.4';

/// Apple's receipt signing in a test: a root, an intermediate and a signing
/// certificate, and receipts signed as PKCS #7 the way Apple's are.
final class FakeReceiptSigner {
  FakeReceiptSigner({int seed = 5}) : _random = pc.FortunaRandom() {
    _random.seed(pc.KeyParameter(Uint8List.fromList(List.filled(32, seed))));
    _root = TestKey.generate(_random);
    _intermediate = TestKey.generate(_random);
    _signer = TestKey.generate(_random);
    rootCertificate = testCertificate(
      serial: 10,
      issuer: 'Test Root CA - G3',
      subject: 'Test Root CA - G3',
      subjectSpki: _root.spki,
      signer: _root,
    );
    intermediateCertificate = testCertificate(
      serial: 11,
      issuer: 'Test Root CA - G3',
      subject: 'Test Integration CA',
      subjectSpki: _intermediate.spki,
      signer: _root,
    );
    signerCertificate = testCertificate(
      serial: signerSerial,
      issuer: 'Test Integration CA',
      subject: 'Test Fraud Receipt Signing',
      subjectSpki: _signer.spki,
      signer: _intermediate,
      notAfter: DateTime.utc(2027),
    );
  }

  static const signerSerial = 12;

  final pc.FortunaRandom _random;
  late final TestKey _root;
  late final TestKey _intermediate;
  late final TestKey _signer;
  late final Uint8List rootCertificate;
  late final Uint8List intermediateCertificate;
  late final Uint8List signerCertificate;

  List<PublicKey> get roots => [PublicKey.fromSpki(_root.spki)];

  /// A receipt with [fields] (type to UTF-8 text or raw bytes). With
  /// [signedAttributes] the signature covers attributes holding the payload
  /// digest instead of the payload itself.
  Uint8List receipt(
    Map<int, Object> fields, {
    bool signedAttributes = false,
    TestKey? signWith,
  }) {
    final payload = DerWriter.set([
      for (final MapEntry(:key, :value) in fields.entries)
        DerWriter.sequence([
          DerWriter.integer(key),
          DerWriter.integer(1),
          DerWriter.octets(
            value is String ? utf8.encode(value) : value as List<int>,
          ),
        ]),
    ]);
    final attributes = [
      DerWriter.sequence([
        DerWriter.oid(_contentType),
        DerWriter.set([DerWriter.oid(_data)]),
      ]),
      DerWriter.sequence([
        DerWriter.oid(_messageDigest),
        DerWriter.set([DerWriter.octets(sha256(payload))]),
      ]),
    ];
    final signed = signedAttributes ? DerWriter.set(attributes) : payload;
    final signature = (signWith ?? _signer).sign(signed);
    final signerInfo = DerWriter.sequence([
      DerWriter.integer(1),
      DerWriter.sequence([
        testName('Test Integration CA'),
        DerWriter.integer(signerSerial),
      ]),
      DerWriter.sequence([DerWriter.oid(_sha256), DerWriter.nullValue()]),
      if (signedAttributes)
        DerWriter.element(2, true, 0, attributes.expand((a) => a).toList()),
      DerWriter.sequence([DerWriter.oid(_ecdsaSha256)]),
      DerWriter.octets(signature),
    ]);
    return DerWriter.sequence([
      DerWriter.oid(_signedData),
      DerWriter.explicit(
        0,
        DerWriter.sequence([
          DerWriter.integer(1),
          DerWriter.set([
            DerWriter.sequence([DerWriter.oid(_sha256), DerWriter.nullValue()]),
          ]),
          DerWriter.sequence([
            DerWriter.oid(_data),
            DerWriter.explicit(0, DerWriter.octets(payload)),
          ]),
          DerWriter.element(2, true, 0, [
            ...signerCertificate,
            ...intermediateCertificate,
            ...rootCertificate,
          ]),
          DerWriter.set([signerInfo]),
        ]),
      ),
    ]);
  }
}
