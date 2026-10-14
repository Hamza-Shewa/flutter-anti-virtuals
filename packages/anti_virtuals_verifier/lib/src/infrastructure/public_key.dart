import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'der.dart';

/// Object identifiers used below.
abstract final class Oids {
  static const ecPublicKey = '1.2.840.10045.2.1';
  static const rsaEncryption = '1.2.840.113549.1.1.1';
  static const p256 = '1.2.840.10045.3.1.7';
  static const p384 = '1.3.132.0.34';
  static const ecdsaSha256 = '1.2.840.10045.4.3.2';
  static const ecdsaSha384 = '1.2.840.10045.4.3.3';
  static const ecdsaSha512 = '1.2.840.10045.4.3.4';
  static const rsaSha256 = '1.2.840.113549.1.1.11';
  static const rsaSha384 = '1.2.840.113549.1.1.12';
  static const rsaSha512 = '1.2.840.113549.1.1.13';
}

/// A public key that can check signatures: EC (P-256, P-384) or RSA.
sealed class PublicKey {
  const PublicKey();

  /// Reads an X.509 SubjectPublicKeyInfo.
  factory PublicKey.fromSpki(Uint8List spki) =>
      parseOrFormatException('public key', () => PublicKey._parseSpki(spki));

  factory PublicKey._parseSpki(Uint8List spki) {
    final parts = Der.parse(spki).sequence;
    final algorithm = parts[0].sequence;
    final key = parts[1].bits;
    switch (algorithm[0].oid) {
      case Oids.ecPublicKey:
        return EcPublicKey(algorithm[1].oid, key);
      case Oids.rsaEncryption:
        final numbers = Der.parse(key).sequence;
        return RsaPublicKey(numbers[0].integer, numbers[1].integer);
      case final other:
        throw FormatException('Unsupported public key algorithm $other');
    }
  }

  /// Reads the public key the plugin sends: a SubjectPublicKeyInfo (Android)
  /// or an uncompressed P-256 point (iOS).
  factory PublicKey.fromDevice(Uint8List bytes) =>
      bytes.length == 65 && bytes[0] == 0x04
      ? EcPublicKey(Oids.p256, bytes)
      : PublicKey.fromSpki(bytes);

  /// Checks [signature] over [message] for the X.509 signature algorithm
  /// [algorithmOid]. False for a wrong signature, a malformed one, or an
  /// algorithm that does not fit this key.
  bool verify(String algorithmOid, Uint8List message, Uint8List signature);
}

final class EcPublicKey extends PublicKey {
  EcPublicKey(this.curveOid, Uint8List point)
    : point = Uint8List.fromList(point) {
    if (point.isEmpty || point[0] != 0x04) {
      throw const FormatException('Only uncompressed EC points are supported');
    }
    _domain; // Rejects an unknown curve now rather than at verification.
  }

  final String curveOid;

  /// Uncompressed point: 0x04 || X || Y.
  final Uint8List point;

  pc.ECDomainParameters get _domain => switch (curveOid) {
    Oids.p256 => pc.ECCurve_secp256r1(),
    Oids.p384 => pc.ECCurve_secp384r1(),
    _ => throw FormatException('Unsupported EC curve $curveOid'),
  };

  @override
  bool verify(String algorithmOid, Uint8List message, Uint8List signature) {
    final digest = switch (algorithmOid) {
      Oids.ecdsaSha256 => pc.SHA256Digest(),
      Oids.ecdsaSha384 => pc.SHA384Digest(),
      Oids.ecdsaSha512 => pc.SHA512Digest(),
      _ => null,
    };
    if (digest == null) return false;
    try {
      final rs = Der.parse(signature).sequence;
      if (rs.length != 2) return false;
      final domain = _domain;
      final q = domain.curve.decodePoint(point);
      if (q == null) return false;
      final signer = pc.ECDSASigner(digest)
        ..init(false, pc.PublicKeyParameter(pc.ECPublicKey(q, domain)));
      return signer.verifySignature(
        message,
        pc.ECSignature(rs[0].integer, rs[1].integer),
      );
    } on Object {
      return false;
    }
  }

  @override
  bool operator ==(Object other) =>
      other is EcPublicKey &&
      other.curveOid == curveOid &&
      _sameBytes(other.point, point);

  @override
  int get hashCode => Object.hash(curveOid, Object.hashAll(point));
}

final class RsaPublicKey extends PublicKey {
  const RsaPublicKey(this.modulus, this.exponent);

  final BigInt modulus;
  final BigInt exponent;

  @override
  bool verify(String algorithmOid, Uint8List message, Uint8List signature) {
    final (digest, identifier) = switch (algorithmOid) {
      Oids.rsaSha256 => (pc.SHA256Digest(), '0609608648016503040201'),
      Oids.rsaSha384 => (pc.SHA384Digest(), '0609608648016503040202'),
      Oids.rsaSha512 => (pc.SHA512Digest(), '0609608648016503040203'),
      _ => (null, ''),
    };
    if (digest == null) return false;
    try {
      final signer = pc.RSASigner(digest, identifier)
        ..init(
          false,
          pc.PublicKeyParameter<pc.RSAPublicKey>(
            pc.RSAPublicKey(modulus, exponent),
          ),
        );
      return signer.verifySignature(message, pc.RSASignature(signature));
    } on Object {
      return false;
    }
  }

  @override
  bool operator ==(Object other) =>
      other is RsaPublicKey &&
      other.modulus == modulus &&
      other.exponent == exponent;

  @override
  int get hashCode => Object.hash(modulus, exponent);
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// SHA-256 of [bytes].
Uint8List sha256(List<int> bytes) =>
    pc.SHA256Digest().process(Uint8List.fromList(bytes));
