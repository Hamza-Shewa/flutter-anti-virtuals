import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'der.dart';
import 'public_key.dart';

/// Makes the ES256 JSON Web Tokens that Apple's DeviceCheck and App Attest
/// servers expect, from a `.p8` key you create in your developer account
/// with the DeviceCheck service enabled.
///
/// The header holds `alg: ES256` and `kid`, the claims hold `iss` (your Team
/// ID) and `iat`. Apple rejects tokens whose `iat` is more than an hour old,
/// so [token] makes a new one when the cached one is older than [reuseFor].
/// Signatures are deterministic (RFC 6979), so no random source is needed.
final class AppleJwtSigner {
  /// [privateKeyPem] is the content of the `.p8` file (PKCS #8,
  /// `BEGIN PRIVATE KEY`). A SEC1 `BEGIN EC PRIVATE KEY` is accepted too.
  /// Throws [FormatException] when it is not a P-256 private key.
  factory AppleJwtSigner({
    required String teamId,
    required String keyId,
    required String privateKeyPem,
    Duration reuseFor = const Duration(minutes: 30),
    DateTime Function()? clock,
  }) => AppleJwtSigner._(
    teamId,
    keyId,
    parseOrFormatException('private key', () => _parsePem(privateKeyPem)),
    reuseFor,
    clock ?? DateTime.now,
  );

  AppleJwtSigner._(
    this.teamId,
    this.keyId,
    this._d,
    this.reuseFor,
    this._clock,
  );

  /// Your 10 character Team ID, sent as `iss`.
  final String teamId;

  /// The 10 character Key ID of the `.p8` key, sent as `kid`.
  final String keyId;

  /// How long [token] returns the same token. Keep it under an hour.
  final Duration reuseFor;

  final BigInt _d;
  final DateTime Function() _clock;
  String? _cached;
  DateTime? _cachedAt;

  static final _domain = pc.ECCurve_secp256r1();

  /// The public key of the signing key, to check tokens.
  EcPublicKey get publicKey =>
      EcPublicKey(Oids.p256, (_domain.G * _d)!.getEncoded(false));

  /// A token for the `Authorization` header, reused for [reuseFor].
  String token() {
    final now = _clock();
    final cachedAt = _cachedAt;
    if (_cached != null &&
        cachedAt != null &&
        now.difference(cachedAt) < reuseFor &&
        !now.isBefore(cachedAt)) {
      return _cached!;
    }
    _cachedAt = now;
    return _cached = sign(issuedAt: now);
  }

  /// A new token issued at [issuedAt] (now by default).
  String sign({DateTime? issuedAt}) {
    final iat = (issuedAt ?? _clock()).millisecondsSinceEpoch ~/ 1000;
    final header = _encode({'alg': 'ES256', 'kid': keyId});
    final claims = _encode({'iss': teamId, 'iat': iat});
    final input = '$header.$claims';
    final signer = pc.ECDSASigner(
      pc.SHA256Digest(),
      pc.HMac(pc.SHA256Digest(), 64),
    )..init(true, pc.PrivateKeyParameter(pc.ECPrivateKey(_d, _domain)));
    final signature =
        signer.generateSignature(Uint8List.fromList(utf8.encode(input)))
            as pc.ECSignature;
    final raw = Uint8List(64)
      ..setRange(0, 32, _fixed(signature.r))
      ..setRange(32, 64, _fixed(signature.s));
    return '$input.${_base64Url(raw)}';
  }

  static String _encode(Map<String, Object?> json) =>
      _base64Url(utf8.encode(jsonEncode(json)));

  static String _base64Url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static Uint8List _fixed(BigInt value) {
    final out = Uint8List(32);
    var v = value;
    for (var i = 31; i >= 0; i--) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v >>= 8;
    }
    return out;
  }

  static BigInt _parsePem(String pem) {
    final match = RegExp(
      r'-----BEGIN (EC )?PRIVATE KEY-----([^-]+)-----END (EC )?PRIVATE KEY-----',
    ).firstMatch(pem);
    if (match == null) {
      throw const FormatException('Expected a PEM PRIVATE KEY');
    }
    final der = base64.decode(match[2]!.replaceAll(RegExp(r'\s'), ''));
    final parts = Der.parse(der).sequence;
    final List<Der> ecPrivateKey;
    if (match[1] == null) {
      // PKCS #8 PrivateKeyInfo: version, algorithm, privateKey.
      final algorithm = parts[1].sequence;
      if (algorithm[0].oid != Oids.ecPublicKey ||
          algorithm[1].oid != Oids.p256) {
        throw const FormatException('Not a P-256 key');
      }
      ecPrivateKey = Der.parse(parts[2].octets).sequence;
    } else {
      ecPrivateKey = parts;
      for (final field in parts.skip(2)) {
        if (field.isContext(0) && field.children.single.oid != Oids.p256) {
          throw const FormatException('Not a P-256 key');
        }
      }
    }
    final d = unsignedBigInt(ecPrivateKey[1].octets);
    if (d <= BigInt.zero || d >= _domain.n) {
      throw const FormatException('Invalid private key');
    }
    return d;
  }
}
