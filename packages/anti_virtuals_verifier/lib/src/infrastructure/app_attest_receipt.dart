import 'dart:convert';
import 'dart:typed_data';

import '../domain/app_attest.dart';
import 'apple_roots.dart';
import 'der.dart';
import 'public_key.dart';
import 'x509.dart';

/// An App Attest receipt that cannot be read or does not verify.
final class InvalidReceiptException implements Exception {
  const InvalidReceiptException(this.message);

  final String message;

  @override
  String toString() => 'InvalidReceiptException: $message';
}

/// Checks and reads App Attest receipts: the one inside an attestation and
/// the ones `AppAttestReceiptClient` gets from Apple.
///
/// [read] verifies the PKCS #7 signature over the payload, that the signing
/// certificate chains to Apple Root CA - G3 (embedded, see [AppleRoots]),
/// and that each certificate in that chain is within its validity dates.
/// It does not check revocation (Apple publishes OCSP for these
/// certificates) and it does not check which service the signing
/// certificate was issued for: any certificate under Apple Root CA - G3 that
/// signs a well formed receipt is accepted.
final class AppAttestReceiptReader {
  AppAttestReceiptReader({
    List<PublicKey>? trustedRoots,
    DateTime Function()? clock,
  }) : _roots = trustedRoots ?? AppleRoots.receiptKeys,
       _clock = clock ?? DateTime.now;

  final List<PublicKey> _roots;
  final DateTime Function() _clock;

  static const _signedData = '1.2.840.113549.1.7.2';
  static const _data = '1.2.840.113549.1.7.1';
  static const _sha256 = '2.16.840.1.101.3.4.2.1';
  static const _messageDigest = '1.2.840.113549.1.9.4';

  /// Verifies [receipt] and reads its payload. Then, for the arguments you
  /// pass: field 2 must be [appId], the key in field 3 must be [publicKey]
  /// (an uncompressed P-256 point, as `AppAttestKey.publicKey`), and field
  /// 12 may be at most [maxAge] old, as Apple's "Assessing fraud risk"
  /// asks. Throws [InvalidReceiptException] otherwise.
  AppAttestReceipt read(
    Uint8List receipt, {
    String? appId,
    Uint8List? publicKey,
    Duration? maxAge,
  }) {
    final AppAttestReceipt parsed;
    try {
      parsed = _read(receipt);
    } on InvalidReceiptException {
      rethrow;
    } on Object catch (e) {
      throw InvalidReceiptException(
        'Malformed receipt (${e is FormatException ? e.message : e})',
      );
    }
    if (appId != null && parsed.appId != appId) {
      throw InvalidReceiptException('The receipt is for ${parsed.appId}');
    }
    final attested = parsed.attestedPublicKey;
    if (publicKey != null &&
        (attested == null || !_sameBytes(attested, publicKey))) {
      throw const InvalidReceiptException(
        'The receipt is for another public key',
      );
    }
    if (maxAge != null &&
        _clock().toUtc().difference(parsed.createdAt) > maxAge) {
      throw InvalidReceiptException(
        'The receipt was created at ${parsed.createdAt.toIso8601String()}',
      );
    }
    return parsed;
  }

  AppAttestReceipt _read(Uint8List receipt) {
    final contentInfo = _Ber.parse(receipt).children;
    if (contentInfo.length < 2 || _Ber.oidOf(contentInfo[0]) != _signedData) {
      throw const InvalidReceiptException('Not PKCS #7 signed data');
    }
    final signedData = contentInfo[1].children.single.children;
    var i = 1; // version
    i++; // digestAlgorithms
    final encapsulated = signedData[i++].children;
    if (_Ber.oidOf(encapsulated[0]) != _data || encapsulated.length < 2) {
      throw const InvalidReceiptException('No receipt payload');
    }
    final payload = encapsulated[1].children.single.octets;
    final certificates = <X509Certificate>[];
    if (signedData[i].tagClass == _Ber.contextSpecific &&
        signedData[i].tag == 0) {
      for (final certificate in signedData[i++].children) {
        certificates.add(X509Certificate.fromDer(certificate.encoded));
      }
    }
    if (signedData[i].tagClass == _Ber.contextSpecific &&
        signedData[i].tag == 1) {
      i++; // crls
    }
    final signerInfos = signedData[i].children;
    if (signerInfos.length != 1) {
      throw const InvalidReceiptException('Expected one signer');
    }
    _verifySignature(signerInfos.single.children, payload, certificates);
    return _payload(receipt, payload);
  }

  void _verifySignature(
    List<_Ber> signer,
    Uint8List payload,
    List<X509Certificate> certificates,
  ) {
    var i = 1; // version
    final identifier = signer[i++];
    final digestAlgorithm = _Ber.oidOf(signer[i++].children.first);
    _Ber? signedAttributes;
    if (signer[i].tagClass == _Ber.contextSpecific && signer[i].tag == 0) {
      signedAttributes = signer[i++];
    }
    final signatureAlgorithm = _Ber.oidOf(signer[i++].children.first);
    final signature = signer[i].octets;

    if (digestAlgorithm != _sha256 ||
        (signatureAlgorithm != Oids.ecdsaSha256 &&
            signatureAlgorithm != Oids.ecPublicKey)) {
      throw InvalidReceiptException(
        'Unsupported algorithms $digestAlgorithm, $signatureAlgorithm',
      );
    }
    // IssuerAndSerialNumber; the chain check below proves the issuer.
    final serial = Der.parse(identifier.children.last.encoded).integer;
    final signerCertificate = certificates
        .where((c) => c.serialNumber == serial)
        .firstOrNull;
    if (signerCertificate == null) {
      throw const InvalidReceiptException('No signer certificate');
    }

    final Uint8List signed;
    if (signedAttributes == null) {
      signed = payload;
    } else {
      // The signature covers the attributes encoded as a SET.
      signed = Uint8List.fromList(signedAttributes.encoded)..[0] = 0x31;
      final digest = signedAttributes.children
          .where((a) => _Ber.oidOf(a.children.first) == _messageDigest)
          .map((a) => a.children[1].children.single.octets)
          .firstOrNull;
      if (digest == null || !_sameBytes(digest, sha256(payload))) {
        throw const InvalidReceiptException('The payload digest differs');
      }
    }
    if (!signerCertificate.publicKey.verify(
      Oids.ecdsaSha256,
      signed,
      signature,
    )) {
      throw const InvalidReceiptException('The signature does not verify');
    }
    _verifyChain(signerCertificate, certificates);
  }

  void _verifyChain(X509Certificate signer, List<X509Certificate> pool) {
    final now = _clock().toUtc();
    var current = signer;
    for (var depth = 0; depth < 4; depth++) {
      if (!current.isValidAt(now)) {
        throw const InvalidReceiptException('A certificate is out of date');
      }
      if (_roots.contains(current.publicKey) ||
          _roots.any(current.isSignedBy)) {
        return;
      }
      final issuer = pool
          .where(
            (c) => !identical(c, current) && current.isSignedBy(c.publicKey),
          )
          .firstOrNull;
      if (issuer == null) break;
      current = issuer;
    }
    throw const InvalidReceiptException(
      'The signer does not chain to an Apple root',
    );
  }

  static AppAttestReceipt _payload(Uint8List receipt, Uint8List payload) {
    final fields = <int, Uint8List>{};
    for (final attribute in Der.parse(payload).set) {
      final parts = attribute.sequence;
      fields[parts[0].integer.toInt()] = Uint8List.fromList(parts[2].octets);
    }
    String? text(int type) =>
        fields[type] == null ? null : utf8.decode(fields[type]!);
    DateTime? time(int type) =>
        text(type) == null ? null : DateTime.parse(text(type)!).toUtc();

    final appId = text(2);
    final type = AppAttestReceiptType.parse(text(6));
    final createdAt = time(12);
    if (appId == null || type == null || createdAt == null) {
      throw const InvalidReceiptException('Fields 2, 6 and 12 are required');
    }
    final certificate = fields[3];
    Uint8List? attestedKey;
    if (certificate != null) {
      final key = X509Certificate.fromDer(certificate).publicKey;
      if (key is EcPublicKey) attestedKey = key.point;
    }
    return AppAttestReceipt(
      bytes: receipt,
      appId: appId,
      type: type,
      createdAt: createdAt,
      fields: fields,
      attestedCertificate: certificate,
      attestedPublicKey: attestedKey,
      clientHash: fields[4],
      token: text(5),
      riskMetric: int.tryParse(text(17) ?? ''),
      notBefore: time(19),
      expiresAt: time(21),
    );
  }
}

/// A BER element. Unlike [Der] it accepts indefinite lengths and string
/// types split into chunks, which Apple's receipts use.
final class _Ber {
  _Ber._(this.tagClass, this.constructed, this.tag, this.encoded, this._body);

  static const contextSpecific = 2;
  static const _maxDepth = 16;

  factory _Ber.parse(Uint8List data) {
    final (element, end) = _read(data, 0, 0);
    if (end != data.length) {
      throw const FormatException('Trailing bytes after the receipt');
    }
    return element;
  }

  static (_Ber, int) _read(Uint8List data, int offset, int depth) {
    if (depth > _maxDepth) throw const FormatException('BER nested too deep');
    var i = offset;
    int next() {
      if (i >= data.length) throw const FormatException('Truncated BER');
      return data[i++];
    }

    final first = next();
    final constructed = first & 0x20 != 0;
    var tag = first & 0x1f;
    if (tag == 0x1f) {
      tag = 0;
      int b;
      do {
        b = next();
        tag = (tag << 7) | (b & 0x7f);
        if (tag > 0x1fffff) throw const FormatException('BER tag too large');
      } while (b & 0x80 != 0);
    }
    final lengthByte = next();
    final children = <_Ber>[];
    int end;
    Uint8List? body;
    if (lengthByte == 0x80) {
      if (!constructed) {
        throw const FormatException('Indefinite length on a primitive');
      }
      while (true) {
        if (i + 1 < data.length && data[i] == 0 && data[i + 1] == 0) {
          i += 2;
          break;
        }
        final (child, childEnd) = _read(data, i, depth + 1);
        children.add(child);
        i = childEnd;
      }
      end = i;
    } else {
      var length = lengthByte;
      if (lengthByte > 0x80) {
        final count = lengthByte & 0x7f;
        if (count > 4) throw const FormatException('BER length too large');
        length = 0;
        for (var n = 0; n < count; n++) {
          length = (length << 8) | next();
        }
      }
      end = i + length;
      if (end > data.length) throw const FormatException('Truncated BER');
      if (constructed) {
        var j = i;
        while (j < end) {
          final (child, childEnd) = _read(data, j, depth + 1);
          if (childEnd > end) {
            throw const FormatException('BER child overruns its parent');
          }
          children.add(child);
          j = childEnd;
        }
      } else {
        body = Uint8List.sublistView(data, i, end);
      }
    }
    return (
      _Ber._(
        first >> 6,
        constructed,
        tag,
        Uint8List.sublistView(data, offset, end),
        constructed ? List<_Ber>.unmodifiable(children) : body,
      ),
      end,
    );
  }

  final int tagClass;
  final bool constructed;
  final int tag;

  /// The whole encoding, header included.
  final Uint8List encoded;

  /// Children of a constructed element, or the content of a primitive one.
  final Object? _body;

  List<_Ber> get children {
    final body = _body;
    if (body is List<_Ber>) return body;
    throw const FormatException('Not a constructed BER element');
  }

  /// The content of an OCTET STRING, joining the chunks of a constructed
  /// one.
  Uint8List get octets {
    if (tagClass != 0 || tag != Der.tagOctetString) {
      throw const FormatException('Expected an OCTET STRING');
    }
    final body = _body;
    if (body is Uint8List) return body;
    final out = BytesBuilder(copy: false);
    for (final chunk in children) {
      out.add(chunk.octets);
    }
    return out.takeBytes();
  }

  static String oidOf(_Ber element) => Der.parse(element.encoded).oid;
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
