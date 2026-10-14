import 'dart:convert';
import 'dart:typed_data';

import 'der.dart';
import 'public_key.dart';

/// The parts of an X.509 certificate that chain checks need.
final class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbs,
    required this.serialNumber,
    required this.notBefore,
    required this.notAfter,
    required this.publicKey,
    required this.signatureAlgorithm,
    required this.signature,
    required this.extensions,
  });

  /// Parses a DER certificate. Throws [FormatException] when it is not one.
  factory X509Certificate.fromDer(Uint8List der) =>
      parseOrFormatException('certificate', () => X509Certificate._parse(der));

  factory X509Certificate._parse(Uint8List der) {
    final certificate = Der.parse(der).sequence;
    if (certificate.length != 3) {
      throw const FormatException('A certificate has three parts');
    }
    final tbs = certificate[0];
    final fields = tbs.sequence;
    // version [0] EXPLICIT is optional; everything after it is positional.
    var i = fields.first.isContext(0) ? 1 : 0;
    final serial = fields[i++].integer;
    i++; // signature algorithm, repeated below the TBS part
    i++; // issuer
    final validity = fields[i++].sequence;
    i++; // subject
    final spki = fields[i++];
    final extensions = <String, Uint8List>{};
    for (final field in fields.skip(i)) {
      if (!field.isContext(3)) continue;
      for (final extension in field.children.single.sequence) {
        final parts = extension.sequence;
        extensions[parts.first.oid] = parts.last.octets;
      }
    }
    return X509Certificate._(
      der: der,
      tbs: tbs.encoded,
      serialNumber: serial,
      notBefore: validity[0].time,
      notAfter: validity[1].time,
      publicKey: PublicKey.fromSpki(spki.encoded),
      signatureAlgorithm: certificate[1].sequence.first.oid,
      signature: certificate[2].bits,
      extensions: Map.unmodifiable(extensions),
    );
  }

  /// Parses one certificate in PEM form.
  factory X509Certificate.fromPem(String pem) {
    final body = pem
        .replaceAll(RegExp(r'-----(BEGIN|END) CERTIFICATE-----'), '')
        .replaceAll(RegExp(r'\s'), '');
    return X509Certificate.fromDer(base64.decode(body));
  }

  final Uint8List der;
  final Uint8List tbs;
  final BigInt serialNumber;
  final DateTime notBefore;
  final DateTime notAfter;
  final PublicKey publicKey;
  final String signatureAlgorithm;
  final Uint8List signature;

  /// Extension values (the content of `extnValue`) by OID.
  final Map<String, Uint8List> extensions;

  bool isSignedBy(PublicKey issuer) =>
      issuer.verify(signatureAlgorithm, tbs, signature);

  bool isValidAt(DateTime time) =>
      !time.isBefore(notBefore) && !time.isAfter(notAfter);
}
