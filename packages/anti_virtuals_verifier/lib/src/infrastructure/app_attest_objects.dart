import 'dart:typed_data';

import 'cbor.dart';
import 'der.dart';

/// OID of the credential certificate extension that holds the attestation
/// nonce.
const appAttestNonceOid = '1.2.840.113635.100.8.2';

/// `aaguid` of a production App Attest key: `appattest` and seven zero
/// bytes.
final appAttestProductionAaguid = Uint8List.fromList([
  ...'appattest'.codeUnits,
  0, 0, 0, 0, 0, 0, 0, //
]);

/// `aaguid` of a development App Attest key.
final appAttestDevelopmentAaguid = Uint8List.fromList(
  'appattestdevelop'.codeUnits,
);

/// WebAuthn authenticator data, as App Attest uses it.
final class AuthenticatorData {
  AuthenticatorData._({
    required this.bytes,
    required this.rpIdHash,
    required this.flags,
    required this.counter,
    this.aaguid,
    this.credentialId,
    this.credentialPublicKey,
    this.extensions,
  });

  /// Reads [bytes]. Throws [FormatException] when they are malformed.
  factory AuthenticatorData.parse(Uint8List bytes) =>
      parseOrFormatException('authenticator data', () => _parse(bytes));

  static AuthenticatorData _parse(Uint8List bytes) {
    if (bytes.length < 37) {
      throw const FormatException('Authenticator data is too short');
    }
    final flags = bytes[32];
    final counter = ByteData.sublistView(bytes, 33, 37).getUint32(0);
    var offset = 37;
    Uint8List? aaguid;
    Uint8List? credentialId;
    Object? publicKey;
    if (flags & attestedCredentialData != 0) {
      if (bytes.length < offset + 18) {
        throw const FormatException('Authenticator data is too short');
      }
      aaguid = Uint8List.fromList(bytes.sublist(offset, offset + 16));
      final length = (bytes[offset + 16] << 8) | bytes[offset + 17];
      offset += 18;
      if (bytes.length < offset + length) {
        throw const FormatException('Authenticator data is too short');
      }
      credentialId = Uint8List.fromList(bytes.sublist(offset, offset + length));
      offset += length;
      final (key, end) = readCbor(bytes, offset);
      publicKey = key;
      offset = end;
    }
    // Apple's own sample attestation carries the extensions map without
    // setting the ED flag, so trailing bytes are read as extensions too. They
    // only inform (validation category, bundle version): the nonce and the
    // signature cover every byte, so extensions in a format this reader does
    // not know are skipped instead of rejecting a genuine object.
    Map<Object?, Object?>? extensions;
    if (offset < bytes.length) {
      try {
        final (value, end) = readCbor(bytes, offset);
        if (value is Map<Object?, Object?> && end == bytes.length) {
          extensions = value;
        }
      } on Object {
        extensions = null;
      }
    }
    return AuthenticatorData._(
      bytes: bytes,
      rpIdHash: Uint8List.fromList(bytes.sublist(0, 32)),
      flags: flags,
      counter: counter,
      aaguid: aaguid,
      credentialId: credentialId,
      credentialPublicKey: publicKey,
      extensions: extensions,
    );
  }

  /// Flag bit: attested credential data follows the counter.
  static const attestedCredentialData = 0x40;

  /// Flag bit: an extensions map ends the data.
  static const extensionData = 0x80;

  final Uint8List bytes;
  final Uint8List rpIdHash;
  final int flags;
  final int counter;
  final Uint8List? aaguid;
  final Uint8List? credentialId;

  /// The COSE key, decoded.
  final Object? credentialPublicKey;

  final Map<Object?, Object?>? extensions;

  /// `apple_validation_category_01` (attestations) or `validationCategory`
  /// (assertions). Apple's sample encodes it as four little-endian bytes;
  /// a CBOR integer is read too.
  int? get validationCategory => switch (_extension(
    'apple_validation_category_01',
    'validationCategory',
  )) {
    final int value => value,
    final Uint8List bytes when bytes.length == 4 => ByteData.sublistView(
      bytes,
    ).getUint32(0, Endian.little),
    _ => null,
  };

  /// `apple_bundle_version_01` (attestations) or `bundleVersion`
  /// (assertions).
  String? get bundleVersion =>
      switch (_extension('apple_bundle_version_01', 'bundleVersion')) {
        final String value => value,
        _ => null,
      };

  Object? _extension(String name, String alias) =>
      extensions?[name] ?? extensions?[alias];
}

/// The CBOR attestation object App Attest returns for a new key.
final class AttestationObject {
  AttestationObject._(this.certificates, this.receipt, this.authData);

  /// Reads the CBOR. Throws [FormatException] when it is not an
  /// `apple-appattest` attestation.
  factory AttestationObject.parse(Uint8List cbor) =>
      parseOrFormatException('attestation object', () {
        final map = decodeCbor(cbor);
        if (map is! Map<Object?, Object?>) {
          throw const FormatException('The attestation is not a CBOR map');
        }
        if (map['fmt'] != 'apple-appattest') {
          throw FormatException('Unsupported attestation format ${map['fmt']}');
        }
        final statement = map['attStmt'];
        final authData = map['authData'];
        if (statement is! Map<Object?, Object?> || authData is! Uint8List) {
          throw const FormatException('attStmt and authData are required');
        }
        final x5c = statement['x5c'];
        final receipt = statement['receipt'];
        if (x5c is! List ||
            x5c.isEmpty ||
            x5c.any((certificate) => certificate is! Uint8List) ||
            receipt is! Uint8List) {
          throw const FormatException('x5c and receipt are required');
        }
        return AttestationObject._(
          List<Uint8List>.unmodifiable(x5c.cast<Uint8List>()),
          receipt,
          authData,
        );
      });

  /// DER certificates, the credential certificate first.
  final List<Uint8List> certificates;
  final Uint8List receipt;
  final Uint8List authData;
}

/// The CBOR assertion object App Attest returns for an enrolled key.
final class AssertionObject {
  AssertionObject._(this.signature, this.authenticatorData);

  /// Reads the CBOR. Throws [FormatException] when it is not an assertion.
  factory AssertionObject.parse(Uint8List cbor) =>
      parseOrFormatException('assertion object', () {
        final map = decodeCbor(cbor);
        if (map is! Map<Object?, Object?>) {
          throw const FormatException('The assertion is not a CBOR map');
        }
        final signature = map['signature'];
        final authenticatorData = map['authenticatorData'];
        if (signature is! Uint8List || authenticatorData is! Uint8List) {
          throw const FormatException(
            'signature and authenticatorData are required',
          );
        }
        return AssertionObject._(signature, authenticatorData);
      });

  /// DER ECDSA signature over SHA-256 of the nonce.
  final Uint8List signature;
  final Uint8List authenticatorData;
}

/// The nonce in the credential certificate extension: a SEQUENCE holding a
/// `[1]` tagged OCTET STRING.
Uint8List readAppAttestNonce(Uint8List extension) =>
    parseOrFormatException('nonce extension', () {
      for (final element in Der.parse(extension).sequence) {
        if (element.isContext(1)) return element.children.single.octets;
      }
      throw const FormatException('No nonce in the extension');
    });
