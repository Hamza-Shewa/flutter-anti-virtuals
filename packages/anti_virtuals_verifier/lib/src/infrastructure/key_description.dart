import 'dart:typed_data';

import '../domain/key_attestation.dart';
import 'der.dart';

/// OID of the Android key attestation extension.
const keyAttestationOid = '1.3.6.1.4.1.11129.2.1.17';

// AuthorizationList tags used here.
const _rootOfTrust = 704;
const _osVersion = 705;
const _osPatchLevel = 706;
const _attestationApplicationId = 709;

/// Reads the KeyDescription in the key attestation extension.
///
/// See https://source.android.com/docs/security/features/keystore/attestation
KeyAttestation parseKeyDescription(Uint8List extension) =>
    parseOrFormatException('key description', () => _parse(extension));

KeyAttestation _parse(Uint8List extension) {
  final description = Der.parse(extension).sequence;
  if (description.length < 8) {
    throw const FormatException('KeyDescription is too short');
  }
  final softwareEnforced = _authorizations(description[6]);
  final hardwareEnforced = _authorizations(description[7]);
  Der? find(int tag) => hardwareEnforced[tag] ?? softwareEnforced[tag];

  final rootOfTrust = hardwareEnforced[_rootOfTrust]?.sequence;
  final applicationId = find(_attestationApplicationId);
  final packages = <String>{};
  final digests = <String>{};
  if (applicationId != null) {
    final parts = Der.parse(applicationId.octets).sequence;
    for (final info in parts[0].set) {
      packages.add(String.fromCharCodes(info.sequence.first.octets));
    }
    for (final digest in parts[1].set) {
      digests.add(_hex(digest.octets));
    }
  }
  return KeyAttestation(
    attestationVersion: description[0].integer.toInt(),
    securityLevel: SecurityLevel.fromValue(description[1].enumerated),
    challenge: Uint8List.fromList(description[4].octets),
    packageNames: Set.unmodifiable(packages),
    signingCertificateDigests: Set.unmodifiable(digests),
    deviceLocked: rootOfTrust?[1].boolean,
    verifiedBootState: rootOfTrust == null
        ? null
        : VerifiedBootState.fromValue(rootOfTrust[2].enumerated),
    osVersion: hardwareEnforced[_osVersion]?.integer.toInt(),
    osPatchLevel: hardwareEnforced[_osPatchLevel]?.integer.toInt(),
  );
}

/// The fields of an AuthorizationList by tag. Each is `[tag] EXPLICIT`, so
/// the value is the single child.
Map<int, Der> _authorizations(Der list) => {
  for (final field in list.sequence)
    if (field.tagClass == Der.contextSpecific) field.tag: field.children.single,
};

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
