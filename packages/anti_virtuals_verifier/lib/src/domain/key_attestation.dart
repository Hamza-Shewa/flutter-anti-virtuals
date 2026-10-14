import 'dart:typed_data';

/// Where Android created and keeps the attested key.
enum SecurityLevel {
  software,
  trustedEnvironment,
  strongBox;

  static SecurityLevel fromValue(int value) => switch (value) {
    0 => software,
    1 => trustedEnvironment,
    2 => strongBox,
    _ => throw FormatException('Unknown security level $value'),
  };
}

/// The boot state the device's secure hardware reports.
enum VerifiedBootState {
  /// Stock, signed system with a locked bootloader.
  verified,

  /// Booted with a user-installed key (custom ROM on a relockable device).
  selfSigned,

  /// Unlocked bootloader: anything can run.
  unverified,
  failed;

  static VerifiedBootState fromValue(int value) => switch (value) {
    0 => verified,
    1 => selfSigned,
    2 => unverified,
    3 => failed,
    _ => throw FormatException('Unknown verified boot state $value'),
  };
}

/// What the Android key attestation extension of the signing key says.
final class KeyAttestation {
  const KeyAttestation({
    required this.attestationVersion,
    required this.securityLevel,
    required this.challenge,
    required this.packageNames,
    required this.signingCertificateDigests,
    this.verifiedBootState,
    this.deviceLocked,
    this.osVersion,
    this.osPatchLevel,
  });

  final int attestationVersion;
  final SecurityLevel securityLevel;

  /// What the app passed as the attestation challenge: the SHA-256 of the
  /// nonce.
  final Uint8List challenge;

  /// The packages of the app that created the key.
  final Set<String> packageNames;

  /// Lowercase hex SHA-256 of the signing certificates of that app.
  final Set<String> signingCertificateDigests;

  /// Null on a key that secure hardware did not attest.
  final VerifiedBootState? verifiedBootState;
  final bool? deviceLocked;

  /// For example 140000 for Android 14.
  final int? osVersion;

  /// Security patch level as `YYYYMM`, for example 202409.
  final int? osPatchLevel;
}
