import 'dart:convert';

import 'attestation.dart';
import 'report.dart';
import 'signal.dart';

/// How the device-bound signing key of a [SignedReport] is protected.
enum KeyProtection {
  /// A dedicated security chip (Android StrongBox).
  strongBox,

  /// Trusted execution environment (Android) or Secure Enclave (iOS).
  hardware,

  /// A key the operating system keeps in software, which proves nothing about
  /// the device.
  software;

  static KeyProtection fromKey(Object? key) => switch (key) {
    'strongBox' => KeyProtection.strongBox,
    'hardware' => KeyProtection.hardware,
    _ => KeyProtection.software,
  };
}

/// What the native side returns after signing a payload with a fresh key.
class DeviceSignature {
  const DeviceSignature({
    required this.signature,
    required this.publicKey,
    required this.algorithm,
    required this.protection,
    required this.attested,
    this.certificateChain = const <String>[],
  });

  factory DeviceSignature.fromMap(Map<Object?, Object?> map) {
    return DeviceSignature(
      signature: map['signature'] as String? ?? '',
      publicKey: map['publicKey'] as String? ?? '',
      algorithm: map['algorithm'] as String? ?? '',
      protection: KeyProtection.fromKey(map['protection']),
      attested: map['attested'] as bool? ?? false,
      certificateChain: <String>[
        for (final cert
            in map['certificateChain'] as List? ?? const <Object?>[])
          cert.toString(),
      ],
    );
  }

  /// Base64 of the signature over the UTF-8 bytes of the payload.
  final String signature;

  /// Base64 of the public key (Android: X.509 SubjectPublicKeyInfo, iOS: the
  /// ANSI X9.63 point).
  final String publicKey;

  /// `SHA256withECDSA` on both platforms.
  final String algorithm;

  final KeyProtection protection;

  /// True when [certificateChain] carries a hardware key attestation whose
  /// challenge is the SHA-256 of the nonce (Android only).
  final bool attested;

  /// Base64 DER certificates, leaf first (Android key attestation).
  final List<String> certificateChain;
}

/// A scan result that a backend can verify: the scan, bound to a nonce the
/// backend chose, signed by a key that was created on the device for this
/// request.
///
/// The client cannot be trusted with a plain [AntiVirtualReport], because
/// whoever controls the device controls the app. A backend should check, in
/// this order: the nonce is one it issued and has not seen before, the
/// signature verifies over [payload] with [publicKey], and, on Android, the
/// certificate chain leads to a Google attestation root and its attestation
/// extension carries the SHA-256 of the nonce as challenge, the app's package
/// and signing certificate, and a verified boot state. See
/// `doc/server-verification.md`.
class SignedReport {
  const SignedReport({
    required this.nonce,
    required this.issuedAt,
    required this.platform,
    required this.payload,
    required this.signature,
    required this.report,
    this.attestation,
  });

  /// Builds the text that is signed. Keys are written in a fixed order and
  /// only `detected` and `supported` are included, so the payload stays small
  /// and the signature does not depend on localized or device-specific
  /// details.
  static String encodePayload({
    required String nonce,
    required DateTime issuedAt,
    required String platform,
    required AntiVirtualReport report,
  }) {
    return jsonEncode(<String, Object?>{
      'v': 1,
      'nonce': nonce,
      'issuedAt': issuedAt.toUtc().millisecondsSinceEpoch,
      'platform': platform,
      'signals': <String, Object?>{
        for (final signal in AntiVirtualSignal.values)
          if (report[signal] case final result?)
            signal.key: <String, Object?>{
              'detected': result.detected,
              'supported': result.supported,
            },
      },
    });
  }

  final String nonce;
  final DateTime issuedAt;

  /// `android` or `iOS`.
  final String platform;

  /// The exact text that was signed. Send it as is; do not re-encode it.
  final String payload;

  final DeviceSignature signature;

  /// The scan the payload was built from, for local use.
  final AntiVirtualReport report;

  /// Play Integrity token or App Attest object bound to [payload], when
  /// requested with `verify(attestation: ...)`.
  final PlatformAttestation? attestation;

  String get publicKey => signature.publicKey;

  /// What to send to the backend.
  Map<String, Object?> toJson() => <String, Object?>{
    'payload': payload,
    'signature': signature.signature,
    'algorithm': signature.algorithm,
    'publicKey': signature.publicKey,
    'protection': signature.protection.name,
    'attested': signature.attested,
    'certificateChain': signature.certificateChain,
    if (attestation != null) 'attestation': attestation!.toJson(),
  };

  @override
  String toString() =>
      'SignedReport(platform: $platform, protection: '
      '${signature.protection.name}, attested: ${signature.attested}, '
      'detected: ${report.detected})';
}
