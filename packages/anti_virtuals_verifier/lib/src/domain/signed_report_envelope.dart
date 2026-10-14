import 'dart:convert';
import 'dart:typed_data';

/// The JSON an app sends: `SignedReport.toJson()` from flutter_anti_virtuals.
final class SignedReportEnvelope {
  const SignedReportEnvelope({
    required this.payload,
    required this.signature,
    required this.algorithm,
    required this.publicKey,
    required this.protection,
    required this.certificateChain,
    this.attestation,
  });

  /// Throws [FormatException] when a required field is missing or is not
  /// valid base64.
  factory SignedReportEnvelope.fromJson(Map<String, Object?> json) {
    final payload = json['payload'];
    final signature = json['signature'];
    final publicKey = json['publicKey'];
    if (payload is! String || signature is! String || publicKey is! String) {
      throw const FormatException(
        'payload, signature and publicKey are required strings',
      );
    }
    final chain = json['certificateChain'];
    final attestation = json['attestation'];
    return SignedReportEnvelope(
      payload: payload,
      signature: base64.decode(signature),
      algorithm: json['algorithm'] as String? ?? 'SHA256withECDSA',
      publicKey: base64.decode(publicKey),
      protection: json['protection'] as String? ?? 'software',
      certificateChain: [
        if (chain is List)
          for (final certificate in chain) base64.decode(certificate as String),
      ],
      attestation: attestation is Map<String, Object?> ? attestation : null,
    );
  }

  /// The exact text that was signed.
  final String payload;
  final Uint8List signature;
  final String algorithm;
  final Uint8List publicKey;

  /// What the app reported about the key: `strongBox`, `hardware` or
  /// `software`. Not trusted; Android key attestation proves it.
  final String protection;

  /// Android: DER certificates, attested leaf first.
  final List<Uint8List> certificateChain;

  /// The Play Integrity or App Attest part, when the app asked for one.
  final Map<String, Object?>? attestation;
}
