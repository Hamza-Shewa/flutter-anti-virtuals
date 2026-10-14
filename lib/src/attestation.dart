/// Which platform service produced a [PlatformAttestation].
enum AttestationType {
  /// Google Play Integrity API token (Android).
  playIntegrity,

  /// Apple App Attest attestation or assertion (iOS).
  appAttest;

  static AttestationType? fromKey(Object? key) => switch (key) {
    'playIntegrity' => AttestationType.playIntegrity,
    'appAttest' => AttestationType.appAttest,
    _ => null,
  };
}

/// How Play Integrity is asked for a token (Android only).
enum PlayIntegrityRequest {
  /// A self-contained request. Its token carries the binding as
  /// `requestDetails.nonce`. It takes a few seconds and has a low daily
  /// quota, so keep it for rare, high-value actions.
  classic,

  /// A request through a token provider that Play prepares ahead of time
  /// (see [FlutterAntiVirtuals.preparePlayIntegrity]). Once prepared it is
  /// fast and has a much higher quota. Its token carries the binding as
  /// `requestDetails.requestHash`. Needs
  /// [AttestationOptions.cloudProjectNumber].
  standard,
}

/// Configures the platform attestation that [FlutterAntiVirtuals.verify] can
/// request on top of the device-signed scan.
class AttestationOptions {
  const AttestationOptions({
    this.cloudProjectNumber,
    this.resetAppAttestKey = false,
    this.playIntegrity = PlayIntegrityRequest.classic,
  }) : assert(
         playIntegrity == PlayIntegrityRequest.classic ||
             cloudProjectNumber != null,
         'Standard Play Integrity requests need a cloudProjectNumber',
       );

  /// Google Cloud project number the Play Integrity API is enabled in. A
  /// classic request can leave it null when the app is distributed on Google
  /// Play and linked to that project in the Play Console; a standard request
  /// always needs it. Android only.
  final int? cloudProjectNumber;

  /// Android only: a [PlayIntegrityRequest.classic] or
  /// [PlayIntegrityRequest.standard] request. Classic is the default because
  /// the two put the binding in different token fields, so switching needs a
  /// matching backend change (see `doc/server-verification.md`).
  final PlayIntegrityRequest playIntegrity;

  /// iOS only. App Attest enrolls a key once (an *attestation*) and then signs
  /// each request with it (an *assertion*). The plugin remembers that it
  /// enrolled a key. Set this to true to throw that key away and enroll a new
  /// one, which is what to do when your backend does not know the key (a first
  /// request that never reached it, a reinstall or a database reset).
  final bool resetAppAttestKey;

  Map<String, Object?> toMap() => <String, Object?>{
    'cloudProjectNumber': cloudProjectNumber,
    'resetAppAttestKey': resetAppAttestKey,
    'playIntegrity': playIntegrity.name,
  };
}

/// An attestation token from the platform, bound to one payload.
///
/// Android: a Play Integrity token whose nonce (classic request) or request
/// hash (standard request) is the URL-safe base64 (no padding) SHA-256 of the
/// signed payload. iOS: an App Attest attestation (the
/// first request of a key) or assertion (every later one) whose client data
/// hash is the SHA-256 of the signed payload. Neither can be checked on the
/// device; send it to your backend, which asks Google or verifies Apple's
/// format. See `doc/server-verification.md`.
class PlatformAttestation {
  const PlatformAttestation({
    required this.type,
    required this.token,
    this.keyId,
    this.isAssertion = false,
    this.isStandardRequest = false,
  });

  factory PlatformAttestation.fromMap(Map<Object?, Object?> map) {
    final type = AttestationType.fromKey(map['type']);
    if (type == null) {
      throw FormatException('Unknown attestation type: ${map['type']}');
    }
    return PlatformAttestation(
      type: type,
      token: map['token'] as String? ?? '',
      keyId: map['keyId'] as String?,
      isAssertion: map['assertion'] as bool? ?? false,
      isStandardRequest: map['standard'] as bool? ?? false,
    );
  }

  final AttestationType type;

  /// Play Integrity token, or base64 App Attest attestation / assertion.
  final String token;

  /// App Attest key identifier (iOS).
  final String? keyId;

  /// App Attest: true for an assertion, false for the first attestation.
  final bool isAssertion;

  /// Play Integrity: true for a [PlayIntegrityRequest.standard] token, whose
  /// binding is in `requestHash` instead of `nonce`.
  final bool isStandardRequest;

  Map<String, Object?> toJson() => <String, Object?>{
    'type': type.name,
    'token': token,
    if (keyId != null) 'keyId': keyId,
    if (type == AttestationType.appAttest) 'assertion': isAssertion,
    if (type == AttestationType.playIntegrity) 'standard': isStandardRequest,
  };

  @override
  String toString() =>
      'PlatformAttestation(${type.name}${isAssertion ? ', assertion' : ''}'
      '${isStandardRequest ? ', standard' : ''})';
}
