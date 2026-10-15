import 'dart:convert';
import 'dart:typed_data';

import '../domain/app_attest.dart';
import '../domain/policy.dart';
import '../domain/ports.dart';
import '../domain/verification_result.dart';
import '../infrastructure/app_attest_objects.dart';
import '../infrastructure/apple_roots.dart';
import '../infrastructure/public_key.dart';
import '../infrastructure/x509.dart';

/// An App Attest object failed verification.
final class AppAttestException implements Exception {
  const AppAttestException(this.reason, this.message);

  final RejectionReason reason;

  /// What failed, for logs.
  final String message;

  @override
  String toString() => 'AppAttestException(${reason.name}: $message)';
}

/// Verifies App Attest attestations and assertions as Apple's "Validating
/// apps that connect to your server" describes, and keeps the key state in
/// an [AppAttestKeyStore].
///
/// `SignedReportVerifier` uses it for iOS reports, with the SHA-256 of the
/// signed payload as client data hash. You can also use it on its own.
final class AppAttestVerifier {
  AppAttestVerifier({
    required this.policy,
    required AppAttestKeyStore keys,
    List<PublicKey>? trustedRoots,
    this.clockSkew = const Duration(seconds: 30),
    DateTime Function()? clock,
  }) : _keys = keys,
       _roots = trustedRoots ?? AppleRoots.appAttestKeys,
       _clock = clock ?? DateTime.now,
       _appIdHashes = {
         for (final appId in policy.appIds) appId: sha256(utf8.encode(appId)),
       };

  final IosPolicy policy;

  /// How far certificate dates may be off from this server's clock.
  final Duration clockSkew;

  final AppAttestKeyStore _keys;
  final List<PublicKey> _roots;
  final DateTime Function() _clock;
  final Map<String, Uint8List> _appIdHashes;

  /// Verifies the attestation of a new key and enrolls it.
  ///
  /// [attestation] is the CBOR object, [keyId] the base64 key identifier the
  /// app sent and [clientDataHash] what the app passed to `attestKey` (the
  /// plugin passes the SHA-256 of the signed payload). Throws
  /// [AppAttestException] when it does not verify or the key is already
  /// enrolled.
  Future<AppAttestResult> verifyAttestation({
    required Uint8List attestation,
    required String keyId,
    required List<int> clientDataHash,
    DateTime? now,
  }) async {
    final time = (now ?? _clock()).toUtc();
    final AttestationObject object;
    final List<X509Certificate> chain;
    final AuthenticatorData authData;
    try {
      object = AttestationObject.parse(attestation);
      chain = [
        for (final der in object.certificates) X509Certificate.fromDer(der),
      ];
      authData = AuthenticatorData.parse(object.authData);
    } on FormatException catch (e) {
      throw AppAttestException(
        RejectionReason.notAttested,
        'Bad attestation: ${e.message}',
      );
    }

    for (var i = 0; i < chain.length - 1; i++) {
      if (!chain[i].isSignedBy(chain[i + 1].publicKey)) {
        _fail(
          RejectionReason.untrustedChain,
          'Certificate $i is not signed by certificate ${i + 1}',
        );
      }
    }
    final last = chain.last;
    if (!_roots.contains(last.publicKey) && !_roots.any(last.isSignedBy)) {
      _fail(
        RejectionReason.untrustedChain,
        'The chain does not end at the App Attest root',
      );
    }
    for (final certificate in chain) {
      if (time.isBefore(certificate.notBefore.subtract(clockSkew)) ||
          time.isAfter(certificate.notAfter.add(clockSkew))) {
        _fail(RejectionReason.untrustedChain, 'A certificate is out of date');
      }
    }

    final leaf = chain.first;
    final leafKey = leaf.publicKey;
    if (leafKey is! EcPublicKey || leafKey.curveOid != Oids.p256) {
      _fail(RejectionReason.notAttested, 'The attested key is not P-256');
    }
    final extension = leaf.extensions[appAttestNonceOid];
    if (extension == null) {
      _fail(RejectionReason.notAttested, 'No nonce extension');
    }
    final Uint8List nonce;
    try {
      nonce = readAppAttestNonce(extension);
    } on FormatException catch (e) {
      _fail(RejectionReason.notAttested, 'Bad nonce extension: ${e.message}');
    }
    if (!sameBytes(nonce, sha256([...object.authData, ...clientDataHash]))) {
      _fail(
        RejectionReason.challengeMismatch,
        'The attestation was not made for this client data',
      );
    }

    final keyIdBytes = _decodeKeyId(keyId);
    if (!sameBytes(sha256(leafKey.point), keyIdBytes)) {
      _fail(
        RejectionReason.keyMismatch,
        'The key id is not the hash of the attested key',
      );
    }
    final appId = _appIdFor(authData);
    if (authData.counter != 0) {
      _fail(
        RejectionReason.notAttested,
        'The attestation counter is ${authData.counter}, not 0',
      );
    }
    final environment = _environment(authData.aaguid);
    final credentialId = authData.credentialId;
    if (credentialId == null || !sameBytes(credentialId, keyIdBytes)) {
      _fail(RejectionReason.keyMismatch, 'The credential id is not the key id');
    }
    _checkValidationCategory(authData);

    final key = AppAttestKey(
      keyId: base64.encode(keyIdBytes),
      publicKey: leafKey.point,
      appId: appId,
      environment: environment,
      receipt: object.receipt,
      attestedAt: time,
    );
    if (!await _keys.save(key)) {
      _fail(RejectionReason.appAttestReplay, 'The key is already enrolled');
    }
    return AppAttestResult(
      keyId: key.keyId,
      isNewKey: true,
      counter: 0,
      appId: appId,
      environment: environment,
      publicKey: key.publicKey,
      receipt: key.receipt,
      validationCategory: authData.validationCategory,
      bundleVersion: authData.bundleVersion,
    );
  }

  /// Verifies an assertion made with an enrolled key and stores its counter.
  ///
  /// [assertion] is the CBOR object, [keyId] the base64 key identifier and
  /// [clientDataHash] what the app passed to `generateAssertion`. Throws
  /// [AppAttestException] when the key is unknown, the assertion does not
  /// verify or its counter did not increase.
  Future<AppAttestResult> verifyAssertion({
    required Uint8List assertion,
    required String keyId,
    required List<int> clientDataHash,
  }) async {
    final AssertionObject object;
    final AuthenticatorData authData;
    try {
      object = AssertionObject.parse(assertion);
      authData = AuthenticatorData.parse(object.authenticatorData);
    } on FormatException catch (e) {
      throw AppAttestException(
        RejectionReason.notAttested,
        'Bad assertion: ${e.message}',
      );
    }
    final stored = await _keys.find(base64.encode(_decodeKeyId(keyId)));
    if (stored == null) {
      _fail(
        RejectionReason.unknownAppAttestKey,
        'No enrolled App Attest key $keyId',
      );
    }
    final PublicKey publicKey;
    try {
      publicKey = EcPublicKey(Oids.p256, stored.publicKey);
    } on FormatException {
      _fail(RejectionReason.notAttested, 'The stored public key is invalid');
    }
    final nonce = sha256([...object.authenticatorData, ...clientDataHash]);
    if (!publicKey.verify(Oids.ecdsaSha256, nonce, object.signature)) {
      _fail(
        RejectionReason.badSignature,
        'The assertion signature does not verify',
      );
    }
    final appId = _appIdFor(authData);
    if (appId != stored.appId) {
      _fail(
        RejectionReason.wrongApp,
        'The key was enrolled for ${stored.appId}, not $appId',
      );
    }
    if (stored.environment == AppleEnvironment.development &&
        !policy.allowDevelopment) {
      _fail(
        RejectionReason.wrongEnvironment,
        'The key is from the development environment',
      );
    }
    if (authData.counter <= stored.counter) {
      _fail(
        RejectionReason.appAttestReplay,
        'Counter ${authData.counter} is not above ${stored.counter}',
      );
    }
    _checkValidationCategory(authData);
    if (!await _keys.compareAndSetCounter(
      stored.keyId,
      expected: stored.counter,
      next: authData.counter,
    )) {
      _fail(
        RejectionReason.appAttestReplay,
        'Another request used the key at the same time',
      );
    }
    return AppAttestResult(
      keyId: stored.keyId,
      isNewKey: false,
      counter: authData.counter,
      appId: appId,
      environment: stored.environment,
      publicKey: stored.publicKey,
      validationCategory: authData.validationCategory,
      bundleVersion: authData.bundleVersion,
    );
  }

  Uint8List _decodeKeyId(String keyId) {
    try {
      final bytes = base64.decode(keyId);
      if (bytes.length == 32) return bytes;
    } on FormatException {
      // Reported below.
    }
    _fail(RejectionReason.keyMismatch, 'The key id is not a base64 SHA-256');
  }

  String _appIdFor(AuthenticatorData authData) {
    for (final MapEntry(key: appId, value: hash) in _appIdHashes.entries) {
      if (sameBytes(hash, authData.rpIdHash)) return appId;
    }
    _fail(
      RejectionReason.wrongApp,
      'The object is for another app (rpIdHash does not match)',
    );
  }

  AppleEnvironment _environment(Uint8List? aaguid) {
    if (aaguid != null && sameBytes(aaguid, appAttestProductionAaguid)) {
      return AppleEnvironment.production;
    }
    if (aaguid != null && sameBytes(aaguid, appAttestDevelopmentAaguid)) {
      if (!policy.allowDevelopment) {
        _fail(
          RejectionReason.wrongEnvironment,
          'The key is from the development environment',
        );
      }
      return AppleEnvironment.development;
    }
    _fail(RejectionReason.notAttested, 'Unknown aaguid');
  }

  void _checkValidationCategory(AuthenticatorData authData) {
    final allowed = policy.allowedValidationCategories;
    final category = authData.validationCategory;
    if (allowed != null && category != null && !allowed.contains(category)) {
      _fail(
        RejectionReason.wrongApp,
        'Validation category $category is not accepted',
      );
    }
  }

  static Never _fail(RejectionReason reason, String message) =>
      throw AppAttestException(reason, message);
}

/// Constant-time comparison of two byte lists.
bool sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
