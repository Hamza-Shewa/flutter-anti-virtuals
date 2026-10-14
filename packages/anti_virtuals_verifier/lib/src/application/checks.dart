import 'dart:convert';
import 'dart:typed_data';

import '../domain/device_report.dart';
import '../domain/key_attestation.dart';
import '../domain/play_integrity.dart';
import '../domain/policy.dart';
import '../domain/ports.dart';
import '../domain/verification_result.dart';
import '../infrastructure/key_description.dart';
import '../infrastructure/public_key.dart';
import '../infrastructure/x509.dart';
import 'app_attest_verifier.dart';
import 'report_check.dart';

/// The nonce was issued by this server and is used now, once.
final class NonceCheck implements ReportCheck {
  const NonceCheck(this._nonces);

  final NonceStore _nonces;

  @override
  Future<Rejected?> check(VerificationContext context) async =>
      await _nonces.consume(context.report.nonce)
      ? null
      : context.reject(
          RejectionReason.unknownNonce,
          'The nonce is unknown, used or expired',
        );
}

/// `issuedAt` is recent.
final class FreshnessCheck implements ReportCheck {
  const FreshnessCheck(this._policy);

  final VerificationPolicy _policy;

  @override
  Rejected? check(VerificationContext context) {
    final age = context.now.difference(context.report.issuedAt);
    if (age > _policy.maxAge) {
      return context.reject(
        RejectionReason.stale,
        'Issued ${age.inSeconds}s ago',
      );
    }
    if (-age > _policy.maxClockSkew) {
      return context.reject(
        RejectionReason.stale,
        'Issued ${(-age).inSeconds}s in the future',
      );
    }
    return null;
  }
}

/// The signature matches the payload and the public key.
final class SignatureCheck implements ReportCheck {
  const SignatureCheck();

  @override
  Rejected? check(VerificationContext context) {
    final envelope = context.envelope;
    if (envelope.algorithm != 'SHA256withECDSA') {
      return context.reject(
        RejectionReason.badSignature,
        'Unsupported algorithm ${envelope.algorithm}',
      );
    }
    final PublicKey key;
    try {
      key = PublicKey.fromDevice(envelope.publicKey);
    } on FormatException catch (e) {
      return context.reject(
        RejectionReason.badSignature,
        'Bad public key: ${e.message}',
      );
    }
    final signed = key.verify(
      Oids.ecdsaSha256,
      Uint8List.fromList(utf8.encode(envelope.payload)),
      envelope.signature,
    );
    return signed
        ? null
        : context.reject(
            RejectionReason.badSignature,
            'The signature does not verify',
          );
  }
}

/// The policy accepts the platform.
final class PlatformCheck implements ReportCheck {
  const PlatformCheck(this._policy);

  final VerificationPolicy _policy;

  @override
  Rejected? check(VerificationContext context) {
    final accepted = switch (context.report.platform) {
      DevicePlatform.android => _policy.android != null,
      DevicePlatform.iOS => _policy.ios != null || _policy.acceptIos,
    };
    return accepted
        ? null
        : context.reject(
            RejectionReason.platformNotAccepted,
            '${context.report.platform.name} reports are not accepted',
          );
  }
}

/// Android: the signing key was created for this nonce, in secure hardware,
/// by your app, on a device with a verified boot.
final class AndroidKeyAttestationCheck implements ReportCheck {
  AndroidKeyAttestationCheck(
    this._policy, {
    required List<PublicKey> trustedRoots,
    RevocationList? revocations,
  }) : _roots = trustedRoots,
       _revocations = revocations,
       _digests = {
         for (final digest in _policy.signingCertificateDigests)
           normalizeHex(digest),
       };

  final AndroidPolicy _policy;
  final List<PublicKey> _roots;
  final RevocationList? _revocations;
  final Set<String> _digests;

  @override
  Rejected? check(VerificationContext context) {
    if (context.report.platform != DevicePlatform.android) return null;
    Rejected reject(RejectionReason reason, String message) =>
        context.reject(reason, message);

    final List<X509Certificate> chain;
    try {
      chain = [
        for (final der in context.envelope.certificateChain)
          X509Certificate.fromDer(der),
      ];
    } on FormatException catch (e) {
      return reject(
        RejectionReason.notAttested,
        'Bad certificate: ${e.message}',
      );
    }
    if (chain.length < 2) {
      return reject(RejectionReason.notAttested, 'No key attestation chain');
    }

    for (var i = 0; i < chain.length - 1; i++) {
      if (!chain[i].isSignedBy(chain[i + 1].publicKey)) {
        return reject(
          RejectionReason.untrustedChain,
          'Certificate $i is not signed by certificate ${i + 1}',
        );
      }
    }
    final last = chain.last;
    if (!_roots.contains(last.publicKey) && !_roots.any(last.isSignedBy)) {
      return reject(
        RejectionReason.untrustedChain,
        'The chain does not end at a trusted root',
      );
    }
    if (_policy.checkCertificateDates &&
        chain.any((certificate) => !certificate.isValidAt(context.now))) {
      return reject(
        RejectionReason.untrustedChain,
        'A certificate is out of date',
      );
    }
    final revocations = _revocations;
    if (revocations != null) {
      for (final certificate in chain) {
        if (revocations.isRevoked(certificate.serialNumber)) {
          return reject(
            RejectionReason.revoked,
            'Certificate ${certificate.serialNumber.toRadixString(16)} is revoked',
          );
        }
      }
    }

    final leaf = chain.first;
    final PublicKey signingKey;
    try {
      signingKey = PublicKey.fromDevice(context.envelope.publicKey);
    } on FormatException catch (e) {
      return reject(
        RejectionReason.keyMismatch,
        'Bad public key: ${e.message}',
      );
    }
    if (leaf.publicKey != signingKey) {
      return reject(
        RejectionReason.keyMismatch,
        'The attested key did not sign the payload',
      );
    }

    final extension = leaf.extensions[keyAttestationOid];
    if (extension == null) {
      return reject(
        RejectionReason.notAttested,
        'No key attestation extension',
      );
    }
    final KeyAttestation attestation;
    try {
      attestation = parseKeyDescription(extension);
    } on FormatException catch (e) {
      return reject(
        RejectionReason.notAttested,
        'Bad key attestation: ${e.message}',
      );
    }

    final challenge = sha256(utf8.encode(context.report.nonce));
    if (!_sameBytes(attestation.challenge, challenge)) {
      return reject(
        RejectionReason.challengeMismatch,
        'The key was not created for this nonce',
      );
    }
    if (!_policy.allowedSecurityLevels.contains(attestation.securityLevel)) {
      return reject(
        RejectionReason.weakKeyStorage,
        'Key created in ${attestation.securityLevel.name}',
      );
    }
    if (!attestation.packageNames.any(_policy.packageNames.contains)) {
      return reject(
        RejectionReason.wrongApp,
        'Key created by ${attestation.packageNames.join(', ')}',
      );
    }
    if (!attestation.signingCertificateDigests.any(_digests.contains)) {
      return reject(
        RejectionReason.wrongApp,
        'The app is not signed with your certificate',
      );
    }
    if (_policy.requireVerifiedBoot &&
        attestation.verifiedBootState != VerifiedBootState.verified) {
      return reject(
        RejectionReason.unsafeDevice,
        'Verified boot state is ${attestation.verifiedBootState?.name ?? 'unknown'}',
      );
    }
    if (_policy.requireLockedBootloader && attestation.deviceLocked != true) {
      return reject(RejectionReason.unsafeDevice, 'The bootloader is unlocked');
    }
    final minimumPatch = _policy.minimumOsPatchLevel;
    final patch = attestation.osPatchLevel;
    if (minimumPatch != null && (patch == null || patch < minimumPatch)) {
      return reject(
        RejectionReason.unsafeDevice,
        'Security patch level ${patch ?? 'unknown'} is older than $minimumPatch',
      );
    }
    context.keyAttestation = attestation;
    return null;
  }
}

/// Android: a decoded Play Integrity verdict vouches for the app and device
/// and is bound to this payload. A rejection names the Google Play dialog
/// that can fix it, when there is one.
final class PlayIntegrityCheck implements ReportCheck {
  PlayIntegrityCheck(this._android, this._policy)
    : _digests = {
        for (final digest in _android.signingCertificateDigests)
          normalizeHex(digest),
      };

  final AndroidPolicy _android;
  final PlayIntegrityPolicy _policy;
  final Set<String> _digests;

  @override
  Rejected? check(VerificationContext context) {
    if (context.report.platform != DevicePlatform.android) return null;
    Rejected reject(String message, [PlayIntegrityRemediation? remediation]) =>
        context.reject(
          RejectionReason.playIntegrity,
          message,
          remediation: remediation,
        );

    final json = context.playIntegrityJson;
    if (json == null) {
      return reject('No decoded Play Integrity verdict was passed');
    }
    final verdict = PlayIntegrityVerdict.fromJson(json);
    context.playIntegrity = verdict;

    final request = verdict.requestDetails;
    final binding = request.requestHash ?? request.nonce;
    final expected = sha256(utf8.encode(context.envelope.payload));
    if (binding == null || !_sameBytes(_base64Url(binding), expected)) {
      return reject('The token is not bound to this payload');
    }
    if (!_android.packageNames.contains(request.requestPackageName)) {
      return reject('The token was requested by ${request.requestPackageName}');
    }
    final timestamp = request.timestamp;
    if (timestamp == null ||
        context.now.difference(timestamp) > _policy.maxAge) {
      return reject('The token is too old');
    }

    final app = verdict.appIntegrity;
    if (_policy.requirePlayRecognized) {
      final recognition = app.appRecognitionVerdict;
      if (recognition != AppRecognitionVerdict.playRecognized) {
        return reject(
          'App recognition: ${recognition?.value ?? 'missing'}',
          recognition == AppRecognitionVerdict.unrecognizedVersion
              ? PlayIntegrityRemediation.getLicensed
              : PlayIntegrityRemediation.getIntegrity,
        );
      }
      if (!app.certificateSha256Hex.any(_digests.contains)) {
        return reject(
          'Play does not know the app as signed with your certificate',
        );
      }
    }

    final device = verdict.deviceIntegrity;
    final required = _policy.requiredDeviceVerdict;
    if (required != null &&
        !device.deviceRecognitionVerdict.contains(required)) {
      return reject(
        'Device recognition: '
        '${device.deviceRecognitionVerdict.map((l) => l.value).join(', ')}',
        required == DeviceRecognitionLabel.meetsStrongIntegrity
            ? PlayIntegrityRemediation.getStrongIntegrity
            : PlayIntegrityRemediation.getIntegrity,
      );
    }

    final licensing = verdict.accountDetails.appLicensingVerdict;
    if (_policy.requireLicensed && licensing != AppLicensingVerdict.licensed) {
      return reject(
        'Licensing: ${licensing?.value ?? 'missing'}',
        licensing == AppLicensingVerdict.unlicensed
            ? PlayIntegrityRemediation.getLicensed
            : PlayIntegrityRemediation.getIntegrity,
      );
    }

    final environment = verdict.environmentDetails;
    final apps = environment.appsDetected;
    if (apps == null) {
      if (_policy.requireAppAccessRiskVerdict) {
        return reject('App access risk was not evaluated');
      }
    } else {
      final found = apps.intersection(_policy.rejectedAppAccessRisks);
      if (found.isNotEmpty) {
        return reject(
          'App access risk: ${found.map((r) => r.value).join(', ')}',
          _accessRiskRemediation(found),
        );
      }
    }

    final playProtect = environment.playProtectVerdict;
    final accepted = _policy.acceptedPlayProtectVerdicts;
    if (accepted != null && !accepted.contains(playProtect)) {
      return reject(
        'Play Protect: ${playProtect?.value ?? 'missing'}',
        PlayIntegrityRemediation.getStrongIntegrity,
      );
    }

    final cap = _policy.maxDeviceActivityLevel;
    final activity = device.deviceActivityLevel;
    if (cap != null && (activity == null || !activity.isAtMost(cap))) {
      return reject('Recent device activity: ${activity?.value ?? 'missing'}');
    }
    return null;
  }

  /// `CLOSE_ALL_ACCESS_RISK` when a known app is involved, since closing
  /// unknown apps would not help; `CLOSE_UNKNOWN_ACCESS_RISK` otherwise. No
  /// dialog closes apps that are only installed or draw overlays.
  static PlayIntegrityRemediation? _accessRiskRemediation(
    Set<AppAccessRisk> found,
  ) {
    if (found.any(
      const {
        AppAccessRisk.knownCapturing,
        AppAccessRisk.knownControlling,
      }.contains,
    )) {
      return PlayIntegrityRemediation.closeAllAccessRisk;
    }
    if (found.any(AppAccessRisk.unknownCapturingOrControlling.contains)) {
      return PlayIntegrityRemediation.closeUnknownAccessRisk;
    }
    return null;
  }

  static Uint8List _base64Url(String value) {
    try {
      return base64Url.decode(base64Url.normalize(value));
    } on FormatException {
      return Uint8List(0);
    }
  }
}

/// iOS: an App Attest attestation or assertion from your app, made for this
/// payload. The client data hash is the SHA-256 of the signed payload, as
/// the plugin computes it.
final class AppAttestCheck implements ReportCheck {
  const AppAttestCheck(this._policy, this._verifier);

  final IosPolicy _policy;
  final AppAttestVerifier _verifier;

  @override
  Future<Rejected?> check(VerificationContext context) async {
    if (context.report.platform != DevicePlatform.iOS) return null;
    final attestation = context.envelope.attestation;
    if (attestation == null || attestation['type'] != 'appAttest') {
      return _policy.requireAppAttest
          ? context.reject(RejectionReason.notAttested, 'No App Attest object')
          : null;
    }
    final token = attestation['token'];
    final keyId = attestation['keyId'];
    if (token is! String || keyId is! String) {
      return context.reject(
        RejectionReason.notAttested,
        'The App Attest object has no token or key id',
      );
    }
    final Uint8List object;
    try {
      object = base64.decode(token);
    } on FormatException {
      return context.reject(
        RejectionReason.notAttested,
        'The App Attest token is not base64',
      );
    }
    final clientDataHash = sha256(utf8.encode(context.envelope.payload));
    try {
      context.appAttest = attestation['assertion'] == true
          ? await _verifier.verifyAssertion(
              assertion: object,
              keyId: keyId,
              clientDataHash: clientDataHash,
            )
          : await _verifier.verifyAttestation(
              attestation: object,
              keyId: keyId,
              clientDataHash: clientDataHash,
              now: context.now,
            );
    } on AppAttestException catch (e) {
      return context.reject(e.reason, e.message);
    }
    return null;
  }
}

/// No blocking signal was detected, and none of their checks failed.
final class SignalPolicyCheck implements ReportCheck {
  const SignalPolicyCheck(this._policy);

  final VerificationPolicy _policy;

  @override
  Rejected? check(VerificationContext context) {
    final signals = context.report.signals;
    for (final key in _policy.blockOn) {
      final verdict = signals[key];
      if (verdict == null) continue;
      if (verdict.failed && _policy.blockOnFailedChecks) {
        return context.reject(
          RejectionReason.blockedSignal,
          'The $key check failed on the device',
        );
      }
      if (verdict.detected &&
          (!verdict.installedOnly || _policy.blockOnInstalledApps)) {
        return context.reject(RejectionReason.blockedSignal, '$key detected');
      }
    }
    return null;
  }
}

/// Lowercase hex without separators.
String normalizeHex(String hex) =>
    hex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '').toLowerCase();

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
