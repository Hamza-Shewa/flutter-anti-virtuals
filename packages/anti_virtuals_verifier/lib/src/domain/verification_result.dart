import 'app_attest.dart';
import 'device_report.dart';
import 'key_attestation.dart';
import 'play_integrity.dart';

/// Why a report was rejected.
enum RejectionReason {
  /// Not a signed report from flutter_anti_virtuals.
  malformed,

  /// The nonce was not issued by this server, was already used or expired.
  unknownNonce,

  /// `issuedAt` is too old or too far in the future.
  stale,

  /// The signature does not match the payload and public key, or an App
  /// Attest assertion signature does not verify.
  badSignature,

  /// The policy does not accept reports from this platform.
  platformNotAccepted,

  /// There is no usable key attestation: no Android chain, or no App Attest
  /// object, or one that cannot be read.
  notAttested,

  /// The chain does not lead to a trusted Google or Apple root.
  untrustedChain,

  /// A certificate in the chain is on Google's revocation list.
  revoked,

  /// The attested key is not the key that signed the payload, or the App
  /// Attest key id does not match the attested key.
  keyMismatch,

  /// The attested key or App Attest object was not created for this
  /// payload.
  challengeMismatch,

  /// The key was not created in a TEE or StrongBox.
  weakKeyStorage,

  /// The key belongs to another app or to a re-signed copy of yours.
  wrongApp,

  /// Unlocked bootloader, custom ROM or an old security patch.
  unsafeDevice,

  /// Play Integrity did not vouch for the app, the device or the binding.
  playIntegrity,

  /// An App Attest assertion used a key this server has not enrolled. Ask
  /// the app to call `verify` again with
  /// `AttestationOptions(resetAppAttestKey: true)`.
  unknownAppAttestKey,

  /// An App Attest counter did not increase, or a key was attested twice:
  /// the object was replayed or the key is used from two places.
  appAttestReplay,

  /// An App Attest key from the development environment, which the policy
  /// does not accept.
  wrongEnvironment,

  /// A blocking signal was detected, or its check failed.
  blockedSignal,
}

/// The outcome of [SignedReportVerifier.verify].
sealed class VerificationResult {
  const VerificationResult();

  bool get accepted => this is Accepted;
}

final class Accepted extends VerificationResult {
  const Accepted(
    this.report, {
    this.keyAttestation,
    this.playIntegrityVerdict,
    this.appAttest,
    this.deviceCheckToken,
  });

  final DeviceReport report;

  /// Android: what the hardware attested about the key and the device.
  final KeyAttestation? keyAttestation;

  /// Android with a Play Integrity policy: the verdict that passed. Read
  /// its device recall bits or environment details for your own rules.
  final PlayIntegrityVerdict? playIntegrityVerdict;

  /// iOS with an App Attest object: what it proved.
  final AppAttestResult? appAttest;

  /// iOS: the DeviceCheck token the app sent, if any. This package does not
  /// check it and it is not bound to the payload; pass it to
  /// `DeviceCheckClient`, where Apple validates it.
  final String? deviceCheckToken;

  @override
  String toString() => 'Accepted(${report.platform.name})';
}

final class Rejected extends VerificationResult {
  const Rejected(
    this.reason,
    this.message, {
    this.report,
    this.playIntegrityVerdict,
    this.remediation,
  });

  final RejectionReason reason;

  /// What failed, for logs. Do not show it to the user.
  final String message;

  /// The parsed payload when it got that far. Its content is not trusted.
  final DeviceReport? report;

  /// The Play Integrity verdict when the check got that far.
  final PlayIntegrityVerdict? playIntegrityVerdict;

  /// The Google Play dialog that can fix this failure, when there is one.
  /// Send its `name` to the app, which shows it with
  /// `showPlayIntegrityDialog(PlayIntegrityDialog.values.byName(name))`,
  /// then asks for a new nonce and verifies again.
  final PlayIntegrityRemediation? remediation;

  @override
  String toString() => 'Rejected(${reason.name}: $message)';
}
