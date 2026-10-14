import 'device_report.dart';
import 'key_attestation.dart';

/// Why a report was rejected.
enum RejectionReason {
  /// Not a signed report from flutter_anti_virtuals.
  malformed,

  /// The nonce was not issued by this server, was already used or expired.
  unknownNonce,

  /// `issuedAt` is too old or too far in the future.
  stale,

  /// The signature does not match the payload and public key.
  badSignature,

  /// The policy does not accept reports from this platform.
  platformNotAccepted,

  /// There is no usable Android key attestation chain.
  notAttested,

  /// The chain does not lead to a trusted Google root.
  untrustedChain,

  /// A certificate in the chain is on Google's revocation list.
  revoked,

  /// The attested key is not the key that signed the payload.
  keyMismatch,

  /// The attested key was not created for this nonce.
  challengeMismatch,

  /// The key was not created in a TEE or StrongBox.
  weakKeyStorage,

  /// The key belongs to another app or to a re-signed copy of yours.
  wrongApp,

  /// Unlocked bootloader, custom ROM or an old security patch.
  unsafeDevice,

  /// Play Integrity did not vouch for the app, the device or the binding.
  playIntegrity,

  /// A blocking signal was detected, or its check failed.
  blockedSignal,
}

/// The outcome of [SignedReportVerifier.verify].
sealed class VerificationResult {
  const VerificationResult();

  bool get accepted => this is Accepted;
}

final class Accepted extends VerificationResult {
  const Accepted(this.report, {this.keyAttestation});

  final DeviceReport report;

  /// Android: what the hardware attested about the key and the device.
  final KeyAttestation? keyAttestation;

  @override
  String toString() => 'Accepted(${report.platform.name})';
}

final class Rejected extends VerificationResult {
  const Rejected(this.reason, this.message, {this.report});

  final RejectionReason reason;

  /// What failed, for logs. Do not show it to the user.
  final String message;

  /// The parsed payload when it got that far. Its content is not trusted.
  final DeviceReport? report;

  @override
  String toString() => 'Rejected(${reason.name}: $message)';
}
