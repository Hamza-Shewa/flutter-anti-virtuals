import 'dart:async';

import '../domain/app_attest.dart';
import '../domain/device_report.dart';
import '../domain/key_attestation.dart';
import '../domain/play_integrity.dart';
import '../domain/signed_report_envelope.dart';
import '../domain/verification_result.dart';

/// What the checks share while a report is verified.
final class VerificationContext {
  VerificationContext({
    required this.envelope,
    required this.report,
    required this.now,
    this.playIntegrityJson,
  });

  final SignedReportEnvelope envelope;
  final DeviceReport report;
  final DateTime now;

  /// The decoded Play Integrity token, when the caller passed one.
  final Map<String, Object?>? playIntegrityJson;

  /// Set by the Android key attestation check once it passed.
  KeyAttestation? keyAttestation;

  /// Set by the Play Integrity check once it read the verdict.
  PlayIntegrityVerdict? playIntegrity;

  /// Set by the App Attest check once it passed.
  AppAttestResult? appAttest;

  Rejected reject(
    RejectionReason reason,
    String message, {
    PlayIntegrityRemediation? remediation,
  }) => Rejected(
    reason,
    message,
    report: report,
    playIntegrityVerdict: playIntegrity,
    remediation: remediation,
  );
}

/// One step of the verification. Steps run in order and the first rejection
/// ends it (chain of responsibility).
abstract interface class ReportCheck {
  /// Returns a rejection, or null to hand over to the next step.
  FutureOr<Rejected?> check(VerificationContext context);
}
