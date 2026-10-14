import '../domain/device_report.dart';
import '../domain/policy.dart';
import '../domain/ports.dart';
import '../domain/signed_report_envelope.dart';
import '../domain/verification_result.dart';
import '../infrastructure/google_roots.dart';
import '../infrastructure/public_key.dart';
import 'checks.dart';
import 'report_check.dart';

/// Checks a report from `FlutterAntiVirtuals.verify()` on your server, in the
/// order `doc/server-verification.md` of flutter_anti_virtuals describes,
/// and stops at the first failure.
///
/// ```dart
/// final verifier = SignedReportVerifier(
///   nonces: nonceStore,
///   policy: VerificationPolicy(
///     android: AndroidPolicy(
///       packageNames: {'com.example.app'},
///       signingCertificateDigests: {'AB:CD:…'},
///     ),
///   ),
/// );
/// final result = await verifier.verify(jsonFromTheApp);
/// if (result is Rejected) return forbidden(result.reason);
/// ```
final class SignedReportVerifier {
  SignedReportVerifier({
    required NonceStore nonces,
    required this.policy,
    RevocationList? revocations,
    List<PublicKey>? trustedRoots,
    DateTime Function()? clock,
  }) : _clock = clock ?? DateTime.now,
       _checks = List.unmodifiable(<ReportCheck>[
         NonceCheck(nonces),
         FreshnessCheck(policy),
         const SignatureCheck(),
         PlatformCheck(policy),
         if (policy.android case final android?) ...[
           AndroidKeyAttestationCheck(
             android,
             trustedRoots: trustedRoots ?? GoogleAttestationRoots.keys,
             revocations: revocations,
           ),
           if (android.playIntegrity case final playIntegrity?)
             PlayIntegrityCheck(android, playIntegrity),
         ],
         SignalPolicyCheck(policy),
       ]);

  final VerificationPolicy policy;
  final DateTime Function() _clock;
  final List<ReportCheck> _checks;

  /// Verifies [json], the map the app sent (`SignedReport.toJson()`).
  ///
  /// With [AndroidPolicy.playIntegrity] set, decode the token in
  /// `json['attestation']` with Google's `decodeIntegrityToken` first and
  /// pass its `tokenPayloadExternal` as [playIntegrityVerdict].
  Future<VerificationResult> verify(
    Map<String, Object?> json, {
    Map<String, Object?>? playIntegrityVerdict,
  }) async {
    final SignedReportEnvelope envelope;
    final DeviceReport report;
    try {
      envelope = SignedReportEnvelope.fromJson(json);
      report = DeviceReport.parse(envelope.payload);
    } on FormatException catch (e) {
      return Rejected(RejectionReason.malformed, e.message);
    }
    final context = VerificationContext(
      envelope: envelope,
      report: report,
      now: _clock().toUtc(),
      playIntegrityVerdict: playIntegrityVerdict,
    );
    for (final check in _checks) {
      if (await check.check(context) case final rejected?) return rejected;
    }
    return Accepted(report, keyAttestation: context.keyAttestation);
  }
}
