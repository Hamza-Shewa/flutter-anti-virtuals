import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';

/// One nonce store for the process. Use Redis or a database table when the
/// backend runs on more than one instance.
final nonces = InMemoryNonceStore();

final verifier = SignedReportVerifier(
  nonces: nonces,
  policy: const VerificationPolicy(
    android: AndroidPolicy(
      packageNames: {'com.example.app'},
      // Play Console > Setup > App signing > App signing key certificate.
      signingCertificateDigests: {
        'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:'
            'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89',
      },
    ),
  ),
);

/// GET /nonce
String issueNonce() => nonces.issue();

/// POST /transfer with the app's `SignedReport.toJson()` as `attestation`.
Future<bool> allowTransfer(Map<String, Object?> attestation) async {
  final result = await verifier.verify(attestation);
  switch (result) {
    case Accepted(:final report, :final keyAttestation):
      print(
        'Accepted ${report.platform.name} report, '
        'patch level ${keyAttestation?.osPatchLevel}',
      );
      return true;
    case Rejected(:final reason, :final message):
      print('Rejected (${reason.name}): $message');
      return false;
  }
}

Future<void> main() async {
  // A report that was not signed by the app is rejected.
  await allowTransfer({'payload': '{}', 'signature': '', 'publicKey': ''});
}
