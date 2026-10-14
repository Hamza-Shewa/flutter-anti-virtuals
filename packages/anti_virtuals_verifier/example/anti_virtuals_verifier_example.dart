import 'dart:io';

import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:anti_virtuals_verifier/io.dart';

/// One nonce store and one App Attest key store for the process. Use Redis
/// or a database table when the backend runs on more than one instance.
final nonces = InMemoryNonceStore();
final appAttestKeys = InMemoryAppAttestKeyStore();

final verifier = SignedReportVerifier(
  nonces: nonces,
  appAttestKeys: appAttestKeys,
  policy: const VerificationPolicy(
    android: AndroidPolicy(
      packageNames: {'com.example.app'},
      // Play Console > Setup > App signing > App signing key certificate.
      signingCertificateDigests: {
        'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:'
            'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89',
      },
    ),
    // Membership > Team ID, and the app's bundle identifier.
    ios: IosPolicy(teamId: 'ABCDE12345', bundleIds: {'com.example.app'}),
  ),
);

/// GET /nonce
String issueNonce() => nonces.issue();

/// POST /transfer with the app's `SignedReport.toJson()` as `report`.
/// Returns what to answer the app.
Future<Map<String, Object?>> allowTransfer(Map<String, Object?> report) async {
  final result = await verifier.verify(report);
  switch (result) {
    case Accepted(:final report, :final keyAttestation, :final appAttest):
      print(
        'Accepted ${report.platform.name} report, '
        'patch level ${keyAttestation?.osPatchLevel}, '
        'App Attest key ${appAttest?.keyId}',
      );
      return {'ok': true};
    case Rejected(reason: RejectionReason.unknownAppAttestKey):
      // The app should call verify(attestation:
      // AttestationOptions(resetAppAttestKey: true)) to enroll a new key.
      return {'ok': false, 'resetAppAttestKey': true};
    case Rejected(:final reason, :final message, :final remediation):
      print('Rejected (${reason.name}): $message');
      // The app can show this Google Play dialog, then verify again.
      return {'ok': false, 'dialog': ?remediation?.name};
  }
}

/// Uses DeviceCheck to let each iPhone claim a trial once. Needs a `.p8` key
/// with the DeviceCheck service enabled.
Future<bool> claimTrial(String deviceCheckToken) async {
  final transport = IoHttpTransport();
  try {
    final deviceCheck = DeviceCheckClient(
      transport: transport,
      signer: AppleJwtSigner(
        teamId: 'ABCDE12345',
        keyId: 'KEY1234567',
        privateKeyPem: File('AuthKey_KEY1234567.p8').readAsStringSync(),
      ),
    );
    final bits = await deviceCheck.queryTwoBits(deviceCheckToken);
    if (bits?.bit0 ?? false) return false;
    await deviceCheck.updateTwoBits(deviceCheckToken, bit0: true);
    return true;
  } finally {
    transport.close();
  }
}

Future<void> main() async {
  // A report that was not signed by the app is rejected.
  print(
    await allowTransfer({'payload': '{}', 'signature': '', 'publicKey': ''}),
  );
}
