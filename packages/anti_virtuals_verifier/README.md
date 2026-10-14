# anti_virtuals_verifier

Server-side checks for the reports that
[flutter_anti_virtuals](https://pub.dev/packages/flutter_anti_virtuals)
signs with `FlutterAntiVirtuals.instance.verify()`. Pure Dart, so it runs in
any Dart backend (shelf, dart_frog, Serverpod, Cloud Run, Lambda).

The app's own verdict runs on a device the user controls. This package is the
part that decides on your server, in the order
[server-verification.md](https://github.com/Hamza-Shewa/flutter-anti-virtuals/blob/main/doc/server-verification.md)
describes:

1. The nonce is one you issued and is used once.
2. `issuedAt` is recent.
3. The signature matches the payload.
4. On Android, the signing key was created in a TEE or StrongBox for this
   nonce, by your app signed with your certificate, on a device with a
   verified boot and a locked bootloader. The certificate chain must end at
   one of Google's hardware attestation roots and none of its certificates
   may be revoked.
5. Optionally, a decoded Play Integrity verdict is bound to the same payload
   and vouches for the app and the device.
6. No signal you block on was detected, and none of their checks failed.

It stops at the first failure and tells you which one.

## Usage

```dart
import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';

final nonces = InMemoryNonceStore(); // one instance only; use Redis otherwise

final verifier = SignedReportVerifier(
  nonces: nonces,
  policy: const VerificationPolicy(
    android: AndroidPolicy(
      packageNames: {'com.example.app'},
      signingCertificateDigests: {'AB:CD:…'}, // app signing key, SHA-256
    ),
  ),
);

// GET /nonce
final nonce = nonces.issue();

// POST /transfer, where the app sent signed.toJson() as "report"
final report = body['report'] as Map<String, Object?>;
final result = await verifier.verify(report);
switch (result) {
  case Accepted():
    // go ahead
  case Rejected(:final reason, :final message):
    log('rejected: ${reason.name} $message');
    // refuse, without telling the client which check failed
}
```

`signingCertificateDigests` is the SHA-256 of the certificate your users'
copy of the app is signed with. With Play App Signing that is the app signing
key in the Play Console (Setup, App signing), not your upload key.

### Nonces

`NonceStore.consume` must return true once for a nonce you issued and false
for anything else, atomically. `InMemoryNonceStore` does that inside one
process. With several server instances, implement `NonceStore` on Redis
(`GETDEL`) or a database row you delete in the same statement that reads it.

### Revocation

Google revokes leaked attestation keys through a status list. Fetch
`https://android.googleapis.com/attestation/status`, cache it for a few hours
and pass it in:

```dart
final status = jsonDecode(await http.read(statusUrl)) as Map<String, Object?>;
final verifier = SignedReportVerifier(
  nonces: nonces,
  policy: policy,
  revocations: GoogleStatusList(status),
);
```

Without it, a chain from a device whose keys leaked still passes.

### Play Integrity

Set `AndroidPolicy(playIntegrity: PlayIntegrityPolicy())`, decode the token
in `report['attestation']['token']` with Google's `decodeIntegrityToken` (it
needs your service account), and pass the decoded `tokenPayloadExternal`:

```dart
final result = await verifier.verify(
  report,
  playIntegrityVerdict: decoded['tokenPayloadExternal'],
);
```

Classic and standard requests are both handled: the binding is read from
`requestHash` when present and from `nonce` otherwise.

### iOS

iOS reports are rejected unless you set `VerificationPolicy(acceptIos: true)`.
Their signature proves the payload was not changed on the way, but iOS has no
key attestation, so nothing proves the device is genuine. This package does
not verify App Attest; follow Apple's guide for that.

## What it does not catch

A genuine device can still run a hooked copy of your app that signs a clean
report. Key attestation proves where the key lives and which app created it,
not what that app's code did before signing. Treat an accepted report as one
input to your risk decision.
