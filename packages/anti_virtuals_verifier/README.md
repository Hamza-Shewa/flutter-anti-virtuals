# anti_virtuals_verifier

Server-side checks for the reports that
[flutter_anti_virtuals](https://pub.dev/packages/flutter_anti_virtuals)
signs with `FlutterAntiVirtuals.instance.verify()`. Pure Dart, so it runs in
any Dart backend (shelf, dart_frog, Serverpod, Cloud Run, Lambda).
`package:anti_virtuals_verifier/io.dart` adds an HTTP transport on `dart:io`
for the clients that call Apple and Google.

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
   and vouches for the app and the device, and its environment details meet
   your rules.
6. On iOS, an App Attest attestation or assertion from your app was made for
   this payload by a key Apple attested.
7. No signal you block on was detected, and none of their checks failed.

It stops at the first failure and tells you which one. It also has clients
for the server-to-server APIs around these checks: Google's
`decodeIntegrityToken` and device recall, Apple's DeviceCheck bits and App
Attest risk metric.

## Usage

```dart
import 'package:anti_virtuals_verifier/anti_virtuals_verifier.dart';
import 'package:anti_virtuals_verifier/io.dart'; // IoHttpTransport

final nonces = InMemoryNonceStore(); // one instance only; use Redis otherwise
final appAttestKeys = InMemoryAppAttestKeyStore(); // use a database table

final verifier = SignedReportVerifier(
  nonces: nonces,
  appAttestKeys: appAttestKeys,
  policy: const VerificationPolicy(
    android: AndroidPolicy(
      packageNames: {'com.example.app'},
      signingCertificateDigests: {'AB:CD:…'}, // app signing key, SHA-256
    ),
    ios: IosPolicy(teamId: 'ABCDE12345', bundleIds: {'com.example.app'}),
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

## Play Integrity

Set `AndroidPolicy(playIntegrity: PlayIntegrityPolicy())`, decode the token
in `report['attestation']['token']` and pass the decoded
`tokenPayloadExternal`. `PlayIntegrityClient` calls `decodeIntegrityToken`
for you; you supply an OAuth access token for a service account with the
`https://www.googleapis.com/auth/playintegrity` scope (for example from
`package:googleapis_auth`):

```dart
final play = PlayIntegrityClient(
  transport: IoHttpTransport(),
  accessToken: () => credentials.accessToken.data,
);
final attestation = report['attestation'] as Map<String, Object?>;
final verdict = await play.decodeIntegrityToken(
  packageName: 'com.example.app',
  integrityToken: attestation['token'] as String,
);
final result = await verifier.verify(report, playIntegrityVerdict: verdict);
```

Classic and standard requests are both handled: the binding is read from
`requestHash` when present and from `nonce` otherwise.

By default the verdict must be bound to the payload, requested for your
package, at most two minutes old, `PLAY_RECOGNIZED` with your certificate and
`MEETS_DEVICE_INTEGRITY`. The other rules are opt in, and the environment
ones need the matching responses turned on in the Play Console:

```dart
const PlayIntegrityPolicy(
  requiredDeviceVerdict: DeviceRecognitionLabel.meetsStrongIntegrity,
  requireLicensed: true,
  // appAccessRiskVerdict.appsDetected
  rejectedAppAccessRisks: AppAccessRisk.unknownCapturingOrControlling,
  // playProtectVerdict
  acceptedPlayProtectVerdicts: {PlayProtectVerdict.noIssues},
  // recentDeviceActivity.deviceActivityLevel
  maxDeviceActivityLevel: DeviceActivityLevel.level2,
)
```

A verdict where app access risk was not evaluated passes
`rejectedAppAccessRisks`; set `requireAppAccessRiskVerdict` to reject it too.
A missing Play Protect verdict or activity level fails the rules that ask for
one.

`Accepted.playIntegrityVerdict` is the parsed verdict
(`PlayIntegrityVerdict`): request details, app integrity, device labels,
`deviceAttributes.sdkVersion`, recent device activity, device recall,
licensing and environment details, as typed fields with the exact names and
values Google uses.

### Remediation dialogs

Google Play can show the user a dialog that fixes what made a verdict fail.
When one fits, `Rejected.remediation` names it:

| Failure | `remediation` |
| --- | --- |
| `appRecognitionVerdict` is `UNRECOGNIZED_VERSION` | `getLicensed` |
| `appLicensingVerdict` is `UNLICENSED` | `getLicensed` |
| app recognition or licensing `UNEVALUATED` | `getIntegrity` |
| required device label missing | `getIntegrity` |
| `MEETS_STRONG_INTEGRITY` required and missing | `getStrongIntegrity` |
| a rejected `UNKNOWN_CAPTURING` or `UNKNOWN_CONTROLLING` app | `closeUnknownAccessRisk` |
| a rejected `KNOWN_CAPTURING` or `KNOWN_CONTROLLING` app | `closeAllAccessRisk` |
| Play Protect verdict not accepted | `getStrongIntegrity` |

Binding, package, age, certificate and activity failures have no dialog. The
enum names match the plugin's `PlayIntegrityDialog`, so send the name to the
app:

```dart
// Server
if (result case Rejected(:final remediation?)) {
  return {'dialog': remediation.name};
}

// App
final dialog = PlayIntegrityDialog.values.byName(response['dialog']);
await FlutterAntiVirtuals.instance.showPlayIntegrityDialog(dialog);
// then get a new nonce and verify again
```

### Device recall

With device recall turned on (beta), `verdict.deviceIntegrity.deviceRecall`
holds the three bits you stored for the device, which survive a reinstall
and a factory reset, and the month each was last set. To change them, use the
token you just verified (it stays usable for writes for 14 days):

```dart
await play.writeDeviceRecall(
  packageName: 'com.example.app',
  integrityToken: attestation['token'] as String,
  newValues: const DeviceRecallValues(bitFirst: true), // null bits keep their value
);
```

## iOS and App Attest

Set `VerificationPolicy(ios: IosPolicy(...))` and pass an `AppAttestKeyStore`.
The app must call `verify(nonce: ..., attestation: AttestationOptions())`.

* The first request of a key carries an attestation. The package checks the
  certificate chain up to Apple's App Attestation root (embedded in
  `AppleRoots`), the nonce extension against
  `SHA256(authData || SHA256(payload))`, the key id, `rpIdHash` against
  `SHA256("<TeamID>.<BundleID>")`, a counter of 0, the production `aaguid`
  (development only with `allowDevelopment: true`) and the credential id.
  It then saves the key with `AppAttestKeyStore.save`.
* Later requests carry assertions. The package checks the ECDSA SHA-256
  signature over `SHA256(authenticatorData || SHA256(payload))` with the
  stored key, the `rpIdHash`, and that the counter is above the stored one,
  which it moves with `compareAndSetCounter`.

Implement `AppAttestKeyStore` on your database. `save` must refuse a key id
that exists, and `compareAndSetCounter` must be atomic
(`UPDATE ... WHERE key_id = ? AND counter = ?`) so that one assertion cannot
pass twice.

`Accepted.appAttest` says what was proved: the key id, whether the key was
enrolled with this request, the counter, the environment and, for an
attestation, the receipt bytes. When a report is rejected with
`RejectionReason.unknownAppAttestKey`, your server lost the key or never got
the attestation: tell the app to call `verify` again with
`AttestationOptions(resetAppAttestKey: true)`.

Newer iOS versions add `apple_validation_category_01` (how the app was
distributed) and `apple_bundle_version_01` to the authenticator data.
`AppAttestResult` exposes both, and `IosPolicy.allowedValidationCategories`
can require, for example, `{2, 4}` (TestFlight and App Store).

`AppAttestVerifier` also works on its own, with any client data hash.

`VerificationPolicy(acceptIos: true)` without an `ios` policy still accepts
iOS reports on their signature alone, which proves nothing about the device
or the app.

## Apple server APIs

DeviceCheck and the App Attest risk metric authenticate with an ES256 JWT
made from a `.p8` key you create in your developer account with the
DeviceCheck service enabled:

```dart
final signer = AppleJwtSigner(
  teamId: 'ABCDE12345',
  keyId: 'KEY1234567',
  privateKeyPem: File('AuthKey_KEY1234567.p8').readAsStringSync(),
);
final transport = IoHttpTransport();
```

### DeviceCheck

`AttestationOptions(deviceCheck: true)` makes the app add a DeviceCheck token
(`attestation.deviceCheckToken`, also on `Accepted.deviceCheckToken`).
`DeviceCheckClient` reads and sets the two bits Apple keeps for that device:

```dart
final deviceCheck = DeviceCheckClient(transport: transport, signer: signer);
final bits = await deviceCheck.queryTwoBits(token); // null: never set
if (bits?.bit0 ?? false) return refuse('trial already used');
await deviceCheck.updateTwoBits(token, bit0: true);
```

Use `AppleEnvironment.development` for builds run from Xcode. Apple validates
the token, but it is not bound to the signed payload, so it does not prove
which device sent the report.

### App Attest risk metric

The attestation's receipt can be exchanged for one that carries a risk
metric: about how many keys were attested for your app on this device in the
last 30 days.

```dart
final receipts = AppAttestReceiptClient(transport: transport, signer: signer);
final fresh = await receipts.refresh(
  key.receipt!,
  appId: key.appId,
  publicKey: key.publicKey,
);
// null: too early (Apple answered 304), keep the old receipt
if (fresh != null) store(fresh.bytes, fresh.riskMetric, fresh.notBefore);
```

`AppAttestReceiptReader` checks a receipt before you trust it: the PKCS #7
signature over the payload, that the signing certificate chains to Apple
Root CA - G3 (embedded) within its validity dates, and, if you ask, the App
ID, the attested public key and the creation time. It does not check
certificate revocation, and it does not check which Apple service the
signing certificate was issued for.

## HTTP

The clients send requests through `HttpTransport`. `IoHttpTransport`, from
`package:anti_virtuals_verifier/io.dart`, uses `dart:io`; implement the
interface to use your own HTTP stack, or a fake in tests.

## What it does not catch

A genuine device can still run a hooked copy of your app that signs a clean
report. Key attestation and App Attest prove where the key lives and which
app created it, not what that app's code did before signing. Treat an
accepted report as one input to your risk decision.
