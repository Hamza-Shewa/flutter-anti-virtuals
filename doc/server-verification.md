# Verifying a device report on your server

Everything the app computes runs on a device its user controls. A rooted or
hooked device can make `scan()` return a clean report, so a client-side
verdict is a convenience, not a security boundary. `verify()` produces a
report that a server can check.

```dart
// 1. Ask your backend for a fresh nonce (single use, short lived).
final nonce = await api.issueNonce();

// 2. Scan and sign it, right before the sensitive action.
final signed = await FlutterAntiVirtuals.instance.verify(nonce: nonce);

// 3. Send it. The backend decides.
await api.transfer(amount, attestation: signed.toJson());
```

`toJson()` contains:

| Field | Meaning |
| --- | --- |
| `payload` | The exact text that was signed: `{"v":1,"nonce":…,"issuedAt":<ms>,"platform":"android"\|"iOS","signals":{"vpn":{"detected":false,"supported":true},…}}`. A check that failed on the device also carries `"failed":true`; treat it as unknown, not clean. A detection that only rests on an installed tool carries `"installedOnly":true`. Do not re-encode it. |
| `signature` | Base64 `SHA256withECDSA` signature (DER) over the UTF-8 bytes of `payload`. |
| `publicKey` | Base64 public key. Android: X.509 SubjectPublicKeyInfo. iOS: ANSI X9.63 uncompressed point. |
| `protection` | `strongBox`, `hardware` or `software`. Treat `software` as no device binding. |
| `attested` | Android only: the chain below carries a hardware key attestation. |
| `certificateChain` | Android only: base64 DER certificates, attested leaf first. |
| `attestation` | Only with `verify(attestation: ...)`: `type` (`playIntegrity` or `appAttest`), `token` (the Play Integrity token, or the base64 App Attest object), `standard` (Play Integrity: a standard request), `keyId` and `assertion` (App Attest: the base64 key id, and false for an attestation, true for an assertion), `deviceCheckToken` (iOS with `deviceCheck: true`: a base64 DeviceCheck token). |

## What the server must check

Do these in order and reject on the first failure. A Dart backend can use the
[`anti_virtuals_verifier`](../packages/anti_virtuals_verifier/) package, which
makes all of them, App Attest included, and has clients for the Google and
Apple server APIs below.

1. **Nonce.** `payload.nonce` is one you issued, has not been used before and
   has not expired. Delete it as you check it. This is what stops replay.
2. **Freshness.** `payload.issuedAt` is within a minute or two of your clock.
3. **Signature.** `signature` verifies over `payload` with `publicKey`.
4. **Key origin (Android).** Require `attested` and verify the chain:
   * each certificate is signed by the next and the last one is a Google
     hardware attestation root (use Google's published roots and revocation
     list, which change; do not pin a single root forever);
   * the leaf public key equals `publicKey`;
   * the key attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`) has
     `attestationChallenge` equal to the SHA-256 of the nonce. This proves the
     key was created for this request on a real device;
   * `attestationSecurityLevel` is `TrustedEnvironment` or `StrongBox`;
   * `attestationApplicationId` holds your package name and the SHA-256 of
     your release signing certificate (this is the tamper check that cannot be
     faked from inside the app);
   * `rootOfTrust.verifiedBootState` is `Verified` and `deviceLocked` is true.
     An unlocked bootloader or a custom ROM fails here, which is stronger than
     any on-device root check.
5. **Policy.** Only now read `payload.signals` and decide, for example reject
   when `rooted`, `hooked`, `emulator` or `mockLocation` is detected.

## Platform attestation (Play Integrity, App Attest)

`verify(nonce: ..., attestation: AttestationOptions())` also asks Google or
Apple for a token bound to the same payload, so the backend can confirm the
device and the app with the platform vendor instead of trusting the report. The
binding is the SHA-256 of the UTF-8 bytes of `payload`; because the payload
contains the nonce, the nonce is covered too. The token is in
`toJson()['attestation']`.

### Android: Play Integrity

`attestation.token` is a Play Integrity token. Never decode it on the device.
Your backend calls Google's `decodeIntegrityToken` (service account, or the
Play Integrity API with your Google Cloud project) and checks:

* the binding matches: the URL-safe base64 without padding of the SHA-256 of
  the `payload` you received equals `requestDetails.nonce` for a classic
  request, or `requestDetails.requestHash` for a standard one
  (`attestation.standard` is `true`). Also check that
  `requestDetails.requestPackageName` is your package and `timestampMillis`
  is recent;
* `appIntegrity.appRecognitionVerdict` is `PLAY_RECOGNIZED` and
  `certificateSha256Digest` is your release certificate;
* `deviceIntegrity.deviceRecognitionVerdict` contains
  `MEETS_DEVICE_INTEGRITY` (or `MEETS_STRONG_INTEGRITY` for the most
  sensitive actions);
* optionally `accountDetails.appLicensingVerdict` is `LICENSED`;
* optionally the environment details and device activity, once you turn
  these responses on in the Play Console (Protected with Play, Play Integrity
  API, Change responses): `environmentDetails.appAccessRiskVerdict.appsDetected`
  has no `UNKNOWN_CAPTURING` or `UNKNOWN_CONTROLLING` (apps not from Play
  that could read the screen or control the device; the `KNOWN_` values are
  the same for Play and system apps), `environmentDetails.playProtectVerdict`
  is `NO_ISSUES`, and `deviceIntegrity.recentDeviceActivity.deviceActivityLevel`
  is not above what your app normally reaches (`LEVEL_1` to `LEVEL_4`, by
  the number of tokens your app requested on the device in the last hour).
  An empty `appAccessRiskVerdict` means Play did not evaluate it.

Both request types are decoded with the same `decodeIntegrityToken` call.

**Classic** (the default) is one self-contained request. It takes a few
seconds and the quota is per project and day, so request it before rare,
high-value actions. Pass `AttestationOptions(cloudProjectNumber: ...)` unless
the app is on Google Play and linked to that project in the Play Console.

**Standard** is faster and has a much higher quota, which suits checks on
every login or payment:

```dart
// At startup: Play prepares a token provider in the background.
await FlutterAntiVirtuals.instance
    .preparePlayIntegrity(cloudProjectNumber: 123456789012);

// Later, per request:
final signed = await FlutterAntiVirtuals.instance.verify(
  nonce: nonce,
  attestation: const AttestationOptions(
    cloudProjectNumber: 123456789012,
    playIntegrity: PlayIntegrityRequest.standard,
  ),
);
```

`verify` prepares on its own if you skipped that step, and prepares again
when Play reports the provider expired. A standard request always needs
`cloudProjectNumber`. Either way the app needs the `INTERNET` permission.

#### Remediation dialogs

When a verdict fails for a reason the user can fix, Google Play can show a
dialog for it. The server picks the dialog and tells the app, which shows it
with `showPlayIntegrityDialog` in the same app session as the request it
verified:

| Verdict | Dialog (`PlayIntegrityDialog`) |
| --- | --- |
| `appLicensingVerdict` is `UNLICENSED`, or `appRecognitionVerdict` is `UNRECOGNIZED_VERSION` | `getLicensed` (`GET_LICENSED`) |
| `appsDetected` has `UNKNOWN_CAPTURING` or `UNKNOWN_CONTROLLING` | `closeUnknownAccessRisk` (`CLOSE_UNKNOWN_ACCESS_RISK`) |
| `appsDetected` has `KNOWN_CAPTURING` or `KNOWN_CONTROLLING` | `closeAllAccessRisk` (`CLOSE_ALL_ACCESS_RISK`) |
| no `MEETS_DEVICE_INTEGRITY`, or licensing or app recognition `UNEVALUATED` | `getIntegrity` (`GET_INTEGRITY`) |
| no `MEETS_STRONG_INTEGRITY`, or a `playProtectVerdict` other than `NO_ISSUES` | `getStrongIntegrity` (`GET_STRONG_INTEGRITY`) |

```dart
// The server answered {"dialog": "getIntegrity"}.
final result = await FlutterAntiVirtuals.instance.showPlayIntegrityDialog(
  PlayIntegrityDialog.values.byName(response['dialog']),
);
// successful only means the user went through it: get a new nonce and
// verify again.
```

`anti_virtuals_verifier` puts the dialog in `Rejected.remediation`.

#### Device recall

Device recall (beta, opt in from the same Play Console page) stores three
bits per device with Google. They survive a reinstall and a factory reset,
and every app in your developer account shares them. The verdict carries
them as `deviceIntegrity.deviceRecall.values` (`bitFirst`, `bitSecond`,
`bitThird`) and `writeDates` (`yyyymmFirst` and so on, set while a bit is
true). To change them, your server calls Google with a token it already
verified, within 14 days:

```
POST https://playintegrity.googleapis.com/v1/<packageName>/deviceRecall:write
Authorization: Bearer <OAuth token with the playintegrity scope>

{"integrityToken": "<token>", "newValues": {"bitFirst": true}}
```

Bits you leave out keep their value. Setting a bit to false clears its write
date. The new value can take up to 30 seconds to show in verdicts; a
standard request sees it after the provider is prepared again.

### iOS: App Attest

Enable the App Attest capability (entitlement
`com.apple.developer.devicecheck.appattest-environment`, `development` or
`production`). The Simulator does not support it and `verify` then throws.

The client data hash the app passes to App Attest is the SHA-256 of the UTF-8
bytes of `payload`. Check every object against that hash, computed from the
`payload` you received.

* The first request of a key returns an attestation (`assertion: false`), a
  CBOR object with `fmt` `apple-appattest`. Verify it as Apple documents:
  the `x5c` chain leads to the Apple App Attestation Root CA, the nonce
  extension (OID `1.2.840.113635.100.8.2`) of the first certificate equals
  `SHA256(authData || clientDataHash)`, `keyId` is the SHA-256 of that
  certificate's public key, `authData.rpIdHash` is
  `SHA256("<TeamID>.<BundleID>")`, the counter is 0, the AAGUID is
  `appattest` followed by seven zero bytes (production) or
  `appattestdevelop` (development), and the credential id equals `keyId`.
  Then store `keyId`, the public key, the counter (0) and the receipt from
  `attStmt.receipt`. A `keyId` you already store must not be enrolled again.
* Every later request returns an assertion (`assertion: true`), a CBOR map
  with `signature` and `authenticatorData`. Verify the signature (ECDSA with
  SHA-256) over `nonce = SHA256(authenticatorData || clientDataHash)` with
  the stored public key, the `rpIdHash`, and that the counter is greater
  than the stored one. Store the new counter in the same atomic step that checks
  the old one, so that one assertion cannot pass twice.
* If your backend does not know `keyId` (the first request never arrived, the
  database was reset), call `verify` again with
  `AttestationOptions(resetAppAttestKey: true)` to enroll a new key. Do not do
  this on every request: Apple rate limits key attestation.
* Recent iOS versions add `apple_validation_category_01` (how the app was
  distributed: 2 TestFlight, 3 development signed, 4 App Store, 5 Enterprise
  or ad hoc) and `apple_bundle_version_01` to the authenticator data. Check
  them if you want to refuse, for example, development builds.

`anti_virtuals_verifier` does all of this with
`VerificationPolicy(ios: IosPolicy(teamId: ..., bundleIds: {...}))` and an
`AppAttestKeyStore` for the keys.

#### Risk metric

A compromised device can serve assertions to many copies of an app. Apple
counts how many keys were attested for your app on a device in the last 30
days. To read it, POST the base64 receipt to
`https://data.appattest.apple.com/v1/attestationData`
(`data-development.appattest.apple.com` for development keys) with an
`Authorization` header holding the JWT described under DeviceCheck. Apple
answers with a new base64 receipt (PKCS #7). Check its signature up to Apple
Root CA - G3, that field 2 is your App ID, that the creation time (field 12)
is at most five minutes old and that field 3 holds the key you stored; the
risk metric is field 17. Store the new receipt and send it next time, after
its "not before" time (field 19, Apple answers 304 before) and before it
expires (field 21). `anti_virtuals_verifier` has `AppAttestReceiptClient`
for this.

### iOS: DeviceCheck

`AttestationOptions(deviceCheck: true)` also adds a DeviceCheck token
(`attestation.deviceCheckToken`). With it your server can read and set two
bits that Apple keeps per device for your team. They survive a reinstall,
which suits "already claimed the trial" or "banned".

Send JSON with `device_token`, a unique `transaction_id` and `timestamp` (ms)
to `https://api.devicecheck.apple.com/v1/query_two_bits`, `update_two_bits`
(with `bit0` and `bit1`) or `validate_device_token`
(`api.development.devicecheck.apple.com` for builds run from Xcode). The
`Authorization: Bearer` header holds a JWT signed with ES256 by a `.p8` key
you create with the DeviceCheck service enabled: header `alg` `ES256` and
`kid` the key id, claims `iss` your Team ID and `iat` the time in seconds,
at most an hour old. A query answers `{"bit0": ..., "bit1": ...,
"last_update_time": "YYYY-MM"}`, or the text `Bit State Not Found` for a
device whose bits were never set.

Apple checks that the token comes from a genuine Apple device and an app of
your team, but the token is not bound to the signed payload, so it does not
prove which device sent the report. Treat the bits as memory about a device,
next to App Attest. `anti_virtuals_verifier` has `DeviceCheckClient` and
`AppleJwtSigner` for this.

## iOS without App Attest

iOS has no key attestation, so without App Attest the signature only proves
that the payload was not altered in transit and was produced with a fresh
key. It does not prove the device or the app is genuine. Treat such a report
as advisory.

## What this does not protect against

* A device whose attestation is genuine but whose app process is hooked while
  `verify()` runs can still sign a falsified `signals` map. The attestation
  proves the device and the app signature, not the honesty of the app's
  runtime, so combine it with the `hooked` and `debugger` signals, Play
  Integrity, and server-side behavior checks.
* Nonces must be issued and tracked by your backend. A nonce generated on the
  client defeats the replay protection.
