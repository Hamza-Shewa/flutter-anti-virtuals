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
| `payload` | The exact text that was signed: `{"v":1,"nonce":…,"issuedAt":<ms>,"platform":"android"\|"iOS","signals":{"vpn":{"detected":false,"supported":true},…}}`. Do not re-encode it. |
| `signature` | Base64 `SHA256withECDSA` signature (DER) over the UTF-8 bytes of `payload`. |
| `publicKey` | Base64 public key. Android: X.509 SubjectPublicKeyInfo. iOS: ANSI X9.63 uncompressed point. |
| `protection` | `strongBox`, `hardware` or `software`. Treat `software` as no device binding. |
| `attested` | Android only: the chain below carries a hardware key attestation. |
| `certificateChain` | Android only: base64 DER certificates, attested leaf first. |

## What the server must check

Do these in order and reject on the first failure.

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

* `requestDetails.nonce` is the URL-safe base64 without padding of the SHA-256
  of the `payload` you received, `requestDetails.requestPackageName` is your
  package and `timestampMillis` is recent;
* `appIntegrity.appRecognitionVerdict` is `PLAY_RECOGNIZED` and
  `certificateSha256Digest` is your release certificate;
* `deviceIntegrity.deviceRecognitionVerdict` contains
  `MEETS_DEVICE_INTEGRITY` (or `MEETS_STRONG_INTEGRITY` for the most
  sensitive actions);
* optionally `accountDetails.appLicensingVerdict` is `LICENSED`.

Pass `AttestationOptions(cloudProjectNumber: ...)` unless the app is on Google
Play and linked to that project in the Play Console. The token is a classic
request, so the quota is per project and day: request it before sensitive
actions, not on every launch. The app needs the `INTERNET` permission.

### iOS: App Attest

Enable the App Attest capability (entitlement
`com.apple.developer.devicecheck.appattest-environment`, `development` or
`production`). The Simulator does not support it and `verify` then throws.

* The first request of a key returns an **attestation** (`assertion: false`).
  Verify it as Apple documents: the CBOR object's `x5c` chain leads to the
  Apple App Attestation root, the nonce extension (OID
  `1.2.840.113635.100.8.2`) equals `SHA256(authData || SHA256(payload))`,
  `authData.rpIdHash` is `SHA256("<TeamID>.<BundleID>")`, the counter is 0,
  the AAGUID is `appattest` (production) and the credential id equals `keyId`.
  **Store `keyId` and the public key from the certificate**; this enrolls the
  device.
* Every later request returns an **assertion** (`assertion: true`). Verify the
  signature over `authData || SHA256(payload)` with the stored public key, the
  `rpIdHash`, and that the counter is greater than the stored one, then store
  the new counter.
* If your backend does not know `keyId` (the first request never arrived, the
  database was reset), call `verify` again with
  `AttestationOptions(resetAppAttestKey: true)` to enroll a new key. Do not do
  this on every request: Apple rate limits key attestation.

## iOS without App Attest

iOS has no key attestation, so on iOS the signature only proves that the
payload was not altered in transit and was produced with a fresh key. It does
not prove the device is genuine. Use Apple App Attest for that (see the
attestation guide) and treat an iOS `verify()` report as advisory until it is
bound to an App Attest assertion.

## What this does not protect against

* A device whose attestation is genuine but whose app process is hooked while
  `verify()` runs can still sign a falsified `signals` map. The attestation
  proves the device and the app signature, not the honesty of the app's
  runtime, so combine it with the `hooked` and `debugger` signals, Play
  Integrity, and server-side behavior checks.
* Nonces must be issued and tracked by your backend. A nonce generated on the
  client defeats the replay protection.
