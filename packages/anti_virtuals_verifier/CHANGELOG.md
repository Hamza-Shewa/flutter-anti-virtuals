## 0.3.0

* **Security fix: a forged Android key attestation was accepted.** The
  verifier read the attestation from the first certificate without checking
  that the certificates above it were allowed to issue one. A key attested on
  any device, including an unlocked one running another app, could sign a
  certificate that claimed your app, a locked bootloader and the current
  nonce. A chain where a certificate above the leaf carries a key attestation
  is now rejected with `RejectionReason.untrustedChain`. Every earlier
  version is affected; update.
* `AndroidPolicy.requiredSignals` and `IosPolicy.requiredSignals` reject a
  report where one of the named signals is missing, unsupported or failed.
  Empty by default. Before, a signal in `blockOn` that the app never checked
  passed, and there was no way to insist on it.

## 0.2.0

* App Attest for iOS reports: `IosPolicy` (team ID, bundle IDs, development
  environment, App Attest required or not, accepted validation categories)
  and a check that verifies attestations (chain to Apple's App Attestation
  root, nonce, key id, `rpIdHash`, counter, `aaguid`, credential id) and
  assertions (signature, `rpIdHash`, rising counter). Keys live in an
  `AppAttestKeyStore` with an atomic counter update;
  `InMemoryAppAttestKeyStore` is the in-process version. `AppAttestVerifier`
  can be used on its own. `Accepted.appAttest` says what was proved.
* New rejection reasons `unknownAppAttestKey`, `appAttestReplay` and
  `wrongEnvironment`.
* Typed Play Integrity verdicts: `PlayIntegrityVerdict` with request details,
  app integrity, device labels, SDK version, recent device activity, device
  recall, licensing and environment details. `Accepted.playIntegrityVerdict`
  and `Rejected.playIntegrityVerdict` carry it.
* New opt-in Play Integrity rules: `rejectedAppAccessRisks`,
  `requireAppAccessRiskVerdict`, `acceptedPlayProtectVerdicts` and
  `maxDeviceActivityLevel`.
* `Rejected.remediation` names the Google Play dialog that can fix a failed
  verdict (`PlayIntegrityRemediation`, whose names match the plugin's
  `PlayIntegrityDialog`).
* `PlayIntegrityClient` decodes tokens and writes device recall bits.
* Apple server APIs: `AppleJwtSigner` (ES256 tokens from a `.p8` key),
  `DeviceCheckClient` (query, update and validate the two bits) and
  `AppAttestReceiptClient` with `AppAttestReceiptReader`, which checks a
  receipt's signature up to Apple Root CA - G3 and reads its fields,
  including the risk metric. `Accepted.deviceCheckToken` passes on the token
  the app sent.
* `HttpTransport` port for the clients. `IoHttpTransport` implements it on
  `dart:io` and lives in `package:anti_virtuals_verifier/io.dart`, so the
  main library still has no `dart:io` import.

Breaking changes:

* `PlayIntegrityPolicy.requiredDeviceVerdict` is a `DeviceRecognitionLabel?`
  instead of a `String?`. Write
  `DeviceRecognitionLabel.meetsStrongIntegrity` for
  `'MEETS_STRONG_INTEGRITY'`.
* `RejectionReason` has new values, so an exhaustive `switch` over it needs
  new cases.

## 0.1.0

* First version: nonce, freshness and signature checks, Android key
  attestation (Google roots, revocation list, challenge, security level, app
  identity, verified boot, patch level), decoded Play Integrity verdicts and
  a signal policy.
