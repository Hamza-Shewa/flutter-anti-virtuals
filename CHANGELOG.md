## 0.0.1

* Initial release: scan API with VPN, proxy, mock location, virtual camera,
  developer options, ADB, clock, installer, signature, accessibility, remote
  control, clone, user CA and sideload signals.

## Unreleased

* `ScanOptions` now has one `check*` boolean per signal (all on by default)
  instead of a `signals` set, and asserts that configured checks receive their
  configuration (`expectedSignatureSha256`, `trustedInstallers`).
* `ScanOptions` is no longer `const`; `copyWith` was replaced by `onlyChecking`.
* Added `AntiVirtualGuard`: scans at startup and on resume, blocks the app
  with a localized default screen (en, ar, fr, es) or a custom builder, and can
  force-exit after a configurable delay (default 5 seconds, off by default).
