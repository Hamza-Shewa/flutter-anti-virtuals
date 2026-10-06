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
* Guard: the app is not built before the first clean scan, blocked apps lose
  focus and animations, the force-exit countdown pauses in the background,
  rescans only follow a real background trip, and a failed rescan fails open.
* Guard: `ScanOptions` compares by value (no rescan on every parent rebuild);
  a failed rescan keeps the last result; new `failClosed`, `rescanDebounce`,
  `rescanInterval`, `unmountWhileBlocked` and `hardExit` options; the countdown
  restarts after a background trip even without a rescan; `copyWith` keeps
  `textDirection`; the screen follows device locale changes.
* Guard: `unmountWhileBlocked` is `true` by default, so a blocked app cannot be
  reached with the back button; pass `false` to keep it mounted and keep state.
* Live detection: `FlutterAntiVirtuals.environmentChanges` emits when a VPN or
  proxy may have been switched on or off (Android `ConnectivityManager`
  callbacks, iOS `NWPathMonitor`), and `AntiVirtualGuard` rescans on it
  (`liveMonitoring`, `liveDebounce`).
