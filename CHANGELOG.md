## 0.0.1

* Initial release: scan API with VPN, proxy, mock location, virtual camera,
  developer options, ADB, clock, installer, signature, accessibility, remote
  control, clone, user CA and sideload signals.

## Unreleased

* New `rooted` signal (`ScanOptions.checkRooted`, on by default) for Android
  root and iOS jailbreak. Android: one strong indicator (`su`/Magisk binaries
  in `PATH` and the usual directories, root manager and root-hiding apps, root
  tool files, a writable `/system`, `/vendor` or `/product`, `adbd` as root,
  `ro.secure=0`, permissive SELinux, Magisk/KernelSU/APatch mounts) or two weak
  ones (a debug build of the system plus an unlocked bootloader). iOS: Cydia,
  Sileo, Zebra and other jailbreak files (including rootless `/var/jb`),
  writing outside the sandbox, injected tweak libraries and
  `DYLD_INSERT_LIBRARIES`. Localized for the guard's default screen; not in
  `defaultBlockingSignals`.
* New `emulator` signal (`ScanOptions.checkEmulator`, on by default): Android
  emulators (Android Studio, Genymotion, BlueStacks, Nox, LDPlayer, MEmu, ...)
  from qemu properties, emulator hardware, files, apps and sensors, needing
  one strong or two weak indicators so real devices are not reported; the iOS
  Simulator from the build target, `SIMULATOR_*` variables and the hardware
  model. Localized for the guard's default screen; not in
  `defaultBlockingSignals`.
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
* Live detection review fixes: `environmentChanges` is one shared stream (a
  second listener no longer breaks the first), a missing native side is quiet,
  a change in the background is scanned on resume even without
  `rescanOnResume`, bursts are capped at `liveDebounce` x 4, watcher failures
  are labelled as such and retried, Android keeps network state from the
  callback arguments instead of querying on every update, iOS emits on every
  path update, ignores updates from a cancelled monitor and tears down on
  engine detach.
* Fix: Android now reports a proxy set globally (for example with
  `adb shell settings put global http_proxy`) through `environmentChanges`. The
  settings observer it relied on does not fire when the value is set, so the
  watcher also listens to the system's proxy-change broadcast.
* Fix: Android `mockLocation` ignores mock fixes older than two minutes. The
  last fix of a provider is cached, so a mock location that had been switched
  off kept the device flagged (and the app blocked) for several minutes.
