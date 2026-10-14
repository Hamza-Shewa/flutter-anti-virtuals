# flutter_anti_virtuals

Detects VPNs, proxies, mock locations, virtual cameras, emulators, rooted or
jailbroken devices, hooking tools and other tampered environments in Flutter
apps. Every finding comes with the evidence behind it, and a signed version of
the report lets your server make the final decision.

Android and iOS run the checks. Web, macOS, Windows and Linux build and run
too, with every check reported as unsupported.

```dart
final report = await FlutterAntiVirtuals.instance.scan();

if (report.hasAny({AntiVirtualSignal.vpn, AntiVirtualSignal.mockLocation})) {
  print(report.toJson()); // block, warn, or send it to your server
}
```

## Contents

- [Installation](#installation)
- [Scanning the device](#scanning-the-device)
- [Blocking the app with AntiVirtualGuard](#blocking-the-app-with-antivirtualguard)
- [Using the monitor without the widget](#using-the-monitor-without-the-widget)
- [Protecting the screen](#protecting-the-screen)
- [Verifying on your server](#verifying-on-your-server)
- [Signals](#signals)
- [Limits](#limits)

The [`example/`](example/) app has a runnable file for each way of using the
plugin: `scan_example.dart`, `guard_example.dart`, `monitor_example.dart`, and
`main.dart`, which shows everything at once.

## Installation

```sh
flutter pub add flutter_anti_virtuals
```

Android needs `minSdk` 24. The plugin declares the permissions it uses
(`ACCESS_NETWORK_STATE`, plus `HIDE_OVERLAY_WINDOWS` and
`DETECT_SCREEN_RECORDING` for screen protection, all granted at install) and
the package queries for the tools it looks for. Two checks depend on what your
app already has:

* `mockLocation` reads the last location fix only when the app already holds a
  location permission. The plugin never asks for it.
* The Frida port check and Play Integrity need the `INTERNET` permission.

iOS needs iOS 15. To use App Attest, enable the App Attest capability
(entitlement `com.apple.developer.devicecheck.appattest-environment`).

## Scanning the device

`scan()` runs every check and returns a report. Call it whenever you need an
answer, for example right before a payment.

```dart
// One signal.
final vpn = await FlutterAntiVirtuals.instance.check(AntiVirtualSignal.vpn);
if (vpn.detected) print(vpn.details); // e.g. [VPN transport, tun0]

// Several, with the evidence for each.
final report = await FlutterAntiVirtuals.instance.scan(
  ScanOptions(checkDeveloperOptions: false, checkAdb: false),
);
for (final signal in report.detected) {
  print('${signal.name}: ${report[signal]!.details.join(', ')}');
}
```

Each signal ends up in one of four states:

| State | Meaning |
| --- | --- |
| detected | `result.detected`. The details say what was found |
| clean | The check ran and found nothing |
| unsupported | `result.supported` is false: the platform cannot run this check (`adb` on iOS, every check on desktop and web). Never counted as detected |
| failed | `result.failed`, with `result.error`: the check threw, or the native side left it out. Its state is unknown, so `report.isClean` is false while any check failed, and `report.failed` lists them |

`mockLocation` and `virtualCamera` also separate what is in use from what is
merely installed. A fake-GPS app that sits on the phone ends up in
`result.installedApps`, and `result.onlyInstalledApps` is true when that is all
the check found.

A scan can also throw (`PlatformException`, `MissingPluginException`). Treat
that as an unknown device:

```dart
Future<bool> deviceLooksSafe() async {
  const risky = {
    AntiVirtualSignal.rooted,
    AntiVirtualSignal.hooked,
    AntiVirtualSignal.mockLocation,
    AntiVirtualSignal.vpn,
  };
  try {
    final report = await FlutterAntiVirtuals.instance.scan();
    return report.detected.intersection(risky).isEmpty &&
        report.failed.intersection(risky).isEmpty;
  } catch (_) {
    return false;
  }
}
```

Whoever controls the device can fake what it reports, so do not trust a
client-side report for anything that matters. Use
[`verify()`](#verifying-on-your-server) and check the result on your server.

### Choosing checks

`ScanOptions` has one flag per signal (`checkVpn`, `checkProxy`,
`checkMockLocation` and so on), all on by default. Two checks need settings,
and they assert in debug builds when the settings are missing, so a
misconfigured scan fails early:

| Flag | Needs |
| --- | --- |
| `checkSignatureMismatch` | `expectedSignatureSha256`. The default `null` means "run when hashes are given", so a bare `ScanOptions()` still works. `true` without hashes fails the assertion; `false` turns the check off |
| `checkUntrustedInstaller` | A non-empty `trustedInstallers`. The default lists the major app stores |

`accessibilityAbuse` ignores the services in `allowedAccessibilityServices`,
for example `com.google.android.marvin.talkback` for TalkBack.
`checkClockTampering` works on its own by looking at the automatic date and
time settings. Pass `trustedTime` from a server response to also compare the
device clock against it.

## Blocking the app with AntiVirtualGuard

`AntiVirtualGuard` scans when the app starts and covers it with a blocking
screen while a blocking signal is detected. Put it in `MaterialApp.builder` to
guard the whole app, or around a single screen:

```dart
MaterialApp(
  builder: (context, child) => AntiVirtualGuard(
    options: ScanOptions(expectedSignatureSha256: ['<release cert sha256>']),
    child: child!,
  ),
  home: const HomePage(),
)
```

Your app is not built until the first scan finishes clean. While it is blocked,
the guard removes it from the tree, so the Android back button and deep links
cannot reach it, and rebuilds it with fresh state once the block clears. Code
that runs outside the widget tree, such as `main()` or a network call already
in flight, keeps running.

### What blocks

By default the guard blocks on `vpn`, `proxy`, `mockLocation`, `virtualCamera`
and `signatureMismatch`. Other detections only reach `onReport`.

`emulator` is left out so you can develop on an emulator or Simulator. `rooted`
is left out because refusing every rooted or jailbroken phone locks out
legitimate users in some markets, and `hooked` and `debugger` for the same
reason (a debug build started from your IDE reports a debugger). Add what your
app must refuse:

```dart
AntiVirtualGuard(
  blockOn: {
    ...AntiVirtualGuard.defaultBlockingSignals,
    AntiVirtualSignal.rooted,
    if (kReleaseMode) AntiVirtualSignal.emulator,
  },
  child: child,
)
```

An installed fake-GPS or virtual-camera app that is not in use does not block
unless you set `blockOnInstalledApps: true`. It still reaches `onReport`.

A scan that fails lets the app through. With `failClosed: true` the guard
blocks instead, both when the whole scan fails and when the check of a signal
in `blockOn` fails, and the screen says the device could not be verified.
Without it, a failed rescan keeps the previous result, so sending the app to
the background cannot clear a block.

### The blocked screen

The built-in screen lists what was found and has a Try again button that scans
again (hide it with `showRetry: false`). Its text follows the device language
and ships in English, Arabic (right to left), French and Spanish, with English
as the fallback. Change single strings with
`AntiVirtualMessages.english.copyWith(...)`, and pass
`locale: Localizations.localeOf(context)` if your app has its own language
switch.

To draw your own screen, pass `blockedBuilder`. It gets the blocking signals
in a fixed order, such as `[vpn, mockLocation]`, or an empty list when the
device could not be verified. A button on that screen can scan again through
the nearest guard:

```dart
AntiVirtualGuard(
  blockedBuilder: (context, matches) => MyBlockedPage(
    matches: matches,
    onRetry: () => AntiVirtualGuard.rescan(context),
  ),
  child: child,
)
```

### When it scans again

The guard scans again when the app comes back from the background. After a
shorter interruption (the notification shade, quick settings, Control Center,
a permission dialog) it scans when the last scan is older than
`rescanDebounce`, 3 seconds by default, which catches a VPN switched on from
quick settings. When the problem is gone, the app is shown again and a
pending exit is cancelled.

It also scans as soon as the network changes, so a VPN or proxy switched on
while the app is in front is caught right away. Android listens to
`ConnectivityManager` for VPN transport and per-network proxy changes and to
the proxy-change broadcast for a global proxy. iOS counts every
`NWPathMonitor` update. A burst of changes, such as a VPN coming up, leads to
one scan once it has been quiet for `liveDebounce` (500 ms), and never later
than four times `liveDebounce` after the first change, so a flapping network
cannot postpone it. A watcher that fails is reported through `onError` and
retried after 30 seconds.

Mock location and cameras send no change notifications, and iOS does not
report a changed proxy setting live. Those wait for the next rescan. Set
`rescanInterval` to also scan on a timer while the app is in front.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `options` | `ScanOptions()` | What to check |
| `blockOn` | see above | Detections that block |
| `blockOnInstalledApps` | `false` | Also block on a tool that is only installed |
| `failClosed` | `false` | Block when a scan, or the check of a blocking signal, fails |
| `blockedBuilder` | built-in screen | Your own blocking screen |
| `showRetry` | `true` | Show Try again on the built-in screen |
| `messages`, `locale` | device language | Text of the built-in screen |
| `waitForScan`, `loadingBuilder` | `true` | Wait for the first clean scan before building the app, showing this meanwhile |
| `unmountWhileBlocked` | `true` | Pass `false` to keep the app mounted while blocked. Its state survives; it is hidden, loses focus and has its animations paused |
| `rescanOnResume`, `rescanDebounce` | `true`, 3 s | Scan again on return to the foreground |
| `liveMonitoring`, `liveDebounce` | `true`, 500 ms | Scan again when the network changes. A change while the app is in the background is scanned on resume, even with `rescanOnResume: false` |
| `rescanInterval` | `null` | Also scan this often while in front |
| `protectScreen` | `null` | [Screen protection](#protecting-the-screen) while the guard is mounted |
| `forceExit`, `forceExitAfter` | `false`, 5 s | Close the app after blocking for this long |
| `hardExit` | `false` | Android: end the process with `exit(0)` instead of `SystemNavigator.pop()` |
| `onReport`, `onError` | none | Every finished scan, and every failure. Failures go to `FlutterError.reportError` when `onError` is not set |

Changing any of these on a mounted guard takes effect.

`forceExit` shows a countdown on the built-in screen, pauses it while the app
is in the background, and starts over on return if the problem is still there.
Apple's App Review Guidelines discourage apps that quit themselves, so it can
get an app rejected from the App Store. On iOS it calls `exit(0)`. On Android
it calls `SystemNavigator.pop()`, which finishes the activity but can leave
the process running or return to the previous activity; `hardExit` ends the
process.

## Using the monitor without the widget

`AntiVirtualMonitor` is the guard's logic without its widget: scans on
resume, on network changes and on a timer, and the blocking decision. It is a
`ValueListenable<GuardState>`, so it fits Bloc, Riverpod, a plain service, or
a check before one action:

```dart
final monitor = AntiVirtualMonitor(
  blockOn: {...AntiVirtualMonitor.defaultBlockingSignals, AntiVirtualSignal.rooted},
)..start();

ValueListenableBuilder<GuardState>(
  valueListenable: monitor,
  builder: (context, state, _) => switch (state) {
    GuardScanning() => const CircularProgressIndicator(),
    GuardAllowed() => const PayButton(),
    GuardBlocked(:final matches) => Text('Payments are off: $matches'),
  },
);

monitor.reports.listen(analytics.log); // every finished scan
await monitor.rescan();
monitor.dispose();
```

It takes the guard's scan and blocking settings (`options`, `blockOn`,
`failClosed`, `rescanOnResume`, `liveMonitoring` and the rest), and they can
change while it runs.
Inside a guard, `AntiVirtualGuard.monitorOf(context)` returns the guard's own
monitor.

The network watcher is public as well.
`FlutterAntiVirtuals.instance.environmentChanges` emits when the network setup
changes or the screen starts or stops being recorded or mirrored. It carries
no data, so call `scan()` to find out what changed, and it says nothing about
the state that already exists when you start listening. Any number of
listeners can share it. Where the native side is missing, for example in a
widget test that mocks only the method channel, it never emits.

## Protecting the screen

Screens that show balances, codes or documents can be protected from
screenshots and recording while they are visible:

```dart
AntiVirtualGuard(
  protectScreen: const ScreenProtectionOptions(),
  blockOn: {
    ...AntiVirtualGuard.defaultBlockingSignals,
    AntiVirtualSignal.screenCapture,
  },
  child: child,
)
```

| Platform | What it does |
| --- | --- |
| Android | `FLAG_SECURE`, so screenshots, recordings and casts show black and the recent-apps thumbnail is blank. `setFilterTouchesWhenObscured`, so touches that pass through another app's window on top of yours are dropped. On Android 12 and later, `setHideOverlayWindows` hides other apps' overlays while yours is in front |
| iOS | Apple has no switch for this, so the app is covered with a blur while the screen is recorded or mirrored and while the app is in the app switcher |

Protection also stops your own users from taking screenshots, so it is off by
default. You can also call `FlutterAntiVirtuals.instance.protectScreen()` and
`unprotectScreen()` yourself. Requests are combined: the window stays protected
while any guard or call still asks for it, and `unprotectScreen()` withdraws
only its own request. On Android the plugin clears only the flags it set, so a
`FLAG_SECURE` your app sets itself stays.

## Verifying on your server

`verify()` scans right now, binds the result to a nonce your backend issued and
signs it with a key created on the device for that one request:

```dart
final nonce = await api.issueNonce(); // single use, from your server
final signed = await FlutterAntiVirtuals.instance.verify(nonce: nonce);
await api.transfer(amount, report: signed.toJson());
```

On Android the key is created in StrongBox or the TEE and attested with the
SHA-256 of the nonce as its challenge. Your server can then prove that the
request is live and that it comes from your release-signed app on a device
with a locked bootloader and a verified boot. iOS signs with a Secure Enclave
key, which proves the payload was not changed on the way but not that the
device is genuine.

To also get a token from Google or Apple bound to the same payload, pass
`AttestationOptions`:

```dart
final signed = await FlutterAntiVirtuals.instance.verify(
  nonce: nonce,
  attestation: const AttestationOptions(cloudProjectNumber: 123456789012),
);
```

On Android that is a Play Integrity token, on iOS an App Attest attestation
for a new key or an assertion for an enrolled one. A classic Play Integrity
request takes a few seconds and has a low daily quota. For checks on every
login or payment, prepare a standard request at startup and use it later:

```dart
// At startup.
await FlutterAntiVirtuals.instance
    .preparePlayIntegrity(cloudProjectNumber: 123456789012);

// Per request.
final signed = await FlutterAntiVirtuals.instance.verify(
  nonce: nonce,
  attestation: const AttestationOptions(
    cloudProjectNumber: 123456789012,
    playIntegrity: PlayIntegrityRequest.standard,
  ),
);
```

### Checking it on the server

[`doc/server-verification.md`](doc/server-verification.md) lists every check
the server has to make. The
[`anti_virtuals_verifier`](packages/anti_virtuals_verifier/) package in this
repository makes them for a Dart backend: nonce, age, signature, the Android
key attestation chain up to Google's roots with the revocation list, the
attested app and boot state, a decoded Play Integrity verdict, and your signal
policy.

```dart
final verifier = SignedReportVerifier(
  nonces: nonceStore,
  policy: const VerificationPolicy(
    android: AndroidPolicy(
      packageNames: {'com.example.app'},
      signingCertificateDigests: {'AB:CD:…'},
    ),
  ),
);

final result = await verifier.verify(body['report']);
if (result is Rejected) return forbidden();
```

It does not verify App Attest objects.

## Signals

| Signal | Android | iOS | How it is detected |
| --- | --- | --- | --- |
| `vpn` | yes | yes | VPN transport and `tun`, `ppp`, `tap` or `wg` interfaces. iOS reads `utun`, `ipsec`, `tap`, `tun` and `ppp` entries in the scoped network settings, where system tunnels such as Private Relay and Wi-Fi Calling do not appear |
| `proxy` | yes | yes | Per-network proxy, PAC file, JVM proxy properties |
| `mockLocation` | yes | iOS 15+ | `Location.isMock` of a fix from the last 2 minutes, the app selected as mock location app in the developer options, known mock apps (`installedApps`). iOS: `isSimulatedBySoftware` |
| `virtualCamera` | partial | iOS 17+ | External cameras, known virtual-camera apps (`installedApps`) |
| `emulator` | yes | yes | Android needs one strong indicator (`ro.kernel.qemu` or `ro.boot.qemu`, goldfish, ranchu or vbox86 hardware, qemu and vendor files, Genymotion, BlueStacks, Nox, LDPlayer or MEmu builds and apps, Goldfish sensors) or two weak ones (generic fingerprint, SDK model or product, no sensors, operator "Android"), so real devices are not reported. iOS: Simulator build, `SIMULATOR_*` environment, host CPU as hardware model |
| `rooted` | yes | yes | Android needs one strong indicator (`su`, `magisk` or `daemonsu` in `PATH` and the usual directories, a root manager or root-hiding app such as Magisk, KernelSU, APatch, SuperSU or RootCloak, root tool files, a writable `/system`, `/vendor` or `/product`, `adbd` running as root, `ro.secure=0`, permissive SELinux, Magisk, KernelSU or APatch mounts) or two weak ones (a debug build of the system and an unlocked bootloader). iOS: jailbreak files from Cydia, Sileo, Zebra, Filza and others (rootless `/var/jb` and `/var/binpack` too), a successful write outside the sandbox, injected tweak libraries (Substrate, Substitute, libhooker, ElleKit), `DYLD_INSERT_LIBRARIES`. The Simulator is reported by `emulator` |
| `hooked` | yes | yes | Instrumentation in the app process. Android: Frida, Xposed, LSPosed, EdXposed, Substrate or Riru and Zygisk libraries in `/proc/self/maps`, Frida threads, `XposedBridge` classes, hooking managers and files, framework frames in the plugin's own call stack, Frida's default port. iOS: injected Frida, Substrate, Substitute, libhooker and ElleKit libraries, hooking classes, `DYLD_INSERT_LIBRARIES`, the Frida port |
| `debugger` | yes | yes | A Java debugger or `TracerPid` on Android, `P_TRACED` on iOS |
| `screenCapture` | yes | yes | External and wireless displays, screen recording on Android 15+, iOS `isCaptured`. Before Android 15, casting and recording through a private virtual display are invisible |
| `developerOptions` | yes | no | `DEVELOPMENT_SETTINGS_ENABLED` |
| `adb` | yes | no | USB and wireless debugging |
| `clockTampering` | yes | with `trustedTime` | Automatic time or time zone off, skew against server time |
| `untrustedInstaller` | yes | no | An installer that is not in `trustedInstallers` (Play, Galaxy Store, AppGallery, Amazon and GetApps by default). On Android 11+ an install started from the shell that claims an installer, as in `adb install -i com.android.vending`, is reported too. Builds installed with adb, debug builds included, report no installer |
| `signatureMismatch` | yes | no | Signing certificate SHA-256 against `expectedSignatureSha256` |
| `accessibilityAbuse` | yes | no | Non-system services that can read window content |
| `remoteControlApp` | yes | no | AnyDesk, TeamViewer, RustDesk and similar apps installed |
| `clonedApp` | yes | no | Unexpected data directory or process name, known cloner apps |
| `userCertificates` | yes | no | User-installed CA certificates |
| `sideloaded` | no | yes | An embedded provisioning profile |

A hooking tool can rename itself or hide its mappings, so a `hooked` detection
is strong evidence and a clean result is no evidence either way.

## Limits

A determined attacker can defeat any check that runs on the device.
Root-hiding tools (Magisk's Zygisk DenyList, Shamiko, jailbreak-detection
bypass tweaks) and a renamed or custom Frida build remove the evidence the
checks look for, and a hook installed before the plugin loads can lie about
what the process reads. Use `verify()` with `AttestationOptions` and check the
result on your server for anything that matters. See
[`doc/server-verification.md`](doc/server-verification.md) and
[`doc/hardening.md`](doc/hardening.md).

iOS reports fewer signals than Android (no developer options, ADB, installer,
signature, accessibility, remote-control, clone or user CA checks) and has no
key attestation. App Attest does not work on the Simulator. CI builds the
Swift code and runs its unit and integration tests on the Simulator, but it has
not yet been tested on a physical iPhone.

The lists of known apps (mock location, remote control, cloners, root
managers, hooking apps) need updates as new tools appear. Location and camera
spoofing done through hooks is invisible to these checks.

Android keeps the last fix of every location provider, so only fixes younger
than two minutes count (a running mock app injects one about every second),
and it hands out last-known locations only while the app is in the
foreground.

Play Integrity needs Google Play services on the device and has a daily quota
per Google Cloud project.

## License

MIT, see [LICENSE](LICENSE).
