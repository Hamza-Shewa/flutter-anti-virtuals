# flutter_anti_virtuals

Detects VPNs, proxies, mock locations, virtual cameras, emulators, rooted or
jailbroken devices, hooking tools and other tampered environments in Flutter
apps. Every finding comes with the evidence behind it, and a signed version of
the report lets your server make the final decision.

Android and iOS run most of the checks. macOS, Windows and Linux check for
VPNs, proxies, debuggers and virtual machines, and the web checks for browser
automation. See [Platform support](#platform-support).

```dart
final report = await FlutterAntiVirtuals.instance.scan();

if (report.hasAny({AntiVirtualSignal.vpn, AntiVirtualSignal.mockLocation})) {
  print(report.toJson()); // block, warn, or send it to your server
}
```

## Contents

- [Platform support](#platform-support)
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

## Platform support

| Feature | Android | iOS | macOS, Windows, Linux | Web |
| --- | --- | --- | --- | --- |
| [Signals](#signals) checked by `scan()` and `check()` | 22 of 23 | 15 of 23 | 5 of 23 | 2 of 23 |
| `AntiVirtualGuard` and `AntiVirtualMonitor` | Yes | Yes | Yes | Yes |
| Live change events (`environmentChanges`), which trigger a rescan | Network, displays, recording and calls | Network, recording and displays | No, the stream never emits | No, the stream never emits |
| [Screenshot events](#protecting-the-screen) (`screenshots`) | Android 14+ | Yes | No | No |
| [Screen protection](#protecting-the-screen) | `FLAG_SECURE`, touch filtering, overlay hiding on Android 12+ | Blur while recorded, mirrored or in the app switcher | No, the calls do nothing | No, the calls do nothing |
| [`verify()`](#verifying-on-your-server) signed report | Hardware key with key attestation (StrongBox or TEE) | Secure Enclave key, no attestation | Throws `UnsupportedError` | Throws `UnsupportedError` |
| Platform attestation | Play Integrity, classic and standard, with remediation dialogs | App Attest (not on the Simulator) and a DeviceCheck token | Throws `UnsupportedError` | Throws `UnsupportedError` |
| `forceExit` | `SystemNavigator.pop()`, or `exit(0)` with `hardExit` | `exit(0)` | `exit(0)` | Keeps the blocking screen up |
| Minimum version | Android 7.0 (API 24) | iOS 15 | Flutter's own minimums | Flutter's own minimums |

Android leaves out `sideloaded`, which only applies to iOS. iOS leaves out
`automation` and seven Android-only checks: `developerOptions`, `adb`,
`untrustedInstaller`, `accessibilityAbuse`, `remoteControlApp`, `clonedApp` and
`userCertificates`. On iOS, `virtualCamera` needs iOS 17, `clockTampering`
needs a `trustedTime` and `signatureMismatch` needs `expectedTeamIds`.

macOS, Windows and Linux check `vpn`, `proxy`, `debugger`, `emulator` (a
virtual machine) and `clockTampering` against a `trustedTime`. The web checks
`automation` and `clockTampering`. These checks are written in Dart; see
[On desktop and the web](#on-desktop-and-the-web). Every other signal is
unsupported there, and an unsupported result never counts as detected or
failed.

## Installation

```sh
flutter pub add flutter_anti_virtuals
```

Android needs `minSdk` 24. The plugin declares the permissions it uses
(`ACCESS_NETWORK_STATE`, `HIDE_OVERLAY_WINDOWS` and `DETECT_SCREEN_RECORDING`
for screen protection, and `DETECT_SCREEN_CAPTURE` for screenshot events, all
granted at install) and the package queries for the tools it looks for. Two
checks depend on what your app already has:

* `mockLocation` reads the last location fix only when the app already holds a
  location permission. The plugin never asks for it.
* The Frida port check and Play Integrity need the `INTERNET` permission.

iOS needs iOS 15. To use App Attest, enable the App Attest capability
(entitlement `com.apple.developer.devicecheck.appattest-environment`).
DeviceCheck tokens need no capability. The `activeCall` check loads CallKit
when it first runs. CallKit is not allowed in apps sold in mainland China, so
turn the check off there with `ScanOptions(checkActiveCall: false)`.

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
| unsupported | `result.supported` is false: the platform cannot run this check (`adb` on iOS, `rooted` on desktop). Never counted as detected |
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
| `checkSignatureMismatch` | `expectedSignatureSha256` (Android) or `expectedTeamIds` (iOS), or both. The default `null` means "run when either is given", so a bare `ScanOptions()` still works. `true` without either fails the assertion; `false` turns the check off. A platform whose list is empty reports the check as unsupported |
| `checkUntrustedInstaller` | A non-empty `trustedInstallers`. The default lists the major app stores |

`accessibilityAbuse` ignores the services in `allowedAccessibilityServices`,
for example `com.google.android.marvin.talkback` for TalkBack.
`checkClockTampering` works on its own by looking at the automatic date and
time settings. Pass `trustedTime` from a server response to also compare the
device clock against it.

### Fraud context

Three checks look at the situation a scam needs rather than at tampering.
None of them blocks by default; add them to `blockOn`, or better, ask for a
second factor or slow down a payment when they fire.

* `activeCall` fires while a phone or VoIP call is in progress. Scammers keep
  victims on the line while they approve a transfer. Android reads the audio
  mode (no permission needed) and a call starting or ending emits on
  `environmentChanges` on Android 12 and later. iOS asks CallKit.
* `noScreenLock` fires when the device has no PIN, pattern, password or
  passcode, so anyone holding the phone gets into a signed-in app.
* `appDataMigrated` fires when the app's data was created on another device:
  restored from a backup onto a new phone, moved with a device transfer or
  copied off a rooted one. A session token that came along with it should not
  be trusted. The plugin keeps an id in the app's data and a key or Keychain
  item that stays on the device. After the user signs in again, accept the
  data on this device:

```dart
final report = await FlutterAntiVirtuals.instance.scan();
if (report.isDetected(AntiVirtualSignal.appDataMigrated)) {
  await signOut();
  // ... once the user has signed in again:
  await FlutterAntiVirtuals.instance.rebindDevice();
}
```

The first scan after installing the app binds it, so it never fires on a
fresh install. An app that turns backups off (`android:allowBackup="false"`)
never sees it on Android.

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
changes, the screen starts or stops being recorded or mirrored, or (Android 12
and later) a call starts or ends. It carries no data, so call `scan()` to find
out what changed, and it says nothing about the state that already exists when
you start listening. Any number of listeners can share it. Where the native
side is missing, for example in a widget test that mocks only the method
channel, it never emits.

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

To learn about screenshots without blocking them, listen to
`FlutterAntiVirtuals.instance.screenshots`. It emits after the user takes one:
on Android 14 and later while your activity is visible (Android then tells the
user that the app noticed; screenshots taken through adb are not reported),
and on iOS. It never emits elsewhere.

```dart
FlutterAntiVirtuals.instance.screenshots.listen((_) {
  analytics.log('screenshot on the card details screen');
});
```

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

When the verdict fails, Google Play can often fix it with one of its own
dialogs: get the app from Play, close apps that capture or control the screen,
or repair the device's integrity. Your server reads the verdict and picks the
dialog, and the app shows it for the token it got earlier in the same session:

```dart
final result = await FlutterAntiVirtuals.instance.showPlayIntegrityDialog(
  PlayIntegrityDialog.values.byName(response['dialog']), // e.g. closeUnknownAccessRisk
);
if (result == PlayIntegrityDialogResult.successful) {
  // Ask for a new token: the old one keeps its verdict.
}
```

On iOS, `AttestationOptions(deviceCheck: true)` adds a DeviceCheck token. With
it your server reads and sets two bits that Apple keeps for the device and that
stay after the app is deleted and installed again, such as "already got the
sign-up bonus".
Android gets the same kind of memory from the Play Integrity verdict (device
recall), configured in the Play Console.

### Checking it on the server

[`doc/server-verification.md`](doc/server-verification.md) lists every check
the server has to make. The
[`anti_virtuals_verifier`](packages/anti_virtuals_verifier/) package in this
repository makes them for a Dart backend: nonce, age, signature, the Android
key attestation chain up to Google's roots with the revocation list, the
attested app and boot state, a decoded Play Integrity verdict with its
environment details and the remediation dialog that fits, App Attest
attestations and assertions, and your signal policy. It also has clients for
Play Integrity token decoding and device recall, Apple's DeviceCheck two bits
and the App Attest risk metric.

```dart
final verifier = SignedReportVerifier(
  nonces: nonceStore,
  appAttestKeys: appAttestKeyStore, // your table of enrolled App Attest keys
  policy: const VerificationPolicy(
    android: AndroidPolicy(
      packageNames: {'com.example.app'},
      signingCertificateDigests: {'AB:CD:…'},
    ),
    ios: IosPolicy(teamId: 'ABCDE12345', bundleIds: {'com.example.app'}),
  ),
);

final result = await verifier.verify(body['report']);
if (result is Rejected) return forbidden(dialog: result.remediation?.name);
```

## Signals

The table covers Android and iOS. For macOS, Windows, Linux and the web see
[On desktop and the web](#on-desktop-and-the-web).

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
| `signatureMismatch` | yes | with `expectedTeamIds` | Android: signing certificate SHA-256 against `expectedSignatureSha256`. iOS: the team ID in the app's keychain access group against `expectedTeamIds`, and an App Store build whose binary is no longer encrypted (a dumped copy) |
| `accessibilityAbuse` | yes | no | Non-system services that can read window content |
| `remoteControlApp` | yes | no | AnyDesk, TeamViewer, RustDesk and similar apps installed |
| `clonedApp` | yes | no | Unexpected data directory or process name, known cloner apps |
| `userCertificates` | yes | no | User-installed CA certificates |
| `sideloaded` | no | yes | An embedded provisioning profile |
| `automation` | yes | no | The monkey tester, test harness mode, a connected UiAutomation (UI Automator, Appium) and installed automation helpers (`installedApps`) |
| `activeCall` | yes | yes | Android: the audio mode of a cellular or VoIP call. iOS: a connected CallKit call |
| `noScreenLock` | yes | yes | `KeyguardManager.isDeviceSecure` on Android, `LAContext` on iOS |
| `appDataMigrated` | yes | yes | The id in the app's data has no matching Android Keystore key or Keychain item on this device. Cleared by `rebindDevice()` |

A hooking tool can rename itself or hide its mappings, so a `hooked` detection
is strong evidence and a clean result is no evidence either way.

### On desktop and the web

| Signal | macOS | Windows | Linux | Web |
| --- | --- | --- | --- | --- |
| `vpn` | Connected services in `scutil --nc list`, `utun`, `ipsec`, `ppp`, `tun` and `tap` interfaces with routable addresses | Adapters named after VPN drivers and clients (WireGuard, Wintun, TAP, OpenVPN, NordLynx, Proton, AnyConnect, FortiClient, GlobalProtect, ZeroTier, Tailscale) | `tun`, `tap`, `wg`, `ppp`, `ipsec`, `vti`, `nordlynx`, `tailscale` and `zt` interfaces | no |
| `proxy` | `scutil --proxy` (HTTP, HTTPS, SOCKS, PAC) | Internet Settings in the registry (proxy server, PAC) | GNOME proxy mode | no |
| `debugger` | `ps` marks the process as traced | `IsDebuggerPresent` | `TracerPid` | no |
| `emulator` | `kern.hv_vmm_present`, a virtual `hw.model` | BIOS manufacturer and product | DMI vendor and product | no |
| `automation` | no | no | no | `navigator.webdriver`, headless Chrome |
| `clockTampering` | with `trustedTime` | with `trustedTime` | with `trustedTime` | with `trustedTime` |

All three desktop systems also count `HTTP_PROXY`, `HTTPS_PROXY` and
`ALL_PROXY` in the process environment as a proxy. On desktop, `emulator`
means a virtual machine, which also covers cloud desktops and CI runners.

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
accessibility, remote-control, clone, user CA or automation checks) and has no
key attestation. App Attest and DeviceCheck do not work on the Simulator. CI
builds the Swift code and runs its unit and integration tests on the
Simulator, but it has not yet been tested on a physical iPhone.

The desktop and web checks are best effort. They read what the operating
system or browser tells any program, so a user who controls the machine can
hide a VPN behind an unusual adapter name or patch `navigator.webdriver`.
Nothing there can be attested, and `verify()` is not available.

The lists of known apps (mock location, remote control, cloners, root
managers, hooking apps, automation tools) need updates as new tools appear. Location and camera
spoofing done through hooks is invisible to these checks.

Android keeps the last fix of every location provider, so only fixes younger
than two minutes count (a running mock app injects one about every second),
and it hands out last-known locations only while the app is in the
foreground.

Play Integrity needs Google Play services on the device and has a daily quota
per Google Cloud project.

## License

MIT, see [LICENSE](LICENSE).
