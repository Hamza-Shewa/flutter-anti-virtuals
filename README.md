# flutter_anti_virtuals

Detects virtualized, spoofed and tampered environments in Flutter apps on
Android and iOS, and reports each finding with evidence so your backend can
decide what to do.

```dart
// Every check is on by default.
final report = await FlutterAntiVirtuals.instance.scan(
  ScanOptions(
    expectedSignatureSha256: ['<release cert sha256>'],
    allowedAccessibilityServices: ['com.google.android.marvin.talkback'],
    checkClockTampering: false, // switch off what you do not need
  ),
);

if (report.hasAny({
  AntiVirtualSignal.mockLocation,
  AntiVirtualSignal.virtualCamera,
  AntiVirtualSignal.vpn,
  AntiVirtualSignal.proxy,
})) {
  // block, warn, or just send report.toJson() to your server
}
```

## Block the app at startup

`AntiVirtualGuard` runs a scan when the app starts (and again every time it
returns to the foreground) and covers your app with a blocking screen while a
blocking signal is detected. Put it in `MaterialApp.builder`:

```dart
MaterialApp(
  builder: (context, child) => AntiVirtualGuard(
    options: ScanOptions(expectedSignatureSha256: ['<release cert sha256>']),
    child: child!,
  ),
  home: const HomePage(),
)
```

| Option | Default | Meaning |
| --- | --- | --- |
| `blockOn` | `vpn`, `proxy`, `mockLocation`, `virtualCamera`, `signatureMismatch` | Detections that block. Others (developer options, installer, ...) only reach `onReport` |
| `blockedBuilder` | built-in screen | `(context, matches)` where `matches` is e.g. `[vpn, mockLocation]`, so you can write your own text |
| `messages` / `locale` | device language | Text of the built-in screen. Ships English, Arabic (RTL), French and Spanish, falling back to English; `AntiVirtualMessages.english.copyWith(...)` overrides single strings. Apps with their own language switch pass `locale: Localizations.localeOf(context)` |
| `forceExit` | `false` | Close the app after `forceExitAfter`. The countdown pauses while the app is in the background and restarts on return if the problem is still there |
| `forceExitAfter` | 5 seconds | Delay before the app exits. The built-in screen shows a countdown |
| `waitForScan` / `loadingBuilder` | `true` | The app is not built until the first scan is clean |
| `rescanOnResume` | `true` | Scan again when the app returns to the foreground. Coming back from the background always rescans; a shorter interruption (notification shade, quick settings, Control Center, permission dialog) rescans when the last scan is older than `rescanDebounce` (3 seconds), so a VPN switched on from quick settings is caught. If the problem is gone the app is shown again and the exit is cancelled |
| `liveMonitoring` | `true` | Scan as soon as the network changes, so a VPN or proxy switched on while the app is in front is caught right away. Android listens to `ConnectivityManager` for VPN transport and per-network proxy changes and to the system's proxy-change broadcast for a proxy set globally, iOS to `NWPathMonitor` (every path update counts). A failing watcher is reported through `onError` and retried after 30 seconds. A change while the app is in the background is scanned on resume, even with `rescanOnResume: false`. Mock location and cameras have no change notification, so they wait for the next rescan. iOS does not report a changed proxy setting live |
| `liveDebounce` | 500 ms | Wait after a change before scanning, so a burst of changes (a VPN coming up) causes one scan |
| `rescanInterval` | `null` | Also scan this often while in the foreground |
| `failClosed` | `false` | Block when a scan fails. The built-in screen then says the device could not be verified and `blockedBuilder` gets an empty list. Without it a failing first scan lets the app through and a failed rescan keeps the previous result, so backgrounding the app cannot be used to clear a block |
| `unmountWhileBlocked` | `true` | Remove the app from the tree while blocked, so the Android back button and deep links cannot reach it (a widget above the `Navigator` cannot intercept them). Its state is lost and it is rebuilt when the block clears. Pass `false` to keep it mounted and hidden instead |
| `hardExit` | `false` | Android: end the process with `exit(0)` instead of `SystemNavigator.pop()` |
| `onReport`, `onError` | none | Every completed scan; scan failures (reported through `FlutterError.reportError` when `onError` is not set) |

The app is not built until the first scan is clean. While blocked it is
removed from the tree and rebuilt with fresh state when the block clears; with
`unmountWhileBlocked: false` it stays mounted (state kept) but hidden, without
focus and with animations paused. Code outside the widget tree (`main()`, network
calls already started) is not stopped. Changing `options`, `blockOn` or
`forceExit` later takes effect.

**Force exit on iOS:** Apple's App Review Guidelines discourage apps from
quitting themselves, so `forceExit` can get an app rejected from the App
Store. It is off by default. On Android it calls `SystemNavigator.pop()`,
which finishes the activity but can leave the process running (or return to
the previous activity); set `hardExit` to end the process. On iOS it calls
`exit(0)`.

The stream behind it is public: `FlutterAntiVirtuals.instance.environmentChanges`
emits when the network setup changes (it carries no data, call `scan()` to find
out what changed) and nothing for the state that exists when you start
listening. It is one shared stream, so any number of listeners (several
guards, your own code) can use it. Where the native side is missing, for
example in a widget test that only mocks the `flutter_anti_virtuals` method
channel, it simply never emits. A scan is started at most `liveDebounce` x 4
after the first change of a burst, so a flapping network cannot postpone it.

## Protecting the screen

Detecting a screen recording is not the same as stopping it. For the screens
that show balances, codes or documents:

```dart
AntiVirtualGuard(
  protectScreen: const ScreenProtectionOptions(),   // or call
  blockOn: {...AntiVirtualGuard.defaultBlockingSignals,   // protectScreen() yourself
            AntiVirtualSignal.screenCapture},
  child: child,
)
```

| Platform | What `protectScreen` does |
| --- | --- |
| Android | `FLAG_SECURE`: screenshots, screen recording and casting show black, and the recent-apps thumbnail is blank. `setFilterTouchesWhenObscured`: touches that pass through another app's window drawn over yours are dropped (tapjacking). Android 12+: `setHideOverlayWindows`, so other apps' overlay windows are hidden while yours is in front |
| iOS | Apple offers no switch for this. The app is covered with a blur while the screen is recorded or mirrored and while the app is in the app switcher |

It also stops your own users from taking screenshots, so it is off by default.
The plugin declares the `HIDE_OVERLAY_WINDOWS` and `DETECT_SCREEN_RECORDING`
permissions; both are normal permissions granted at install.

## Verify before a sensitive action

A client-side scan can be faked by whoever controls the device. `verify()` runs
a scan right now, binds it to a nonce your backend issued and signs it with a
key created on the device for that request:

```dart
final nonce = await api.issueNonce();          // single use, from your server
final signed = await FlutterAntiVirtuals.instance.verify(nonce: nonce);
await api.transfer(amount, attestation: signed.toJson());
```

On Android the key is attested by the secure hardware (StrongBox or TEE) with
the SHA-256 of the nonce as challenge, so your server can prove the request is
live, comes from a locked, verified-boot device and from your release-signed
app. iOS signs with a Secure Enclave key; bind it to App Attest for device
proof. Add `attestation: AttestationOptions()` to also get a Play Integrity token
(Android) or an App Attest attestation/assertion (iOS) bound to the same
payload. What the server has to check is in
[`doc/server-verification.md`](doc/server-verification.md).

## Choosing checks

`ScanOptions` has one boolean per signal (`checkVpn`, `checkProxy`,
`checkMockLocation`, ...), all `true` by default. Checks that need
configuration assert that it was provided, so a misconfigured scan fails in
debug builds instead of silently doing nothing:

| Flag | Needs |
| --- | --- |
| `checkSignatureMismatch` | `expectedSignatureSha256`. The default is `null`, meaning "run when hashes are provided", so a bare `ScanOptions()` still works. `true` without hashes is an assertion failure; `false` turns it off. |
| `checkUntrustedInstaller` | A non-empty `trustedInstallers` (defaults to the major app stores) |

`checkClockTampering` works without `trustedTime` (it then only looks at the
automatic date/time settings); pass `trustedTime` from a server response to
also compare the clock.

## Signals

| Signal | Android | iOS | How |
| --- | --- | --- | --- |
| `vpn` | yes | yes | VPN transport, `tun`/`ppp`/`tap`/`wg` interfaces (iOS: `utun`/`ipsec`/`tap`/`tun`/`ppp` entries in the scoped network settings, which system tunnels such as Private Relay and Wi-Fi Calling do not appear in) |
| `proxy` | yes | yes | Per-network proxy, PAC file, JVM proxy properties |
| `mockLocation` | yes | iOS 15+ | `Location.isMock` of a fix from the last 2 minutes (needs granted location permission and the app in the foreground), known mock apps; iOS `isSimulatedBySoftware` |
| `virtualCamera` | partial | iOS 17+ | Known virtual-camera apps, external cameras |
| `emulator` | yes | yes | Android: any one strong indicator (`ro.kernel.qemu`/`ro.boot.qemu`, goldfish/ranchu/vbox86 hardware, qemu and vendor files, Genymotion, BlueStacks, Nox, LDPlayer, MEmu builds or apps, Goldfish sensors) or two weak ones (generic fingerprint, SDK model or product, no sensors, operator "Android", ...), so real devices are not reported. iOS: Simulator build, `SIMULATOR_*` environment, host CPU as hardware model |
| `rooted` | yes | yes | Android root, iOS jailbreak. Android: any one strong indicator (`su`, `magisk` or `daemonsu` in `PATH` and the usual directories, a root manager or root-hiding app such as Magisk, KernelSU, APatch, SuperSU, RootCloak, root tool files, a writable `/system`, `/vendor` or `/product`, `adbd` as root, `ro.secure=0`, permissive SELinux, Magisk/KernelSU/APatch mounts) or two weak ones (a debug build of the system and an unlocked bootloader). iOS: Cydia, Sileo, Zebra, Filza and other jailbreak files (rootless `/var/jb` and `/var/binpack` too), a successful write outside the sandbox, injected tweak libraries (Substrate, Substitute, libhooker, ElleKit) and `DYLD_INSERT_LIBRARIES`. The iOS Simulator is reported by `emulator`, not here |
| `hooked` | yes | yes | Instrumentation in the app process. Android: Frida, Xposed, LSPosed, EdXposed, Substrate or Riru/Zygisk libraries in `/proc/self/maps`, Frida threads, `XposedBridge` classes, hooking managers and files, framework frames in the plugin's own call stack (a hooked method), Frida's default server port. iOS: injected Frida, Substrate, Substitute, libhooker and ElleKit libraries, hooking classes, `DYLD_INSERT_LIBRARIES`, the Frida port |
| `debugger` | yes | yes | A Java debugger or `TracerPid` (Android), `P_TRACED` (iOS). A debug build started from your IDE reports it, so it is not blocking by default |
| `screenCapture` | yes | yes | External or wireless displays (Android presentation displays, iOS extra screens), screen recording on Android 15+, iOS `isCaptured`. Casting and recording by a private virtual display are not visible to Android before 15 |
| `developerOptions` | yes | no | `DEVELOPMENT_SETTINGS_ENABLED` |
| `adb` | yes | no | USB and wireless debugging |
| `clockTampering` | yes | needs `trustedTime` | Auto time/zone off, skew against server time |
| `untrustedInstaller` | yes | no | Installer not in `trustedInstallers` (Play, Galaxy Store, AppGallery, Amazon, GetApps by default). Builds installed with adb report no installer, including debug builds |
| `signatureMismatch` | yes | no | Signing cert SHA-256 vs `expectedSignatureSha256` |
| `accessibilityAbuse` | yes | no | Non-system services that can read window content |
| `remoteControlApp` | yes | no | AnyDesk, TeamViewer, RustDesk, ... installed |
| `clonedApp` | yes | no | Unexpected data dir or process name, known cloner apps |
| `userCertificates` | yes | no | User-installed CA certificates |
| `sideloaded` | no | yes | Embedded provisioning profile present |

`flutter_defender` has none of: `mockLocation`, `virtualCamera`,
`developerOptions`, `adb`, `clockTampering`, `untrustedInstaller`,
`signatureMismatch`, `accessibilityAbuse`, `remoteControlApp`, `clonedApp`,
`userCertificates`, `sideloaded`.

`emulator` is not in `AntiVirtualGuard.defaultBlockingSignals`, so the guard
does not block your own emulator or Simulator while you develop. Block it in
release builds only:

```dart
AntiVirtualGuard(
  blockOn: {
    ...AntiVirtualGuard.defaultBlockingSignals,
    if (kReleaseMode) AntiVirtualSignal.emulator,
  },
  child: child,
)
```

`rooted` is not blocking by default either, because refusing every rooted or
jailbroken device locks out legitimate users in some markets. Add it when your
app must refuse them:

```dart
AntiVirtualGuard(
  blockOn: {...AntiVirtualGuard.defaultBlockingSignals, AntiVirtualSignal.rooted},
  child: child,
)
```

`hooked` and `debugger` are not blocking by default for the same reason. A
hooking tool can rename itself or hide its mappings, so treat a detection as
strong evidence and a clean result as no evidence. The Frida port check needs
the `INTERNET` permission, which most apps already have.

Root-hiding tools (Magisk's Zygisk DenyList, Shamiko, jailbreak-detection
bypass tweaks) remove most of the evidence for a targeted app, so a clean result
does not prove a clean device. Use Play Integrity / App Attest on your server
for anything that matters.

## Limits

Every check runs on the device, so a rooted device or a hooked app can lie.
Treat the report as a signal and verify important actions on your server,
ideally with Play Integrity / App Attest. Package lists are best effort and
need updating; mock-location and camera spoofing that works through hooks is
not visible to these checks.

For mock-location results to include `isMock`, the host app needs location
permission already granted; the plugin never asks for it.
Android keeps the last fix of every location provider, so a mock fix would
stay visible long after the spoofing app stopped. Only fixes younger than two
minutes count; a running mock app injects one about every second. Android also
only hands out last-known locations while the app is in the foreground.

## License

MIT, see [LICENSE](LICENSE).
