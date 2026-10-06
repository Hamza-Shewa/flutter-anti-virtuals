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
blocking signal is detected. Put it in `MaterialApp.builder` so the default
screen follows the app's locale:

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
| `messages` / `locale` | device or app locale | Text of the built-in screen. Ships English, Arabic (RTL), French and Spanish, falling back to English; `AntiVirtualMessages.english.copyWith(...)` overrides single strings |
| `forceExit` | `false` | Close the app after `forceExitAfter` |
| `forceExitAfter` | 5 seconds | Delay before the app exits. The built-in screen shows a countdown |
| `waitForScan` / `loadingBuilder` | `true` | Hide the app until the first scan finishes |
| `rescanOnResume` | `true` | Scan again when the app comes back to the foreground; if the problem is gone the app is shown again and the exit is cancelled |
| `onReport`, `onError` | none | Every completed scan; scan failures. A failing scan lets the app through (fail open) |

The wrapped app stays mounted (its state is kept) but is hidden and not
interactive while blocked.

**Force exit on iOS:** Apple's App Review Guidelines discourage apps from
quitting themselves, so `forceExit` can get an app rejected from the App
Store. It is off by default. On Android it calls `SystemNavigator.pop()`, on
iOS `exit(0)`.

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
| `mockLocation` | yes | iOS 15+ | `Location.isMock` (needs granted location permission), known mock apps; iOS `isSimulatedBySoftware` |
| `virtualCamera` | partial | iOS 17+ | Known virtual-camera apps, external cameras |
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

## Limits

Every check runs on the device, so a rooted device or a hooked app can lie.
Treat the report as a signal and verify important actions on your server,
ideally with Play Integrity / App Attest. Package lists are best effort and
need updating; mock-location and camera spoofing that works through hooks is
not visible to these checks.

For mock-location results to include `isMock`, the host app needs location
permission already granted; the plugin never asks for it.

## License

MIT, see [LICENSE](LICENSE).
