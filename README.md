# flutter_anti_virtuals

Detects virtualized, spoofed and tampered environments in Flutter apps on
Android and iOS, and reports each finding with evidence so your backend can
decide what to do.

```dart
final report = await FlutterAntiVirtuals.instance.scan(
  const ScanOptions(
    expectedSignatureSha256: ['<release cert sha256>'],
    allowedAccessibilityServices: ['com.google.android.marvin.talkback'],
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

## Signals

| Signal | Android | iOS | How |
| --- | --- | --- | --- |
| `vpn` | yes | yes | VPN transport, `tun`/`ppp`/`tap`/`wg` interfaces (iOS: scoped `tap`/`tun`/`ppp` only; utun-based VPNs are not distinguishable from system tunnels) |
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
