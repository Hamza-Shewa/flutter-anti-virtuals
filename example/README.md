# flutter_anti_virtuals example

Three small apps in `lib/`. Each runs on its own:

| File | Shows | Run |
| --- | --- | --- |
| `main.dart` | Everything on one screen: every signal, live changes, the guard, screen protection and `verify()` with Play Integrity / App Attest | `flutter run` |
| `scan_example.dart` | **Usage 1**, calling `scan()` yourself: a full scan, only the checks you need, one signal with `check()`, and a decision before a sensitive action | `flutter run -t lib/scan_example.dart` |
| `guard_example.dart` | **Usage 2**, the `AntiVirtualGuard` wrapper: around the whole app, around one screen, a custom blocking screen, release-only blocking and `onReport` | `flutter run -t lib/guard_example.dart` |

Run them on a device or an emulator. An emulator reports `emulator` (and
usually `untrustedInstaller` and `adb`); switch a VPN or a proxy on to watch the
guard react.

`verify()` needs a nonce from your own server in a real app. The example makes
one up so it runs without a backend; see
[`doc/server-verification.md`](../doc/server-verification.md) for what the
server checks.
