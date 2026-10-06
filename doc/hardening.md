# Hardening the checks

Detection code that runs in the attacker's process is a target. These are the
steps that make the checks harder to switch off, and an honest list of what
they do not stop.

## Build your app obfuscated

Attackers find checks by name. Ship release builds with Dart and Android
obfuscation on:

```sh
flutter build apk --release --obfuscate --split-debug-info=build/symbols
flutter build appbundle --release --obfuscate --split-debug-info=build/symbols
flutter build ipa --release --obfuscate --split-debug-info=build/symbols
```

On Android keep R8 on (`minifyEnabled true` and `shrinkResources true` in your
`release` build type, which Flutter's template enables by default in recent
versions). The plugin needs no keep rules: it does not use reflection on its
own classes. Keep the `build/symbols` directory to read crash stack traces.

## What the plugin already does

* **Two layers for file checks (Android).** `java.io.File` is what root-hiding
  modules and Frida scripts patch. Every file the plugin looks for is also
  looked up with `Os.stat`, a direct system call. A file counts as present when
  either layer finds it, and a path that only the kernel finds is reported as
  `file API hides <path>` under the `hooked` signal.
* **Hook evidence from several angles.** Mapped libraries, thread names, hooking
  classes, hooking apps, hooking files, framework frames inside the plugin's own
  call stack, the Frida port, and a debugger or tracer.
* **Signed, nonce-bound reports.** `verify()` signs with a per-request key and,
  on Android, a hardware attestation, so a replayed or edited report fails on
  the server. See [server-verification.md](server-verification.md).

## What you should add

1. **Decide on the server.** Use `verify()` plus Play Integrity / App Attest for
   anything that matters, and make the server reject unsigned, stale or
   unattested requests. A client-only check is a speed bump.
2. **Check at the moment of the action,** not only at startup. Call `verify()`
   right before the transfer, login or purchase.
3. **Do not branch on one boolean.** Scatter checks, fail closed on a thrown
   error (`AntiVirtualGuard(failClosed: true)` for blocking screens), and avoid
   a single `if (report.isClean)` that a patch can flip.
4. **Pin the signing certificate** with `expectedSignatureSha256` so a
   repackaged app is reported as `signatureMismatch`, and check it again on the
   server through the attestation (`attestationApplicationId` / Play Integrity
   `certificateSha256Digest`).

## What this does not stop

* A hook installed before the plugin loads can lie about everything the process
  can read, including the kernel layer, if it patches libc. The plugin raises the
  cost; it cannot make an app unhookable.
* A custom, renamed Frida build with no gadget thread, port or library name looks
  clean to every local check. Hardware attestation on the server is what catches
  an unlocked bootloader or a modified system.
* Detection strings live in the app binary. Obfuscation hides names, not
  behavior.
