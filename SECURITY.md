# Security policy

This repository holds two packages: the `flutter_anti_virtuals` plugin and the
`anti_virtuals_verifier` server package. Both are covered.

## Reporting a vulnerability

Report it privately through
[GitHub's vulnerability reporting](https://github.com/Hamza-Shewa/flutter-anti-virtuals/security/advisories/new).
Do not open a public issue for it.

Say which package and version you used, what an attacker can do and how to
reproduce it. A failing test is the most useful form.

## What counts

* A report that `anti_virtuals_verifier` accepts and should reject: a forged
  or replayed report, a broken signature or attestation check.
* A way to make `verify()` sign something the scan did not find.
* A crash, hang or data leak in the plugin that a hostile device or app can
  trigger.

A way to hide a VPN, root, a hook or an emulator from `scan()` is a missed
detection, not a vulnerability: the README says on-device checks can be
defeated. Open a normal issue for those.

## Supported versions

Fixes go into the latest release of each package.
