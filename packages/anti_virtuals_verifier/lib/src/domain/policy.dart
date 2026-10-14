import 'key_attestation.dart';

/// What the server accepts. Every check that the policy turns on must pass.
final class VerificationPolicy {
  const VerificationPolicy({
    this.android,
    this.acceptIos = false,
    this.maxAge = const Duration(minutes: 2),
    this.maxClockSkew = const Duration(seconds: 30),
    this.blockOn = defaultBlockingSignals,
    this.blockOnInstalledApps = false,
    this.blockOnFailedChecks = true,
  });

  /// The signals the app's guard blocks on by default, plus the ones that
  /// only matter on a server.
  static const defaultBlockingSignals = {
    'vpn',
    'proxy',
    'mockLocation',
    'virtualCamera',
    'signatureMismatch',
    'emulator',
    'rooted',
    'hooked',
  };

  /// How Android reports are checked. Null rejects every Android report.
  final AndroidPolicy? android;

  /// Accept iOS reports. Their signature only proves the payload was not
  /// changed on the way; nothing proves the device is genuine (App Attest
  /// is not checked by this package). Off by default.
  final bool acceptIos;

  /// How old `issuedAt` may be.
  final Duration maxAge;

  /// How far `issuedAt` may lie in the future (device clocks drift).
  final Duration maxClockSkew;

  /// Signal keys that reject a report when detected.
  final Set<String> blockOn;

  /// Also reject when a [blockOn] signal was detected only because a known
  /// tool is installed. Off by default, like the app's guard.
  final bool blockOnInstalledApps;

  /// Reject when the device check of a [blockOn] signal failed. A failed
  /// check is unknown, and a tampered device can make checks fail on
  /// purpose.
  final bool blockOnFailedChecks;
}

/// Android key attestation requirements.
final class AndroidPolicy {
  const AndroidPolicy({
    required this.packageNames,
    required this.signingCertificateDigests,
    this.allowedSecurityLevels = const {
      SecurityLevel.trustedEnvironment,
      SecurityLevel.strongBox,
    },
    this.requireVerifiedBoot = true,
    this.requireLockedBootloader = true,
    this.minimumOsPatchLevel,
    this.checkCertificateDates = false,
    this.playIntegrity,
  });

  /// Your application id, for example `com.example.app`.
  final Set<String> packageNames;

  /// SHA-256 of your release signing certificate, as hex (`AB:CD:…` or
  /// `abcd…`). With Play App Signing this is the app signing key from the
  /// Play Console, not your upload key.
  final Set<String> signingCertificateDigests;

  final Set<SecurityLevel> allowedSecurityLevels;

  /// Reject a device whose boot state is not `Verified`: an unlocked
  /// bootloader or a custom ROM.
  final bool requireVerifiedBoot;

  final bool requireLockedBootloader;

  /// Oldest acceptable security patch level as `YYYYMM`, for example 202401.
  final int? minimumOsPatchLevel;

  /// Reject certificates outside their validity dates. Off by default:
  /// attestation leaf certificates often carry placeholder dates, and Google
  /// revokes compromised keys through the status list instead.
  final bool checkCertificateDates;

  /// Also require a Play Integrity verdict. Null skips it.
  final PlayIntegrityPolicy? playIntegrity;
}

/// What a decoded Play Integrity verdict must say.
final class PlayIntegrityPolicy {
  const PlayIntegrityPolicy({
    this.requirePlayRecognized = true,
    this.requiredDeviceVerdict = 'MEETS_DEVICE_INTEGRITY',
    this.requireLicensed = false,
    this.maxAge = const Duration(minutes: 2),
  });

  /// `appRecognitionVerdict` must be `PLAY_RECOGNIZED`.
  final bool requirePlayRecognized;

  /// A label `deviceRecognitionVerdict` must contain, such as
  /// `MEETS_DEVICE_INTEGRITY` or `MEETS_STRONG_INTEGRITY`. Null skips it.
  final String? requiredDeviceVerdict;

  /// `appLicensingVerdict` must be `LICENSED`.
  final bool requireLicensed;

  /// How old the token's `timestampMillis` may be.
  final Duration maxAge;
}
