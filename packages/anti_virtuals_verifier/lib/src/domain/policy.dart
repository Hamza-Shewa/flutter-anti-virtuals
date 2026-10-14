import 'key_attestation.dart';
import 'play_integrity.dart';

/// What the server accepts. Every check that the policy turns on must pass.
final class VerificationPolicy {
  const VerificationPolicy({
    this.android,
    this.ios,
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

  /// How iOS reports are checked: App Attest. Null rejects every iOS report
  /// unless [acceptIos] is set.
  final IosPolicy? ios;

  /// Accept iOS reports without an [ios] policy. Their signature only proves
  /// the payload was not changed on the way; nothing proves the device or
  /// the app is genuine. Off by default; set [ios] instead.
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
///
/// The environment rules ([rejectedAppAccessRisks],
/// [acceptedPlayProtectVerdicts], [maxDeviceActivityLevel]) are off by
/// default. Turn on the matching responses in the Play Console first, or the
/// verdict does not carry them.
final class PlayIntegrityPolicy {
  const PlayIntegrityPolicy({
    this.requirePlayRecognized = true,
    this.requiredDeviceVerdict = DeviceRecognitionLabel.meetsDeviceIntegrity,
    this.requireLicensed = false,
    this.maxAge = const Duration(minutes: 2),
    this.rejectedAppAccessRisks = const {},
    this.requireAppAccessRiskVerdict = false,
    this.acceptedPlayProtectVerdicts,
    this.maxDeviceActivityLevel,
  });

  /// `appRecognitionVerdict` must be `PLAY_RECOGNIZED`.
  final bool requirePlayRecognized;

  /// A label `deviceRecognitionVerdict` must contain, such as
  /// [DeviceRecognitionLabel.meetsDeviceIntegrity] or
  /// [DeviceRecognitionLabel.meetsStrongIntegrity]. Null skips it.
  final DeviceRecognitionLabel? requiredDeviceVerdict;

  /// `appLicensingVerdict` must be `LICENSED`.
  final bool requireLicensed;

  /// How old the token's `timestampMillis` may be.
  final Duration maxAge;

  /// Reject when `appAccessRiskVerdict.appsDetected` contains one of these,
  /// for example [AppAccessRisk.unknownCapturingOrControlling]. A verdict
  /// where app access risk was not evaluated passes this rule unless
  /// [requireAppAccessRiskVerdict] is set.
  final Set<AppAccessRisk> rejectedAppAccessRisks;

  /// Also reject when app access risk was not evaluated (no
  /// `appsDetected`). Play leaves it out for tablets on old Play Store
  /// versions, unlicensed users, standard requests with `verdictOptOut` and
  /// other cases, so this rejects some genuine users.
  final bool requireAppAccessRiskVerdict;

  /// `playProtectVerdict` must be one of these, for example
  /// `{PlayProtectVerdict.noIssues}`. A missing verdict is rejected. Null
  /// skips it.
  final Set<PlayProtectVerdict>? acceptedPlayProtectVerdicts;

  /// The highest acceptable `recentDeviceActivity.deviceActivityLevel`. A
  /// missing or `UNEVALUATED` level is rejected. Null skips it.
  final DeviceActivityLevel? maxDeviceActivityLevel;
}

/// App Attest requirements for iOS reports.
///
/// The app must request an App Attest object with
/// `verify(attestation: AttestationOptions())`. Its first request of a key
/// carries an attestation, which enrolls the key in your
/// `AppAttestKeyStore`; later requests carry assertions signed by that key.
final class IosPolicy {
  const IosPolicy({
    required this.teamId,
    required this.bundleIds,
    this.allowDevelopment = false,
    this.requireAppAttest = true,
    this.allowedValidationCategories,
  });

  /// Your 10 character Team ID (the App ID prefix).
  final String teamId;

  /// Your bundle identifiers, for example `com.example.app`. An App Clip
  /// uses the full app's identifier.
  final Set<String> bundleIds;

  /// Accept keys from the App Attest development environment (builds run
  /// from Xcode). Keep it off in production.
  final bool allowDevelopment;

  /// Reject iOS reports that carry no App Attest object. When false, an
  /// object that is present must still verify, but a report without one is
  /// accepted on its signature alone.
  final bool requireAppAttest;

  /// When set, an `apple_validation_category_01` value in the authenticator
  /// data must be one of these, for example `{2, 4}` for TestFlight and the
  /// App Store. Objects from OS versions that do not include the value pass.
  final Set<int>? allowedValidationCategories;

  /// `<TeamID>.<BundleID>` for every bundle identifier.
  Set<String> get appIds => {for (final id in bundleIds) '$teamId.$id'};
}
