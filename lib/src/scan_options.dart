import 'signal.dart';

/// Configures a scan.
///
/// Every `check*` flag defaults to `true`, except [checkSignatureMismatch]
/// which is only meaningful with [expectedSignatureSha256] and therefore
/// defaults to "on when hashes are provided" (see its documentation). The
/// constructor asserts that checks which need configuration receive it, so a
/// misconfigured scan fails in debug builds instead of silently doing nothing.
class ScanOptions {
  // Not const: the assertions inspect the lists, which is not allowed in a
  // constant expression.
  ScanOptions({
    this.checkVpn = true,
    this.checkProxy = true,
    this.checkMockLocation = true,
    this.checkVirtualCamera = true,
    this.checkDeveloperOptions = true,
    this.checkAdb = true,
    this.checkClockTampering = true,
    this.checkUntrustedInstaller = true,
    this.checkSignatureMismatch,
    this.checkAccessibilityAbuse = true,
    this.checkRemoteControlApp = true,
    this.checkClonedApp = true,
    this.checkUserCertificates = true,
    this.checkSideloaded = true,
    this.expectedSignatureSha256 = const <String>[],
    this.trustedInstallers = defaultTrustedInstallers,
    this.allowedAccessibilityServices = const <String>[],
    this.maxClockSkew = const Duration(minutes: 5),
    this.trustedTime,
  }) : assert(
         checkSignatureMismatch != true || expectedSignatureSha256.isNotEmpty,
         'checkSignatureMismatch requires expectedSignatureSha256 to be '
         'provided (or set checkSignatureMismatch to false).',
       ),
       assert(
         !checkUntrustedInstaller || trustedInstallers.isNotEmpty,
         'checkUntrustedInstaller requires a non-empty trustedInstallers '
         'list, otherwise every installer is reported as untrusted.',
       );

  /// App stores trusted by default. Deliberately excludes
  /// `com.google.android.packageinstaller`, which is the installer used for
  /// manually installed (sideloaded) APKs.
  static const List<String> defaultTrustedInstallers = <String>[
    'com.android.vending', // Google Play
    'com.sec.android.app.samsungapps', // Galaxy Store
    'com.huawei.appmarket', // AppGallery
    'com.amazon.venezia', // Amazon Appstore
    'com.xiaomi.mipicks', // Xiaomi GetApps
  ];

  /// Active VPN transport or tunnel interface.
  final bool checkVpn;

  /// System, per-network or PAC proxy.
  final bool checkProxy;

  /// Mocked GPS location or installed mock-location apps.
  final bool checkMockLocation;

  /// Virtual/external cameras and known virtual-camera apps.
  final bool checkVirtualCamera;

  /// Android developer options enabled.
  final bool checkDeveloperOptions;

  /// USB or wireless debugging enabled.
  final bool checkAdb;

  /// Automatic time off, or skew against [trustedTime].
  final bool checkClockTampering;

  /// Installer not in [trustedInstallers].
  final bool checkUntrustedInstaller;

  /// Signing certificate differs from [expectedSignatureSha256].
  ///
  /// Needs [expectedSignatureSha256]. `null` (the default) means "run when
  /// hashes are provided"; passing `true` without hashes is an assertion
  /// failure, `false` turns the check off.
  final bool? checkSignatureMismatch;

  /// Non-system accessibility services that can read the screen.
  final bool checkAccessibilityAbuse;

  /// Remote-control apps (AnyDesk, TeamViewer, ...) installed.
  final bool checkRemoteControlApp;

  /// App running in a clone / parallel-space container.
  final bool checkClonedApp;

  /// User-installed CA certificates.
  final bool checkUserCertificates;

  /// iOS build with an embedded provisioning profile.
  final bool checkSideloaded;

  /// Lower-case hex SHA-256 digests of the release signing certificate(s).
  /// Required by [checkSignatureMismatch].
  final List<String> expectedSignatureSha256;

  /// Android installer package names considered trustworthy. An app with no
  /// installer (adb, tooling) is always reported, including debug builds.
  final List<String> trustedInstallers;

  /// Accessibility service package names that are allowed (for example your
  /// own app or a screen reader you want to tolerate).
  final List<String> allowedAccessibilityServices;

  /// Largest tolerated difference between the device clock and [trustedTime].
  final Duration maxClockSkew;

  /// Authoritative time, normally taken from a server response. Without it the
  /// clock check only looks at the automatic-time settings.
  final DateTime? trustedTime;

  /// The signals this configuration will evaluate.
  Set<AntiVirtualSignal> get enabledSignals => <AntiVirtualSignal>{
    if (checkVpn) AntiVirtualSignal.vpn,
    if (checkProxy) AntiVirtualSignal.proxy,
    if (checkMockLocation) AntiVirtualSignal.mockLocation,
    if (checkVirtualCamera) AntiVirtualSignal.virtualCamera,
    if (checkDeveloperOptions) AntiVirtualSignal.developerOptions,
    if (checkAdb) AntiVirtualSignal.adb,
    if (checkClockTampering) AntiVirtualSignal.clockTampering,
    if (checkUntrustedInstaller) AntiVirtualSignal.untrustedInstaller,
    if (checkSignatureMismatch ?? expectedSignatureSha256.isNotEmpty)
      AntiVirtualSignal.signatureMismatch,
    if (checkAccessibilityAbuse) AntiVirtualSignal.accessibilityAbuse,
    if (checkRemoteControlApp) AntiVirtualSignal.remoteControlApp,
    if (checkClonedApp) AntiVirtualSignal.clonedApp,
    if (checkUserCertificates) AntiVirtualSignal.userCertificates,
    if (checkSideloaded) AntiVirtualSignal.sideloaded,
  };

  /// A copy that only evaluates [signal]; every other check is turned off.
  ScanOptions onlyChecking(AntiVirtualSignal signal) => ScanOptions(
    checkVpn: signal == AntiVirtualSignal.vpn,
    checkProxy: signal == AntiVirtualSignal.proxy,
    checkMockLocation: signal == AntiVirtualSignal.mockLocation,
    checkVirtualCamera: signal == AntiVirtualSignal.virtualCamera,
    checkDeveloperOptions: signal == AntiVirtualSignal.developerOptions,
    checkAdb: signal == AntiVirtualSignal.adb,
    checkClockTampering: signal == AntiVirtualSignal.clockTampering,
    checkUntrustedInstaller: signal == AntiVirtualSignal.untrustedInstaller,
    checkSignatureMismatch: signal == AntiVirtualSignal.signatureMismatch,
    checkAccessibilityAbuse: signal == AntiVirtualSignal.accessibilityAbuse,
    checkRemoteControlApp: signal == AntiVirtualSignal.remoteControlApp,
    checkClonedApp: signal == AntiVirtualSignal.clonedApp,
    checkUserCertificates: signal == AntiVirtualSignal.userCertificates,
    checkSideloaded: signal == AntiVirtualSignal.sideloaded,
    expectedSignatureSha256: expectedSignatureSha256,
    trustedInstallers: trustedInstallers,
    allowedAccessibilityServices: allowedAccessibilityServices,
    maxClockSkew: maxClockSkew,
    trustedTime: trustedTime,
  );

  Map<String, Object?> toMap() => <String, Object?>{
    'signals': enabledSignals.map((s) => s.key).toList(),
    'expectedSignatureSha256': expectedSignatureSha256
        .map((s) => s.toLowerCase())
        .toList(),
    'trustedInstallers': trustedInstallers,
    'allowedAccessibilityServices': allowedAccessibilityServices,
    'maxClockSkewMs': maxClockSkew.inMilliseconds,
    'trustedTimeMs': trustedTime?.toUtc().millisecondsSinceEpoch,
  };
}
