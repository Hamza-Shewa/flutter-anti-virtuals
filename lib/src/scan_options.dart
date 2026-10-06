import 'signal.dart';

/// Configures a scan.
class ScanOptions {
  const ScanOptions({
    this.signals,
    this.expectedSignatureSha256 = const <String>[],
    this.trustedInstallers = const <String>[
      'com.android.vending',
      'com.google.android.packageinstaller',
    ],
    this.allowedAccessibilityServices = const <String>[],
    this.maxClockSkew = const Duration(minutes: 5),
    this.trustedTime,
  });

  /// Signals to evaluate. `null` evaluates all of them.
  final Set<AntiVirtualSignal>? signals;

  /// Lower-case hex SHA-256 digests of the release signing certificate(s).
  /// Leave empty to skip the signature check.
  final List<String> expectedSignatureSha256;

  /// Android installer package names considered trustworthy.
  final List<String> trustedInstallers;

  /// Accessibility service package names that are allowed (for example your
  /// own app or a screen reader you want to tolerate).
  final List<String> allowedAccessibilityServices;

  /// Largest tolerated difference between the device clock and [trustedTime].
  final Duration maxClockSkew;

  /// Authoritative time, normally taken from a server response. Without it the
  /// clock check only looks at the automatic-time settings.
  final DateTime? trustedTime;

  Map<String, Object?> toMap() => <String, Object?>{
    'signals': signals?.map((s) => s.key).toList(),
    'expectedSignatureSha256': expectedSignatureSha256
        .map((s) => s.toLowerCase())
        .toList(),
    'trustedInstallers': trustedInstallers,
    'allowedAccessibilityServices': allowedAccessibilityServices,
    'maxClockSkewMs': maxClockSkew.inMilliseconds,
    'trustedTimeMs': trustedTime?.toUtc().millisecondsSinceEpoch,
  };
}
