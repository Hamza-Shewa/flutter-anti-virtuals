/// Every integrity signal the plugin can report.
enum AntiVirtualSignal {
  // Core virtualization / spoofing checks.
  vpn,
  proxy,
  mockLocation,
  virtualCamera,

  // Beyond what `flutter_defender` offers.
  developerOptions,
  adb,
  clockTampering,
  untrustedInstaller,
  signatureMismatch,
  accessibilityAbuse,
  remoteControlApp,
  clonedApp,
  userCertificates,
  sideloaded;

  /// Wire name used on the platform channel.
  String get key => name;

  static AntiVirtualSignal? fromKey(String key) {
    for (final signal in values) {
      if (signal.key == key) return signal;
    }
    return null;
  }
}

/// What a single check found.
class SignalResult {
  const SignalResult({
    required this.detected,
    this.supported = true,
    this.details = const <String>[],
  });

  /// Result for a check the current platform cannot perform.
  const SignalResult.unsupported()
    : detected = false,
      supported = false,
      details = const <String>[];

  factory SignalResult.fromMap(Map<Object?, Object?> map) => SignalResult(
    detected: map['detected'] == true,
    supported: map['supported'] != false,
    details: <String>[
      for (final item in (map['details'] as List<Object?>? ?? const []))
        item.toString(),
    ],
  );

  /// True when the risky condition was found.
  final bool detected;

  /// False when the platform has no way to evaluate this check.
  final bool supported;

  /// Human-readable evidence (package names, paths, interface names ...).
  final List<String> details;

  @override
  String toString() => 'SignalResult(detected: $detected, details: $details)';
}
