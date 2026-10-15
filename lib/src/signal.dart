/// Every integrity signal the plugin can report.
enum AntiVirtualSignal {
  // Virtualization, spoofing and tampering of the device or the app process.
  vpn,
  proxy,
  mockLocation,
  virtualCamera,
  emulator,
  rooted,
  hooked,
  debugger,
  screenCapture,
  automation,

  // Device settings, app integrity and abuse of system features.
  developerOptions,
  adb,
  clockTampering,
  untrustedInstaller,
  signatureMismatch,
  accessibilityAbuse,
  remoteControlApp,
  clonedApp,
  userCertificates,
  sideloaded,

  // Fraud context: the device or session is in a state scams rely on.
  activeCall,
  noScreenLock,
  appDataMigrated;

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
///
/// A result is one of four things: [detected], clean (`!detected`,
/// [supported] and not [failed]), unsupported (the platform cannot evaluate
/// it) or [failed] (the check was supposed to run but threw or returned
/// nothing). A failed check is unknown, never clean: treat it as suspicious
/// for anything that matters.
class SignalResult {
  const SignalResult({
    required this.detected,
    this.supported = true,
    this.details = const <String>[],
    this.installedApps = const <String>[],
    this.error,
  });

  /// Result for a check the current platform cannot perform.
  const SignalResult.unsupported()
    : detected = false,
      supported = false,
      details = const <String>[],
      installedApps = const <String>[],
      error = null;

  /// Result for a check that should have run but did not produce an answer.
  const SignalResult.failed(String this.error)
    : detected = false,
      supported = true,
      details = const <String>[],
      installedApps = const <String>[];

  factory SignalResult.fromMap(Map<Object?, Object?> map) {
    final error = map['error'];
    if (map['failed'] == true) {
      return SignalResult.failed(error?.toString() ?? 'check failed');
    }
    return SignalResult(
      detected: map['detected'] == true,
      supported: map['supported'] != false,
      details: _strings(map['details']),
      installedApps: _strings(map['installedApps']),
    );
  }

  static List<String> _strings(Object? raw) => List<String>.unmodifiable(
    <String>[for (final item in (raw as List<Object?>? ?? const [])) '$item'],
  );

  /// True when the risky condition was found.
  final bool detected;

  /// False when the platform has no way to evaluate this check.
  final bool supported;

  /// Human-readable evidence (package names, paths, interface names ...),
  /// including [installedApps].
  final List<String> details;

  /// The part of [details] that only says a known tool is installed, not that
  /// it is in use right now (`mockLocation` and `virtualCamera`). A result
  /// whose only evidence is an installed app is [onlyInstalledApps].
  final List<String> installedApps;

  /// Why the check failed; non-null exactly when [failed] is true.
  final String? error;

  /// The check was supposed to run but produced no answer. Not the same as
  /// clean.
  bool get failed => error != null;

  /// Detected only because a known tool is installed.
  bool get onlyInstalledApps =>
      detected &&
      installedApps.isNotEmpty &&
      details.length == installedApps.length;

  Map<String, Object?> toJson() => <String, Object?>{
    'detected': detected,
    'supported': supported,
    'details': details,
    if (installedApps.isNotEmpty) 'installedApps': installedApps,
    if (failed) 'failed': true,
    if (failed) 'error': error,
  };

  @override
  bool operator ==(Object other) =>
      other is SignalResult &&
      other.detected == detected &&
      other.supported == supported &&
      other.error == error &&
      _listEquals(other.details, details) &&
      _listEquals(other.installedApps, installedApps);

  @override
  int get hashCode => Object.hash(
    detected,
    supported,
    error,
    Object.hashAll(details),
    Object.hashAll(installedApps),
  );

  @override
  String toString() => failed
      ? 'SignalResult(failed: $error)'
      : 'SignalResult(detected: $detected, details: $details)';
}

bool _listEquals(List<String> a, List<String> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
