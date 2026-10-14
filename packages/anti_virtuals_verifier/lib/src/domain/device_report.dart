import 'dart:convert';

/// The platform that produced a report.
enum DevicePlatform { android, iOS }

/// One check in the signed payload.
final class SignalVerdict {
  const SignalVerdict({
    required this.detected,
    this.supported = true,
    this.failed = false,
    this.installedOnly = false,
  });

  factory SignalVerdict.fromJson(Map<String, Object?> json) => SignalVerdict(
    detected: json['detected'] == true,
    supported: json['supported'] != false,
    failed: json['failed'] == true,
    installedOnly: json['installedOnly'] == true,
  );

  final bool detected;
  final bool supported;

  /// The check ran but produced no answer. Unknown, not clean.
  final bool failed;

  /// Detected only because a known tool is installed, not because it is in
  /// use (mockLocation, virtualCamera).
  final bool installedOnly;
}

/// What the app signed: the parsed `payload` of a signed report.
final class DeviceReport {
  const DeviceReport({
    required this.version,
    required this.nonce,
    required this.issuedAt,
    required this.platform,
    required this.signals,
  });

  /// Parses the signed text. Throws [FormatException] when it is not a
  /// version 1 payload.
  factory DeviceReport.parse(String payload) {
    final Object? json;
    try {
      json = jsonDecode(payload);
    } on FormatException {
      throw const FormatException('The payload is not JSON');
    }
    if (json is! Map<String, Object?>) {
      throw const FormatException('The payload is not a JSON object');
    }
    final version = json['v'];
    final nonce = json['nonce'];
    final issuedAt = json['issuedAt'];
    final platform = switch (json['platform']) {
      'android' => DevicePlatform.android,
      'iOS' => DevicePlatform.iOS,
      _ => null,
    };
    final signals = json['signals'];
    if (version != 1 ||
        nonce is! String ||
        issuedAt is! int ||
        platform == null ||
        signals is! Map<String, Object?>) {
      throw const FormatException('The payload is not a version 1 report');
    }
    return DeviceReport(
      version: 1,
      nonce: nonce,
      issuedAt: DateTime.fromMillisecondsSinceEpoch(issuedAt, isUtc: true),
      platform: platform,
      signals: Map.unmodifiable({
        for (final MapEntry(:key, :value) in signals.entries)
          if (value is Map<String, Object?>) key: SignalVerdict.fromJson(value),
      }),
    );
  }

  final int version;
  final String nonce;
  final DateTime issuedAt;
  final DevicePlatform platform;

  /// Checks by signal key, for example `vpn` or `mockLocation`.
  final Map<String, SignalVerdict> signals;

  /// Keys of the signals that were detected.
  Set<String> get detected => {
    for (final MapEntry(:key, :value) in signals.entries)
      if (value.detected) key,
  };

  /// Keys of the checks that failed on the device.
  Set<String> get failed => {
    for (final MapEntry(:key, :value) in signals.entries)
      if (value.failed) key,
  };
}
