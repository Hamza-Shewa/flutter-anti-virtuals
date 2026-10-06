import 'signal.dart';

/// Outcome of one scan. Send it to your backend together with an attestation
/// token (Play Integrity / App Attest) rather than trusting it on the client.
class AntiVirtualReport {
  const AntiVirtualReport(this.results);

  factory AntiVirtualReport.fromMap(Map<Object?, Object?> map) {
    final results = <AntiVirtualSignal, SignalResult>{};
    map.forEach((key, value) {
      final signal = AntiVirtualSignal.fromKey(key.toString());
      if (signal != null && value is Map) {
        results[signal] = SignalResult.fromMap(value);
      }
    });
    return AntiVirtualReport(Map.unmodifiable(results));
  }

  final Map<AntiVirtualSignal, SignalResult> results;

  SignalResult? operator [](AntiVirtualSignal signal) => results[signal];

  bool isDetected(AntiVirtualSignal signal) =>
      results[signal]?.detected ?? false;

  /// Signals that fired.
  Set<AntiVirtualSignal> get detected => {
    for (final entry in results.entries)
      if (entry.value.detected) entry.key,
  };

  bool get isClean => detected.isEmpty;

  /// True when any of [signals] fired.
  bool hasAny(Iterable<AntiVirtualSignal> signals) => signals.any(isDetected);

  Map<String, Object?> toJson() => <String, Object?>{
    for (final entry in results.entries)
      entry.key.key: <String, Object?>{
        'detected': entry.value.detected,
        'supported': entry.value.supported,
        'details': entry.value.details,
      },
  };

  @override
  String toString() => 'AntiVirtualReport(detected: $detected)';
}
