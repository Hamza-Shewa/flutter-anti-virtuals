import 'signal.dart';

/// Outcome of one scan. Send it to your backend together with an attestation
/// token (Play Integrity / App Attest) rather than trusting it on the client.
class AntiVirtualReport {
  const AntiVirtualReport(this.results);

  /// Parses the native result. Every signal in [requested] that the native
  /// side left out is recorded as [SignalResult.failed], so a missing answer
  /// can never read as a clean one.
  factory AntiVirtualReport.fromMap(
    Map<Object?, Object?> map, {
    Iterable<AntiVirtualSignal> requested = const <AntiVirtualSignal>[],
  }) {
    final results = <AntiVirtualSignal, SignalResult>{};
    map.forEach((key, value) {
      final signal = AntiVirtualSignal.fromKey(key.toString());
      if (signal == null) return;
      results[signal] = value is Map
          ? SignalResult.fromMap(value)
          : const SignalResult.failed('malformed native result');
    });
    for (final signal in requested) {
      results.putIfAbsent(
        signal,
        () => const SignalResult.failed('missing from the native result'),
      );
    }
    return AntiVirtualReport(Map.unmodifiable(results));
  }

  final Map<AntiVirtualSignal, SignalResult> results;

  SignalResult? operator [](AntiVirtualSignal signal) => results[signal];

  bool isDetected(AntiVirtualSignal signal) =>
      results[signal]?.detected ?? false;

  /// True when the check for [signal] ran but produced no answer.
  bool isFailed(AntiVirtualSignal signal) => results[signal]?.failed ?? false;

  /// Signals that fired.
  Set<AntiVirtualSignal> get detected => {
    for (final entry in results.entries)
      if (entry.value.detected) entry.key,
  };

  /// Signals whose check failed. Their state is unknown, not clean.
  Set<AntiVirtualSignal> get failed => {
    for (final entry in results.entries)
      if (entry.value.failed) entry.key,
  };

  /// Nothing was detected and every check produced an answer. A report with a
  /// [failed] check is not clean.
  bool get isClean => detected.isEmpty && failed.isEmpty;

  /// True when any of [signals] fired.
  bool hasAny(Iterable<AntiVirtualSignal> signals) => signals.any(isDetected);

  Map<String, Object?> toJson() => <String, Object?>{
    for (final entry in results.entries) entry.key.key: entry.value.toJson(),
  };

  @override
  String toString() =>
      'AntiVirtualReport(detected: $detected'
      '${failed.isEmpty ? '' : ', failed: $failed'})';
}
