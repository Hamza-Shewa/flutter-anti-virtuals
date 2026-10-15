import '../../report.dart';
import '../../scan_options.dart';
import '../../signal.dart';

/// One check written in Dart, for the platforms without native checks.
abstract interface class SignalCheck {
  /// The signal this check answers.
  AntiVirtualSignal get signal;

  Future<SignalResult> run(ScanOptions options);
}

/// A result built from the evidence a check found: detected when there is
/// any.
SignalResult resultOf(List<String> details) {
  final distinct = details.toSet().toList(growable: false);
  return SignalResult(detected: distinct.isNotEmpty, details: distinct);
}

/// Runs the checks a scan asks for, side by side. A signal without a check is
/// unsupported, and a check that throws is failed, never clean.
final class CheckRunner {
  CheckRunner(Iterable<SignalCheck> checks)
    : _checks = {for (final check in checks) check.signal: check};

  final Map<AntiVirtualSignal, SignalCheck> _checks;

  /// The signals this runner has a check for.
  Set<AntiVirtualSignal> get supported => _checks.keys.toSet();

  Future<AntiVirtualReport> scan(ScanOptions options) async {
    final signals = options.enabledSignals.toList(growable: false);
    final results = await Future.wait([
      for (final signal in signals) _run(signal, options),
    ]);
    return AntiVirtualReport(
      Map.unmodifiable({
        for (var i = 0; i < signals.length; i++) signals[i]: results[i],
      }),
    );
  }

  Future<SignalResult> _run(
    AntiVirtualSignal signal,
    ScanOptions options,
  ) async {
    final check = _checks[signal];
    if (check == null) return const SignalResult.unsupported();
    try {
      return await check.run(options);
    } catch (error) {
      return SignalResult.failed('check failed: ${error.runtimeType}');
    }
  }
}
