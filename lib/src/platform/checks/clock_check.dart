import '../../scan_options.dart';
import '../../signal.dart';
import 'signal_check.dart';

/// Compares the device clock with [ScanOptions.trustedTime]. Without a trusted
/// time there is nothing to compare with, so the check is unsupported, as on
/// iOS.
final class ClockCheck implements SignalCheck {
  ClockCheck({DateTime Function()? now}) : _now = now ?? DateTime.now;

  final DateTime Function() _now;

  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.clockTampering;

  @override
  Future<SignalResult> run(ScanOptions options) async {
    final trusted = options.trustedTime;
    if (trusted == null) return const SignalResult.unsupported();
    final skew = _now().difference(trusted).abs();
    return resultOf([
      if (skew > options.maxClockSkew)
        'clock differs from trusted time by ${skew.inMilliseconds}ms',
    ]);
  }
}
