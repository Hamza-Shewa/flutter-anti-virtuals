import 'flutter_anti_virtuals_platform_interface.dart';
import 'src/report.dart';
import 'src/scan_options.dart';
import 'src/signal.dart';

export 'src/report.dart';
export 'src/scan_options.dart';
export 'src/signal.dart';

/// Detects virtualized, spoofed and tampered environments.
class FlutterAntiVirtuals {
  FlutterAntiVirtuals._();

  static final FlutterAntiVirtuals instance = FlutterAntiVirtuals._();

  /// Runs the requested checks and returns what was found. Never throws for a
  /// failing individual check; those are reported as not detected.
  Future<AntiVirtualReport> scan([ScanOptions options = const ScanOptions()]) =>
      FlutterAntiVirtualsPlatform.instance.scan(options);

  /// Convenience for a single check.
  Future<SignalResult> check(
    AntiVirtualSignal signal, [
    ScanOptions options = const ScanOptions(),
  ]) async {
    final report = await scan(
      ScanOptions(
        signals: {signal},
        expectedSignatureSha256: options.expectedSignatureSha256,
        trustedInstallers: options.trustedInstallers,
        allowedAccessibilityServices: options.allowedAccessibilityServices,
        maxClockSkew: options.maxClockSkew,
        trustedTime: options.trustedTime,
      ),
    );
    return report[signal] ?? const SignalResult.unsupported();
  }
}
