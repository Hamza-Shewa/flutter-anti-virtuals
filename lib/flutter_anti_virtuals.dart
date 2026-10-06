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

  /// Runs the requested checks and returns what was found. A check that fails
  /// natively is reported as unsupported (not as clean). Channel errors such as
  /// `PlatformException` or `MissingPluginException` propagate; treat them as a
  /// failed scan rather than a clean device.
  Future<AntiVirtualReport> scan([ScanOptions options = const ScanOptions()]) =>
      FlutterAntiVirtualsPlatform.instance.scan(options);

  /// Convenience for a single check.
  Future<SignalResult> check(
    AntiVirtualSignal signal, [
    ScanOptions options = const ScanOptions(),
  ]) async {
    final report = await scan(options.copyWith(signals: {signal}));
    return report[signal] ?? const SignalResult.unsupported();
  }
}
