import '../../../flutter_anti_virtuals_platform_interface.dart';
import '../../report.dart';
import '../../scan_options.dart';
import '../checks/clock_check.dart';
import '../checks/signal_check.dart';
import '../unsupported_platform.dart';
import 'desktop_checks.dart';
import 'desktop_environment.dart';
import 'io_desktop_environment.dart';

/// The macOS, Windows and Linux implementation. The checks are written in
/// Dart: `vpn`, `proxy`, `debugger`, `emulator` (a virtual machine) and
/// `clockTampering` against a trusted time. Every other signal is
/// unsupported, and signing, attestation and screen protection behave as in
/// [FlutterAntiVirtualsUnsupported].
class FlutterAntiVirtualsDesktop extends FlutterAntiVirtualsUnsupported {
  FlutterAntiVirtualsDesktop({DesktopEnvironment? system})
    : _runner = CheckRunner([
        ...desktopChecks(system ?? IoDesktopEnvironment()),
        ClockCheck(),
      ]);

  /// Registers this implementation. Called by Flutter's plugin registrant.
  static void registerWith() {
    FlutterAntiVirtualsPlatform.instance = FlutterAntiVirtualsDesktop();
  }

  final CheckRunner _runner;

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) => _runner.scan(options);
}
