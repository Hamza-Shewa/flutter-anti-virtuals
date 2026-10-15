import 'package:flutter_web_plugins/flutter_web_plugins.dart';

import '../../flutter_anti_virtuals_platform_interface.dart';
import '../report.dart';
import '../scan_options.dart';
import 'checks/clock_check.dart';
import 'checks/signal_check.dart';
import 'unsupported_platform.dart';
import 'web/browser_checks.dart';
import 'web/js_browser_environment.dart';

/// The web implementation. It checks `automation` (WebDriver or headless
/// Chrome) and `clockTampering` against a trusted time; every other signal is
/// unsupported, and the rest behaves as in [FlutterAntiVirtualsUnsupported].
class FlutterAntiVirtualsWeb extends FlutterAntiVirtualsUnsupported {
  FlutterAntiVirtualsWeb({BrowserEnvironment? browser})
    : _runner = CheckRunner([
        BrowserAutomationCheck(browser ?? const JsBrowserEnvironment()),
        ClockCheck(),
      ]);

  /// Registers this implementation. Called by Flutter's web registrant.
  static void registerWith(Registrar registrar) {
    FlutterAntiVirtualsPlatform.instance = FlutterAntiVirtualsWeb();
  }

  final CheckRunner _runner;

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) => _runner.scan(options);
}
