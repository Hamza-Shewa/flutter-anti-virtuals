import 'flutter_anti_virtuals_platform_interface.dart';
import 'src/report.dart';
import 'src/scan_options.dart';
import 'src/screen_protection.dart';
import 'src/signal.dart';

export 'src/guard/anti_virtual_guard.dart';
export 'src/guard/messages.dart';
export 'src/report.dart';
export 'src/scan_options.dart';
export 'src/screen_protection.dart';
export 'src/signal.dart';

/// Detects virtualized, spoofed and tampered environments.
class FlutterAntiVirtuals {
  FlutterAntiVirtuals._();

  static final FlutterAntiVirtuals instance = FlutterAntiVirtuals._();

  /// Runs the requested checks and returns what was found. A check that fails
  /// natively is reported as unsupported (not as clean). Channel errors such as
  /// `PlatformException` or `MissingPluginException` propagate; treat them as a
  /// failed scan rather than a clean device.
  Future<AntiVirtualReport> scan([ScanOptions? options]) =>
      FlutterAntiVirtualsPlatform.instance.scan(options ?? ScanOptions());

  /// Emits when the network setup changes in a way that can turn a VPN or
  /// proxy on or off (Android: `ConnectivityManager` callbacks for VPN
  /// transport and proxy changes; iOS: `NWPathMonitor`) and when the screen
  /// starts or stops being recorded, mirrored or cast (Android: display
  /// changes and, on Android 15, the screen-recording callback; iOS:
  /// `UIScreen` capture and connect notifications). It only says that
  /// something changed: call [scan] to find out what. Android and iOS emit
  /// nothing for the state that already exists when you start listening.
  /// [AntiVirtualGuard] listens to it by default.
  Stream<void> get environmentChanges =>
      FlutterAntiVirtualsPlatform.instance.environmentChanges;

  /// Protects the screen that shows sensitive content: blocks screenshots,
  /// recording and casting, ignores touches through overlays and hides the app
  /// in the recent apps list (see [ScreenProtectionOptions] for what each
  /// platform does). Stays on until [unprotectScreen]. Returns false when it
  /// could not be applied yet (Android: no activity attached; it is applied
  /// when one is) or when the platform has no such protection.
  ///
  /// [AntiVirtualGuard.protectScreen] does this for you while it is mounted.
  Future<bool> protectScreen([
    ScreenProtectionOptions options = const ScreenProtectionOptions(),
  ]) => FlutterAntiVirtualsPlatform.instance.setScreenProtection(options);

  /// Removes what [protectScreen] applied.
  Future<bool> unprotectScreen() =>
      FlutterAntiVirtualsPlatform.instance.setScreenProtection(null);

  /// Convenience for a single check.
  Future<SignalResult> check(
    AntiVirtualSignal signal, [
    ScanOptions? options,
  ]) async {
    final report = await scan((options ?? ScanOptions()).onlyChecking(signal));
    return report[signal] ?? const SignalResult.unsupported();
  }
}
