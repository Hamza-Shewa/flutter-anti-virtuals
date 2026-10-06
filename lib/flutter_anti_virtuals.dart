import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;

import 'flutter_anti_virtuals_platform_interface.dart';
import 'src/attestation.dart';
import 'src/report.dart';
import 'src/scan_options.dart';
import 'src/screen_protection.dart';
import 'src/signed_report.dart';
import 'src/signal.dart';

export 'src/guard/anti_virtual_guard.dart';
export 'src/guard/messages.dart';
export 'src/attestation.dart';
export 'src/report.dart';
export 'src/scan_options.dart';
export 'src/screen_protection.dart';
export 'src/signed_report.dart';
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

  /// Scans, then signs the result together with [nonce] so a backend can
  /// check it instead of trusting the app. [nonce] must be a fresh value the
  /// backend issued for this request (at least 16 characters), otherwise the
  /// report can be replayed. See [SignedReport] for what the backend must
  /// verify, and call this right before the sensitive action, not at startup.
  ///
  /// Pass [attestation] to also request a Play Integrity token (Android) or
  /// an App Attest attestation / assertion (iOS) bound to the same payload,
  /// which lets the backend confirm the device and app with Google or Apple.
  /// It is requested after signing, so a failure there throws and no
  /// half-attested report is returned.
  ///
  /// Throws an [ArgumentError] for a short [nonce]; native failures propagate
  /// as `PlatformException` and must be treated as an unverified device.
  Future<SignedReport> verify({
    required String nonce,
    ScanOptions? options,
    AttestationOptions? attestation,
  }) async {
    if (nonce.length < 16) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'must be at least 16 characters, issued by your backend',
      );
    }
    final report = await scan(options);
    final issuedAt = DateTime.now().toUtc();
    final platform = defaultTargetPlatform == TargetPlatform.iOS
        ? 'iOS'
        : 'android';
    final payload = SignedReport.encodePayload(
      nonce: nonce,
      issuedAt: issuedAt,
      platform: platform,
      report: report,
    );
    final signature = await FlutterAntiVirtualsPlatform.instance.signPayload(
      nonce,
      payload,
    );
    final platformAttestation = attestation == null
        ? null
        : await FlutterAntiVirtualsPlatform.instance.requestAttestation(
            payload,
            attestation,
          );
    return SignedReport(
      nonce: nonce,
      issuedAt: issuedAt,
      platform: platform,
      payload: payload,
      signature: signature,
      report: report,
      attestation: platformAttestation,
    );
  }

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
