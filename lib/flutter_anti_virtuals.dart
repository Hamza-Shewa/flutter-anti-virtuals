import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;

import 'flutter_anti_virtuals_platform_interface.dart';
import 'src/attestation.dart';
import 'src/report.dart';
import 'src/scan_options.dart';
import 'src/screen_protection.dart';
import 'src/screen_protection_coordinator.dart';
import 'src/signed_report.dart';
import 'src/signal.dart';

export 'src/guard/anti_virtual_guard.dart';
export 'src/guard/messages.dart';
export 'src/monitor/anti_virtual_monitor.dart';
export 'src/monitor/guard_state.dart';
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
  /// natively, or that the native side leaves out, is reported as
  /// [SignalResult.failed] (unknown, not clean). Channel errors such as
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
  /// On Android, `AttestationOptions(playIntegrity:
  /// PlayIntegrityRequest.standard)` uses the faster standard request; see
  /// [preparePlayIntegrity].
  /// It is requested after signing, so a failure there throws and no
  /// half-attested report is returned.
  ///
  /// Throws an [ArgumentError] for a short [nonce] and an [UnsupportedError]
  /// on platforms other than Android and iOS; native failures propagate
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
    final platform = switch (defaultTargetPlatform) {
      TargetPlatform.android => 'android',
      TargetPlatform.iOS => 'iOS',
      final other => throw UnsupportedError(
        'verify() is only available on Android and iOS, not ${other.name}',
      ),
    };
    final report = await scan(options);
    final issuedAt = DateTime.now().toUtc();
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

  /// Gets Play Integrity ready for [PlayIntegrityRequest.standard] requests
  /// with [cloudProjectNumber], so the first [verify] that asks for one does
  /// not wait for it. Preparing takes a few seconds; call it early, for
  /// example at startup, and again whenever you like (a prepared provider is
  /// reused). [verify] prepares on its own when this was not called, and
  /// prepares again when Play reports the provider expired.
  ///
  /// Returns true when ready and false on platforms without Play Integrity
  /// (iOS, desktop, web). Throws a `PlatformException` when Play cannot
  /// prepare (no Play Store, no network, a wrong project number); `verify`
  /// would then fail the same way.
  Future<bool> preparePlayIntegrity({required int cloudProjectNumber}) =>
      FlutterAntiVirtualsPlatform.instance.preparePlayIntegrity(
        cloudProjectNumber,
      );

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

  /// Emits right after the user takes a screenshot (Android 14 and later,
  /// iOS). It cannot stop the screenshot: use [protectScreen] for that on
  /// Android. Android reports screenshots taken with the device buttons
  /// while your activity is visible and shows the user a notice that the
  /// app noticed; screenshots taken through adb are not reported. The
  /// stream never emits on other platforms.
  Stream<void> get screenshots =>
      FlutterAntiVirtualsPlatform.instance.screenshots;

  /// Accepts the app's data on this device again after
  /// [AntiVirtualSignal.appDataMigrated] was detected, typically once the
  /// user has signed in again. Until then every scan keeps reporting it.
  /// Returns false on platforms without the check.
  Future<bool> rebindDevice() =>
      FlutterAntiVirtualsPlatform.instance.rebindDevice();

  /// Shows Google Play's remediation dialog for [dialog], which asks the user
  /// to fix what made the last Play Integrity verdict fail (get the app from
  /// Play, close risky apps, update Play services). Android only; it needs a
  /// token requested by [verify] with [AttestationOptions] earlier in this
  /// app session and a visible activity. Your backend decides which dialog
  /// fits from the decoded verdict. After [PlayIntegrityDialogResult.successful],
  /// call [verify] again: the dialog does not change the old token.
  Future<PlayIntegrityDialogResult> showPlayIntegrityDialog(
    PlayIntegrityDialog dialog,
  ) => FlutterAntiVirtualsPlatform.instance.showPlayIntegrityDialog(dialog);

  /// Protects the screen that shows sensitive content: blocks screenshots,
  /// recording and casting, ignores touches through overlays and hides the app
  /// in the recent apps list (see [ScreenProtectionOptions] for what each
  /// platform does). Stays on until [unprotectScreen]. Returns false when it
  /// could not be applied yet (Android: no activity attached; it is applied
  /// when one is) or when the platform has no such protection.
  ///
  /// [AntiVirtualGuard.protectScreen] does this for you while it is mounted.
  /// Requests from guards and from this method are combined: the window stays
  /// protected while any of them still asks for it.
  Future<bool> protectScreen([
    ScreenProtectionOptions options = const ScreenProtectionOptions(),
  ]) => ScreenProtectionCoordinator.instance.request(this, options);

  /// Withdraws what [protectScreen] asked for. Protections a mounted guard
  /// still needs stay on, and flags your app set on the window itself are
  /// never cleared.
  Future<bool> unprotectScreen() =>
      ScreenProtectionCoordinator.instance.request(this, null);

  /// Convenience for a single check.
  Future<SignalResult> check(
    AntiVirtualSignal signal, [
    ScanOptions? options,
  ]) async {
    final report = await scan((options ?? ScanOptions()).onlyChecking(signal));
    return report[signal] ?? const SignalResult.unsupported();
  }
}
