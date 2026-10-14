import '../../flutter_anti_virtuals_platform_interface.dart';
import '../attestation.dart';
import '../report.dart';
import '../scan_options.dart';
import '../signal.dart';
import '../signed_report.dart';

/// The implementation for platforms without native checks: macOS, Windows,
/// Linux and, through [FlutterAntiVirtualsWeb], the web.
///
/// Every requested check comes back unsupported, screen protection does
/// nothing, there are no live environment changes, and signing or
/// attestation throws [UnsupportedError]. A multi-platform app can call the
/// same code everywhere instead of catching `MissingPluginException`.
class FlutterAntiVirtualsUnsupported extends FlutterAntiVirtualsPlatform {
  /// Registers this implementation. Called by Flutter's plugin registrant.
  static void registerWith() {
    FlutterAntiVirtualsPlatform.instance = FlutterAntiVirtualsUnsupported();
  }

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async =>
      AntiVirtualReport({
        for (final signal in options.enabledSignals)
          signal: const SignalResult.unsupported(),
      });

  @override
  Future<DeviceSignature> signPayload(String nonce, String payload) =>
      throw UnsupportedError('Signing is only available on Android and iOS');

  @override
  Future<PlatformAttestation> requestAttestation(
    String payload,
    AttestationOptions options,
  ) => throw UnsupportedError(
    'Play Integrity and App Attest are only available on Android and iOS',
  );
}
