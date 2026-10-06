import 'dart:async';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_anti_virtuals_method_channel.dart';
import 'src/attestation.dart';
import 'src/report.dart';
import 'src/scan_options.dart';
import 'src/screen_protection.dart';
import 'src/signed_report.dart';

abstract class FlutterAntiVirtualsPlatform extends PlatformInterface {
  FlutterAntiVirtualsPlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterAntiVirtualsPlatform _instance =
      MethodChannelFlutterAntiVirtuals();

  static FlutterAntiVirtualsPlatform get instance => _instance;

  static set instance(FlutterAntiVirtualsPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<AntiVirtualReport> scan(ScanOptions options) {
    throw UnimplementedError('scan() has not been implemented.');
  }

  /// Applies [options] to the app's window, or removes the protections when it
  /// is null. Returns false when nothing could be applied yet (Android without
  /// a resumed activity; it is applied as soon as one is attached) or when the
  /// platform has no such protection.
  Future<bool> setScreenProtection(ScreenProtectionOptions? options) async =>
      false;

  /// Signs [payload] (UTF-8) with a key created on the device for this one
  /// request. On Android the key carries a hardware attestation whose
  /// challenge is the SHA-256 of [nonce] where the device supports it.
  Future<DeviceSignature> signPayload(String nonce, String payload) {
    throw UnimplementedError('signPayload() has not been implemented.');
  }

  /// Asks Play Integrity (Android) or App Attest (iOS) for a token bound to
  /// [payload]: the nonce or client data hash is the SHA-256 of its UTF-8
  /// bytes. Fails when the service is unavailable on this device.
  Future<PlatformAttestation> requestAttestation(
    String payload,
    AttestationOptions options,
  ) {
    throw UnimplementedError('requestAttestation() has not been implemented.');
  }

  /// Emits whenever the network setup changes in a way that can turn a VPN or
  /// proxy on or off. Platforms without live monitoring never emit.
  Stream<void> get environmentChanges => const Stream<void>.empty();
}
