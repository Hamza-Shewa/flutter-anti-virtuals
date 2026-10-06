import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'flutter_anti_virtuals_platform_interface.dart';
import 'src/attestation.dart';
import 'src/report.dart';
import 'src/scan_options.dart';
import 'src/screen_protection.dart';
import 'src/signed_report.dart';

class MethodChannelFlutterAntiVirtuals extends FlutterAntiVirtualsPlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('flutter_anti_virtuals');

  /// Name of the event channel the native side streams network changes on.
  @visibleForTesting
  static const changesChannelName = 'flutter_anti_virtuals/changes';

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async {
    final raw = await methodChannel.invokeMapMethod<Object?, Object?>(
      'scan',
      options.toMap(),
    );
    return AntiVirtualReport.fromMap(raw ?? const <Object?, Object?>{});
  }

  @override
  Future<bool> setScreenProtection(ScreenProtectionOptions? options) async {
    final applied = await methodChannel.invokeMethod<bool>(
      'setScreenProtection',
      (options ??
              const ScreenProtectionOptions(
                secureWindow: false,
                filterObscuredTouches: false,
                hideOverlayWindows: false,
              ))
          .toMap(),
    );
    return applied ?? false;
  }

  @override
  Future<DeviceSignature> signPayload(String nonce, String payload) async {
    final raw = await methodChannel.invokeMapMethod<Object?, Object?>(
      'signPayload',
      <String, Object?>{'nonce': nonce, 'payload': payload},
    );
    return DeviceSignature.fromMap(raw ?? const <Object?, Object?>{});
  }

  @override
  Future<PlatformAttestation> requestAttestation(
    String payload,
    AttestationOptions options,
  ) async {
    final raw = await methodChannel.invokeMapMethod<Object?, Object?>(
      'attest',
      <String, Object?>{'payload': payload, ...options.toMap()},
    );
    return PlatformAttestation.fromMap(raw ?? const <Object?, Object?>{});
  }

  // One shared stream: an event channel has a single message handler, so a
  // stream per reader would let the newest listener steal the events and the
  // first one to cancel stop them for everybody. Native starts watching with
  // the first listener and stops with the last.
  @override
  late final Stream<void> environmentChanges = _openChanges();

  // This is `EventChannel.receiveBroadcastStream` written out, because that
  // reports a failed activation (no native side, for example in a background
  // isolate or a host app's widget test) through `FlutterError.reportError`
  // instead of the stream. Here a missing native side is a stream that never
  // emits, and any other failure is an error event.
  Stream<void> _openChanges() {
    const codec = StandardMethodCodec();
    const control = MethodChannel(changesChannelName);
    final messenger = ServicesBinding.instance.defaultBinaryMessenger;
    late final StreamController<void> controller;
    controller = StreamController<void>.broadcast(
      onListen: () async {
        messenger.setMessageHandler(changesChannelName, (reply) async {
          if (reply == null) {
            await controller.close();
            return null;
          }
          try {
            codec.decodeEnvelope(reply);
            controller.add(null);
          } on PlatformException catch (error, stackTrace) {
            controller.addError(error, stackTrace);
          }
          return null;
        });
        try {
          await control.invokeMethod<void>('listen');
        } on MissingPluginException {
          // Nothing to watch here.
        } on PlatformException catch (error, stackTrace) {
          controller.addError(error, stackTrace);
        }
      },
      onCancel: () async {
        messenger.setMessageHandler(changesChannelName, null);
        try {
          await control.invokeMethod<void>('cancel');
        } on MissingPluginException {
          // Never started.
        } on PlatformException {
          // Nothing left to stop.
        }
      },
    );
    return controller.stream;
  }
}
