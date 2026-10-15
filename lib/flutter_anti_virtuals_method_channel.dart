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

  /// Name of the event channel the native side reports screenshots on.
  @visibleForTesting
  static const screenshotsChannelName = 'flutter_anti_virtuals/screenshots';

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async {
    final raw = await methodChannel.invokeMapMethod<Object?, Object?>(
      'scan',
      options.toMap(),
    );
    if (raw == null) {
      // An empty report would read as a clean device.
      throw PlatformException(
        code: 'no_result',
        message: 'The native scan returned no result',
      );
    }
    return AntiVirtualReport.fromMap(raw, requested: options.enabledSignals);
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

  @override
  Future<bool> preparePlayIntegrity(int cloudProjectNumber) async {
    if (defaultTargetPlatform != TargetPlatform.android) return false;
    final prepared = await methodChannel.invokeMethod<bool>(
      'prepareIntegrity',
      <String, Object?>{'cloudProjectNumber': cloudProjectNumber},
    );
    return prepared ?? false;
  }

  @override
  Future<bool> rebindDevice() async {
    final rebound = await methodChannel.invokeMethod<bool>('rebindDevice');
    return rebound ?? false;
  }

  @override
  Future<PlayIntegrityDialogResult> showPlayIntegrityDialog(
    PlayIntegrityDialog dialog,
  ) async {
    if (defaultTargetPlatform != TargetPlatform.android) {
      return PlayIntegrityDialogResult.unavailable;
    }
    final outcome = await methodChannel.invokeMethod<String>(
      'showIntegrityDialog',
      <String, Object?>{'typeCode': dialog.typeCode},
    );
    return PlayIntegrityDialogResult.fromName(outcome);
  }

  // One shared stream per event channel: an event channel has a single
  // message handler, so a stream per reader would let the newest listener
  // steal the events and the first one to cancel stop them for everybody.
  // Native starts watching with the first listener and stops with the last.
  @override
  late final Stream<void> environmentChanges = _openEvents(changesChannelName);

  @override
  late final Stream<void> screenshots = _openEvents(screenshotsChannelName);

  // This is `EventChannel.receiveBroadcastStream` written out, because that
  // reports a failed activation (no native side, for example in a background
  // isolate or a host app's widget test) through `FlutterError.reportError`
  // instead of the stream. Here a missing native side is a stream that never
  // emits, and any other failure is an error event.
  Stream<void> _openEvents(String channelName) {
    const codec = StandardMethodCodec();
    final control = MethodChannel(channelName);
    final messenger = ServicesBinding.instance.defaultBinaryMessenger;
    late final StreamController<void> controller;
    controller = StreamController<void>.broadcast(
      onListen: () async {
        messenger.setMessageHandler(channelName, (reply) async {
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
        messenger.setMessageHandler(channelName, null);
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
