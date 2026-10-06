import 'dart:async';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_anti_virtuals_method_channel.dart';
import 'src/report.dart';
import 'src/scan_options.dart';

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

  /// Emits whenever the network setup changes in a way that can turn a VPN or
  /// proxy on or off. Platforms without live monitoring never emit.
  Stream<void> get environmentChanges => const Stream<void>.empty();
}
