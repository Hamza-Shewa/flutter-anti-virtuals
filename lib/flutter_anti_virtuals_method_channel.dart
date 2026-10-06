import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'flutter_anti_virtuals_platform_interface.dart';
import 'src/report.dart';
import 'src/scan_options.dart';

class MethodChannelFlutterAntiVirtuals extends FlutterAntiVirtualsPlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('flutter_anti_virtuals');

  @override
  Future<AntiVirtualReport> scan(ScanOptions options) async {
    final raw = await methodChannel.invokeMapMethod<Object?, Object?>(
      'scan',
      options.toMap(),
    );
    return AntiVirtualReport.fromMap(raw ?? const <Object?, Object?>{});
  }
}
