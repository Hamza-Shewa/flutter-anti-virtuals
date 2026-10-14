import 'package:flutter_web_plugins/flutter_web_plugins.dart';

import '../../flutter_anti_virtuals_platform_interface.dart';
import 'unsupported_platform.dart';

/// The web implementation: the same as [FlutterAntiVirtualsUnsupported],
/// registered the way web plugins are.
class FlutterAntiVirtualsWeb extends FlutterAntiVirtualsUnsupported {
  /// Registers this implementation. Called by Flutter's web registrant.
  static void registerWith(Registrar registrar) {
    FlutterAntiVirtualsPlatform.instance = FlutterAntiVirtualsWeb();
  }
}
