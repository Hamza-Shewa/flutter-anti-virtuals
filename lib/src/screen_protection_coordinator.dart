import 'package:flutter/foundation.dart' show visibleForTesting;

import '../flutter_anti_virtuals_platform_interface.dart';
import 'screen_protection.dart';

/// Screen protection is one window-wide switch, but several parts of an app
/// can ask for it (each [AntiVirtualGuard] with `protectScreen`, and
/// `FlutterAntiVirtuals.protectScreen`). This keeps one request per owner and
/// sends the union of them to the platform, so one owner letting go does not
/// switch the protection off for another that still needs it.
class ScreenProtectionCoordinator {
  ScreenProtectionCoordinator._();

  static final ScreenProtectionCoordinator instance =
      ScreenProtectionCoordinator._();

  final Map<Object, ScreenProtectionOptions> _requests =
      <Object, ScreenProtectionOptions>{};

  /// Records what [owner] needs (`null` releases it) and applies the union of
  /// all requests. Returns what the platform reported.
  Future<bool> request(Object owner, ScreenProtectionOptions? options) {
    if (options == null) {
      _requests.remove(owner);
    } else {
      _requests[owner] = options;
    }
    return FlutterAntiVirtualsPlatform.instance.setScreenProtection(effective);
  }

  /// The union of every owner's request, or null when nobody needs any.
  ScreenProtectionOptions? get effective {
    if (_requests.isEmpty) return null;
    final all = _requests.values;
    return ScreenProtectionOptions(
      secureWindow: all.any((o) => o.secureWindow),
      filterObscuredTouches: all.any((o) => o.filterObscuredTouches),
      hideOverlayWindows: all.any((o) => o.hideOverlayWindows),
    );
  }

  @visibleForTesting
  void reset() => _requests.clear();
}
