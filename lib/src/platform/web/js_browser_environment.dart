import 'dart:js_interop';

import 'browser_checks.dart';

@JS('navigator')
external _Navigator get _navigator;

extension type _Navigator._(JSObject _) implements JSObject {
  external JSBoolean? get webdriver;
  external JSString get userAgent;
}

/// [BrowserEnvironment] that reads `window.navigator`.
final class JsBrowserEnvironment implements BrowserEnvironment {
  const JsBrowserEnvironment();

  @override
  bool get webdriver => _navigator.webdriver?.toDart ?? false;

  @override
  String get userAgent => _navigator.userAgent.toDart;
}
