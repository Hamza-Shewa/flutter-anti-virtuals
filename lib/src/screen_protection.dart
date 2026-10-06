/// Window-level protections for the screen that shows sensitive content
/// (balances, one-time codes, identity documents).
///
/// Android applies them to the activity's window; iOS has no equivalent for
/// most of them and only honours [secureWindow].
class ScreenProtectionOptions {
  const ScreenProtectionOptions({
    this.secureWindow = true,
    this.filterObscuredTouches = true,
    this.hideOverlayWindows = true,
  });

  /// Android: `FLAG_SECURE`. Blocks screenshots, screen recording and casting
  /// of the app and blanks its thumbnail in the recent apps list.
  ///
  /// iOS: Apple offers no way to block screenshots or recordings, so the app
  /// is covered with a blurred view while it is recorded or mirrored and when
  /// it goes to the app switcher.
  final bool secureWindow;

  /// Android: ignore touches that pass through another app's window drawn over
  /// yours (tapjacking). Applied to the activity's window with
  /// `setFilterTouchesWhenObscured`.
  final bool filterObscuredTouches;

  /// Android 12 and later: ask the system to hide other apps' overlay windows
  /// (`Window.setHideOverlayWindows`). The plugin declares the
  /// `HIDE_OVERLAY_WINDOWS` permission for it.
  final bool hideOverlayWindows;

  Map<String, Object?> toMap() => <String, Object?>{
    'secureWindow': secureWindow,
    'filterObscuredTouches': filterObscuredTouches,
    'hideOverlayWindows': hideOverlayWindows,
  };

  @override
  bool operator ==(Object other) =>
      other is ScreenProtectionOptions &&
      other.secureWindow == secureWindow &&
      other.filterObscuredTouches == filterObscuredTouches &&
      other.hideOverlayWindows == hideOverlayWindows;

  @override
  int get hashCode =>
      Object.hash(secureWindow, filterObscuredTouches, hideOverlayWindows);
}
