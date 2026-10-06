import 'dart:async';
import 'dart:io' show Platform, exit;
import 'dart:math' as math;

import 'package:flutter/foundation.dart' show setEquals;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../flutter_anti_virtuals_platform_interface.dart';
import '../report.dart';
import '../scan_options.dart';
import '../signal.dart';
import 'messages.dart';

/// Builds the screen shown while [matches] (in [AntiVirtualSignal] order) are
/// detected, for example `[vpn, mockLocation]`.
typedef AntiVirtualBlockedBuilder = Widget Function(
  BuildContext context,
  List<AntiVirtualSignal> matches,
);

/// Runs a scan when the app starts (and when it returns to the foreground) and
/// covers [child] with a blocking screen while a blocking signal is detected.
///
/// Place it around the app, ideally through `MaterialApp.builder` (the default
/// screen follows the device language, see [locale]):
///
/// ```dart
/// MaterialApp(
///   builder: (context, child) => AntiVirtualGuard(
///     options: ScanOptions(expectedSignatureSha256: ['...']),
///     child: child!,
///   ),
/// )
/// ```
///
/// The wrapped app is not built until the first scan is clean (unless
/// [waitForScan] is false). Once built it stays mounted so its state survives,
/// but while blocked it is hidden, loses focus and has its animations paused.
/// Code that runs outside the widget tree (`main()`, network calls the app
/// already started) is not stopped. The Android back button still reaches the
/// hidden app (a guard above the `Navigator` cannot intercept it); set
/// [unmountWhileBlocked] to remove the app from the tree while blocked.
///
/// If the very first scan fails, [onError] is called and the app is let
/// through (fail open) unless [failClosed] is set. A failed rescan keeps the
/// last known result.
class AntiVirtualGuard extends StatefulWidget {
  const AntiVirtualGuard({
    super.key,
    required this.child,
    this.options,
    this.blockOn = defaultBlockingSignals,
    this.blockedBuilder,
    this.loadingBuilder,
    this.waitForScan = true,
    this.messages,
    this.locale,
    this.forceExit = false,
    this.forceExitAfter = const Duration(seconds: 5),
    this.hardExit = false,
    this.rescanOnResume = true,
    this.rescanDebounce = const Duration(seconds: 3),
    this.rescanInterval,
    this.failClosed = false,
    this.unmountWhileBlocked = false,
    this.onReport,
    this.onError,
    @visibleForTesting this.exitApp,
  });

  /// Signals that block the app unless [blockOn] says otherwise. These are the
  /// clear integrity violations; softer signals such as developer options or
  /// an untrusted installer (which also fires for adb installs) are reported
  /// through [onReport] but do not block by default.
  static const Set<AntiVirtualSignal> defaultBlockingSignals =
      <AntiVirtualSignal>{
        AntiVirtualSignal.vpn,
        AntiVirtualSignal.proxy,
        AntiVirtualSignal.mockLocation,
        AntiVirtualSignal.virtualCamera,
        AntiVirtualSignal.signatureMismatch,
      };

  /// The app to protect.
  final Widget child;

  /// Which checks to run. Defaults to `ScanOptions()` (everything on).
  final ScanOptions? options;

  /// Detected signals from this set block the app; others only reach
  /// [onReport].
  final Set<AntiVirtualSignal> blockOn;

  /// Replaces the default screen. Receives the list of blocking detections so
  /// you can write your own text.
  final AntiVirtualBlockedBuilder? blockedBuilder;

  /// Shown while the first scan is running (when [waitForScan] is true).
  final WidgetBuilder? loadingBuilder;

  /// Hide [child] until the first scan finished. Set to false to show the app
  /// immediately and block only if something is found.
  final bool waitForScan;

  /// Overrides the default screen's text (and its layout direction, see
  /// [AntiVirtualMessages.textDirection]).
  final AntiVirtualMessages? messages;

  /// Language of the default screen. Defaults to the device language, falling
  /// back to English when it is not one of
  /// [AntiVirtualMessages.supportedLanguages]. Apps with their own language
  /// switch can pass `Localizations.localeOf(context)` from inside
  /// `MaterialApp.builder`.
  final Locale? locale;

  /// Close the app [forceExitAfter] after it gets blocked. Off by default:
  /// Apple's App Review Guidelines discourage apps from quitting themselves,
  /// so this carries App Store risk on iOS. The countdown pauses while the app
  /// is in the background (so users can go and fix the problem) and restarts
  /// when they return and the rescan still finds it.
  final bool forceExit;

  /// How long the blocking screen stays before the app exits (when
  /// [forceExit] is on).
  final Duration forceExitAfter;

  /// Android only: exit with `exit(0)` instead of `SystemNavigator.pop()`.
  /// `SystemNavigator.pop()` finishes the Flutter activity; if the app was
  /// started on top of another activity, or background services keep the
  /// process alive, the user lands on the previous screen and the process may
  /// keep running. `exit(0)` ends the process. iOS always uses `exit(0)`.
  final bool hardExit;

  /// Scan again when the app comes back to the foreground. Returning from the
  /// background always rescans; a shorter interruption (notification shade,
  /// quick settings, Control Center, permission dialogs) rescans only when the
  /// last scan is older than [rescanDebounce], so a VPN switched on from quick
  /// settings is caught. A scan already running is kept, not restarted.
  final bool rescanOnResume;

  /// Minimum age of the last scan before a short interruption triggers a
  /// rescan (see [rescanOnResume]).
  final Duration rescanDebounce;

  /// Also scan this often while the app is in the foreground. `null` (the
  /// default) disables the periodic scan.
  final Duration? rescanInterval;

  /// Block the app when a scan fails (first scan, or a rescan) instead of
  /// failing open. The default screen then shows
  /// [AntiVirtualMessages.scanFailed] and [blockedBuilder] receives an empty
  /// list. Without it a failing first scan lets the app through, and a failed
  /// rescan keeps the previous result.
  final bool failClosed;

  /// Remove the app from the tree while blocked instead of only hiding it, so
  /// it cannot react to the back button or deep links. Its state is lost and
  /// it is rebuilt when the block clears.
  final bool unmountWhileBlocked;

  /// Called with every completed scan, blocking or not. Exceptions thrown here
  /// are reported through `FlutterError.reportError` and never unblock.
  final ValueChanged<AntiVirtualReport>? onReport;

  /// Called when a scan throws (for example a missing plugin). Without it the
  /// error is reported through `FlutterError.reportError`.
  final void Function(Object error, StackTrace stackTrace)? onError;

  /// Replaces the platform exit, for tests.
  final Future<void> Function()? exitApp;

  @override
  State<AntiVirtualGuard> createState() => _AntiVirtualGuardState();
}

class _AntiVirtualGuardState extends State<AntiVirtualGuard>
    with WidgetsBindingObserver {
  AntiVirtualReport? _report;
  bool _scanned = false;
  bool _failed = false;
  // Sticky: once the app has been allowed into the tree it stays mounted
  // (unless [unmountWhileBlocked]).
  bool _childAllowed = false;
  bool _inFlight = false;
  bool _rescanQueued = false;
  bool _wasBackgrounded = false;
  bool _foreground = true;
  DateTime? _lastScanAt;
  List<AntiVirtualSignal> _matches = const <AntiVirtualSignal>[];
  Timer? _exitTimer;
  Timer? _tickTimer;
  Timer? _intervalTimer;
  int _remaining = 0;

  late ScanOptions _options = widget.options ?? ScanOptions();

  bool get _blocked => _matches.isNotEmpty || (_failed && widget.failClosed);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _childAllowed = !widget.waitForScan;
    _syncInterval();
    _scan();
  }

  @override
  void didUpdateWidget(AntiVirtualGuard old) {
    super.didUpdateWidget(old);
    var changedOptions = false;
    if (old.options != widget.options) {
      // Compared by value, so an inline `ScanOptions(...)` does not rescan on
      // every parent rebuild.
      _options = widget.options ?? ScanOptions();
      changedOptions = true;
    }
    if (old.waitForScan && !widget.waitForScan) _childAllowed = true;
    if (old.rescanInterval != widget.rescanInterval) _syncInterval();
    if (changedOptions) {
      _scan();
    } else if (!setEquals(old.blockOn, widget.blockOn) ||
        old.failClosed != widget.failClosed) {
      _apply();
    }
    if (old.forceExit != widget.forceExit ||
        old.forceExitAfter != widget.forceExitAfter) {
      _cancelExit();
      _syncExit();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _cancelExit();
    _intervalTimer?.cancel();
    super.dispose();
  }

  @override
  void didChangeLocales(List<Locale>? locales) {
    if (mounted) setState(() {});
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        // The user left (maybe to fix the problem in Settings): stop the
        // countdown; it restarts when the app returns and still finds a match.
        _foreground = false;
        _wasBackgrounded = true;
        _cancelExit();
      case AppLifecycleState.resumed:
        _foreground = true;
        final stale =
            _lastScanAt == null ||
            DateTime.now().difference(_lastScanAt!) >= widget.rescanDebounce;
        if (widget.rescanOnResume && (_wasBackgrounded || stale)) {
          _scan();
        } else {
          // No rescan to restart the countdown for us.
          _syncExit();
        }
        _wasBackgrounded = false;
      case AppLifecycleState.inactive:
        break;
    }
  }

  void _syncInterval() {
    _intervalTimer?.cancel();
    _intervalTimer = null;
    final interval = widget.rescanInterval;
    if (interval == null) return;
    _intervalTimer = Timer.periodic(interval, (_) {
      if (_foreground) _scan();
    });
  }

  Future<void> _scan() async {
    if (_inFlight) {
      // Keep the running scan (its result is still applied); refresh after.
      _rescanQueued = true;
      return;
    }
    _inFlight = true;
    AntiVirtualReport? report;
    Object? failure;
    StackTrace? failureTrace;
    try {
      report = await FlutterAntiVirtualsPlatform.instance.scan(_options);
    } catch (error, stackTrace) {
      failure = error;
      failureTrace = stackTrace;
    }
    _inFlight = false;
    if (!mounted) return;
    _lastScanAt = DateTime.now();
    if (report != null) {
      _failed = false;
      _report = report;
      _apply();
      _guard(() => widget.onReport?.call(report!));
    } else {
      // A failed first scan fails open (unless [failClosed]); a failed rescan
      // keeps the last known result instead of discarding a known-bad one.
      _failed = true;
      _apply();
      _reportError(failure!, failureTrace!);
    }
    if (_rescanQueued) {
      _rescanQueued = false;
      unawaited(_scan());
    }
  }

  /// Recomputes what blocks from the last report.
  void _apply() {
    if (!mounted) return;
    final report = _report;
    setState(() {
      _scanned = true;
      _matches = report == null
          ? const <AntiVirtualSignal>[]
          : <AntiVirtualSignal>[
              for (final signal in AntiVirtualSignal.values)
                if (widget.blockOn.contains(signal) &&
                    report.isDetected(signal))
                  signal,
            ];
      if (!_blocked || !widget.waitForScan) _childAllowed = true;
    });
    if (_blocked) _dropFocus();
    _syncExit();
  }

  void _reportError(Object error, StackTrace stackTrace) {
    final onError = widget.onError;
    if (onError == null) {
      FlutterError.reportError(
        FlutterErrorDetails(
          exception: error,
          stack: stackTrace,
          library: 'flutter_anti_virtuals',
          context: ErrorDescription('while scanning the device'),
        ),
      );
      return;
    }
    _guard(() => onError(error, stackTrace));
  }

  // A callback that throws must not turn a blocked device into an open one.
  void _guard(void Function() callback) {
    try {
      callback();
    } catch (error, stackTrace) {
      FlutterError.reportError(
        FlutterErrorDetails(
          exception: error,
          stack: stackTrace,
          library: 'flutter_anti_virtuals',
          context: ErrorDescription(
            'while calling an AntiVirtualGuard callback',
          ),
        ),
      );
    }
  }

  void _dropFocus() => FocusManager.instance.primaryFocus?.unfocus();

  void _syncExit() {
    if (!_blocked || !widget.forceExit || !_foreground) {
      _cancelExit();
      return;
    }
    if (_exitTimer != null) return; // Already counting down.
    _remaining = math.max(
      1,
      (widget.forceExitAfter.inMilliseconds / 1000).ceil(),
    );
    _exitTimer = Timer(widget.forceExitAfter, _exit);
    _tickTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() => _remaining = math.max(0, _remaining - 1));
    });
  }

  void _cancelExit() {
    _exitTimer?.cancel();
    _tickTimer?.cancel();
    _exitTimer = null;
    _tickTimer = null;
  }

  Future<void> _exit() async {
    _cancelExit();
    final exitApp = widget.exitApp;
    if (exitApp != null) return exitApp();
    if (Platform.isAndroid && !widget.hardExit) {
      await SystemNavigator.pop();
    } else {
      exit(0);
    }
  }

  Locale _resolveLocale() {
    final explicit = widget.locale;
    if (explicit != null) return explicit;
    final device = WidgetsBinding.instance.platformDispatcher.locales;
    for (final locale in device) {
      if (AntiVirtualMessages.supportedLanguages.contains(
        locale.languageCode,
      )) {
        return locale;
      }
    }
    return const Locale('en');
  }

  @override
  Widget build(BuildContext context) {
    final blocked = _blocked;
    final loading = !_scanned && widget.waitForScan;
    final Widget? cover = loading
        ? (widget.loadingBuilder?.call(context) ?? const _DefaultLoading())
        : blocked
        ? (widget.blockedBuilder?.call(context, _matches) ??
              _DefaultBlockedScreen(
                matches: _matches,
                messages:
                    widget.messages ??
                    AntiVirtualMessages.forLocale(_resolveLocale()),
                remainingSeconds: widget.forceExit ? _remaining : null,
              ))
        : null;
    final showChild =
        _childAllowed && !(cover != null && widget.unmountWhileBlocked);
    return Stack(
      textDirection: Directionality.maybeOf(context) ?? TextDirection.ltr,
      children: <Widget>[
        // Not built before the first clean scan. Afterwards it stays mounted so
        // state survives, but while covered it is hidden, unfocusable, cannot be
        // hit and its tickers (animations) are paused.
        if (showChild)
          Positioned.fill(
            child: Offstage(
              offstage: cover != null,
              child: TickerMode(
                enabled: cover == null,
                child: ExcludeFocus(
                  excluding: cover != null,
                  child: IgnorePointer(
                    ignoring: cover != null,
                    child: widget.child,
                  ),
                ),
              ),
            ),
          ),
        if (cover != null) Positioned.fill(child: cover),
      ],
    );
  }
}

class _DefaultLoading extends StatelessWidget {
  const _DefaultLoading();

  @override
  Widget build(BuildContext context) => const ColoredBox(
    color: Color(0xFF111111),
    child: Center(child: CircularProgressIndicator()),
  );
}

class _DefaultBlockedScreen extends StatelessWidget {
  const _DefaultBlockedScreen({
    required this.matches,
    required this.messages,
    required this.remainingSeconds,
  });

  final List<AntiVirtualSignal> matches;
  final AntiVirtualMessages messages;
  final int? remainingSeconds;

  @override
  Widget build(BuildContext context) {
    final text = messages;
    const white = Color(0xFFFFFFFF);
    return Directionality(
      textDirection: text.textDirection,
      child: Material(
        color: const Color(0xFF111111),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: DefaultTextStyle(
                style: const TextStyle(color: white, fontSize: 16, height: 1.4),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    const Center(
                      child: Icon(
                        Icons.gpp_maybe_outlined,
                        color: white,
                        size: 64,
                      ),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      text.title,
                      style: const TextStyle(
                        fontSize: 22,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 8),
                    if (matches.isNotEmpty) Text(text.subtitle),
                    const SizedBox(height: 16),
                    if (matches.isEmpty)
                      Text(text.scanFailed)
                    else
                      for (final signal in matches)
                        Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: <Widget>[
                              const Text('•  '),
                              Expanded(child: Text(text.messageFor(signal))),
                            ],
                          ),
                        ),
                    if (remainingSeconds != null) ...<Widget>[
                      const SizedBox(height: 16),
                      Text(
                        text.closingMessage(remainingSeconds!),
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
