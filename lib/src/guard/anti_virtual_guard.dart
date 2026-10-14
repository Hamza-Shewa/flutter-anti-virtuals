import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform, kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../monitor/anti_virtual_monitor.dart';
import '../monitor/guard_state.dart';
import '../platform/process_exit.dart' if (dart.library.io) 'dart:io' show exit;
import '../report.dart';
import '../scan_options.dart';
import '../screen_protection.dart';
import '../screen_protection_coordinator.dart';
import '../signal.dart';
import 'messages.dart';

/// Builds the screen shown while [matches] (in [AntiVirtualSignal] order) are
/// detected, for example `[vpn, mockLocation]`.
typedef AntiVirtualBlockedBuilder =
    Widget Function(BuildContext context, List<AntiVirtualSignal> matches);

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
/// [waitForScan] is false). While blocked it is removed from the tree, so the
/// Android back button and deep links cannot reach it (a guard above the
/// `Navigator` cannot intercept them), and it is rebuilt with fresh state when
/// the block clears. Set [unmountWhileBlocked] to false to keep it mounted
/// (state survives, but it is only hidden, loses focus and has its animations
/// paused). Code that runs outside the widget tree (`main()`, network calls
/// the app already started) is not stopped.
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
    this.liveMonitoring = true,
    this.liveDebounce = const Duration(milliseconds: 500),
    this.protectScreen,
    this.failClosed = false,
    this.blockOnInstalledApps = false,
    this.unmountWhileBlocked = true,
    this.showRetry = true,
    this.onReport,
    this.onError,
    @visibleForTesting this.exitApp,
  });

  /// Signals that block the app unless [blockOn] says otherwise, see
  /// [AntiVirtualMonitor.defaultBlockingSignals]. Add
  /// [AntiVirtualSignal.emulator] in release builds (`if (kReleaseMode)`), and
  /// [AntiVirtualSignal.rooted], [AntiVirtualSignal.hooked] or
  /// [AntiVirtualSignal.debugger] when your app needs to refuse them.
  static const Set<AntiVirtualSignal> defaultBlockingSignals =
      AntiVirtualMonitor.defaultBlockingSignals;

  /// The monitor of the nearest guard above [context], for example to read
  /// its [AntiVirtualMonitor.value] or listen to its reports.
  static AntiVirtualMonitor? monitorOf(BuildContext context) =>
      context.getInheritedWidgetOfExactType<_GuardScope>()?.monitor;

  /// Scans again from inside the guard, for example from a "Try again"
  /// button in a custom [blockedBuilder].
  static Future<void> rescan(BuildContext context) =>
      monitorOf(context)?.rescan() ?? Future<void>.value();

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

  /// Scan again as soon as the network or the screen-capture state changes (a
  /// VPN or proxy switched on, a screen recording or cast started while the
  /// app is in the foreground), see [FlutterAntiVirtuals.environmentChanges]. Changes while the app is in the
  /// background are covered by the rescan on resume. Mock location and the
  /// camera have no change notification, so they are only seen by the other
  /// rescans.
  final bool liveMonitoring;

  /// Protects the screen while the guard is mounted: no screenshots, screen
  /// recording or casting, no touches through overlays and a blank thumbnail
  /// in the recent apps list (see [ScreenProtectionOptions]). Off (`null`) by
  /// default, because it also stops your own users from taking screenshots.
  /// Pair it with [AntiVirtualSignal.screenCapture] in [blockOn] to hide the
  /// app while the screen is recorded or mirrored.
  final ScreenProtectionOptions? protectScreen;

  /// Waits this long after a network change before scanning, so a burst of
  /// changes (a VPN coming up touches several networks) causes one scan.
  final Duration liveDebounce;

  /// Block the app when a scan fails (first scan, or a rescan), or when the
  /// check of a signal in [blockOn] fails ([SignalResult.failed]), instead of
  /// failing open. The default screen then shows
  /// [AntiVirtualMessages.scanFailed] and [blockedBuilder] receives an empty
  /// list. Without it a failing first scan lets the app through, a failed
  /// rescan keeps the previous result and a failed check does not block.
  final bool failClosed;

  /// Also block when the only evidence for a signal is that a known tool is
  /// installed ([SignalResult.onlyInstalledApps]), for example a fake-GPS app
  /// that is not running. Off by default, because many people have such apps
  /// installed without using them; the detection still reaches [onReport].
  final bool blockOnInstalledApps;

  /// Remove the app from the tree while blocked (the default) instead of only
  /// hiding it, so it cannot react to the back button or deep links. Its state
  /// is lost and it is rebuilt when the block clears. Pass false to keep it
  /// mounted and preserve its state.
  final bool unmountWhileBlocked;

  /// Show a "Try again" button on the built-in blocking screen. It scans
  /// again right away, so a user who switched the VPN off does not have to
  /// leave the app. A custom [blockedBuilder] can do the same with
  /// [AntiVirtualGuard.rescan].
  final bool showRetry;

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
  late final AntiVirtualMonitor _monitor = AntiVirtualMonitor(
    options: widget.options,
    blockOn: widget.blockOn,
    failClosed: widget.failClosed,
    blockOnInstalledApps: widget.blockOnInstalledApps,
    rescanInterval: widget.rescanInterval,
    liveMonitoring: widget.liveMonitoring,
    rescanOnResume: widget.rescanOnResume,
    rescanDebounce: widget.rescanDebounce,
    liveDebounce: widget.liveDebounce,
    onReport: widget.onReport,
    onError: widget.onError,
  );

  // Sticky: once the app has been allowed into the tree it stays mounted
  // while blocked only when [unmountWhileBlocked] is false.
  bool _childAllowed = false;
  Timer? _exitTimer;
  Timer? _tickTimer;
  int _remaining = 0;

  GuardState get _state => _monitor.value;
  bool get _blocked => _state is GuardBlocked;
  List<AntiVirtualSignal> get _matches => switch (_state) {
    GuardBlocked(:final matches) => matches,
    _ => const <AntiVirtualSignal>[],
  };

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _childAllowed = !widget.waitForScan;
    _monitor.addListener(_onMonitorChanged);
    if (widget.protectScreen != null) _syncProtection();
    _monitor.start();
  }

  @override
  void didUpdateWidget(AntiVirtualGuard old) {
    super.didUpdateWidget(old);
    if (old.waitForScan && !widget.waitForScan) _childAllowed = true;
    _monitor
      ..onReport = widget.onReport
      ..onError = widget.onError
      ..rescanOnResume = widget.rescanOnResume
      ..rescanDebounce = widget.rescanDebounce
      ..liveDebounce = widget.liveDebounce
      ..rescanInterval = widget.rescanInterval
      ..liveMonitoring = widget.liveMonitoring;
    if (old.protectScreen != widget.protectScreen &&
        (old.protectScreen != null || widget.protectScreen != null)) {
      _syncProtection();
    }
    if (old.options != widget.options) {
      // Compared by value, so an inline `ScanOptions(...)` does not rescan on
      // every parent rebuild.
      _monitor.options = widget.options ?? ScanOptions();
    }
    _monitor
      ..blockOn = widget.blockOn
      ..failClosed = widget.failClosed
      ..blockOnInstalledApps = widget.blockOnInstalledApps;
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
    _monitor
      ..removeListener(_onMonitorChanged)
      ..dispose();
    if (widget.protectScreen != null) {
      unawaited(
        ScreenProtectionCoordinator.instance
            .request(this, null)
            .then<void>((_) {}, onError: (Object _) {}),
      );
    }
    super.dispose();
  }

  @override
  void didChangeLocales(List<Locale>? locales) {
    if (mounted) setState(() {});
  }

  void _onMonitorChanged() {
    if (!mounted) return;
    setState(() {
      if (_state is! GuardScanning && (!_blocked || !widget.waitForScan)) {
        _childAllowed = true;
      }
    });
    if (_blocked) _dropFocus();
    _syncExit();
  }

  void _syncProtection() {
    ScreenProtectionCoordinator.instance
        .request(this, widget.protectScreen)
        .then<void>(
          (_) {},
          onError: (Object error, StackTrace stackTrace) {
            if (error is MissingPluginException) return;
            _reportError(error, stackTrace, 'while protecting the screen');
          },
        );
  }

  void _reportError(
    Object error,
    StackTrace stackTrace, [
    String context = 'while scanning the device',
  ]) {
    final onError = widget.onError;
    if (onError == null) {
      FlutterError.reportError(
        FlutterErrorDetails(
          exception: error,
          stack: stackTrace,
          library: 'flutter_anti_virtuals',
          context: ErrorDescription(context),
        ),
      );
      return;
    }
    try {
      onError(error, stackTrace);
    } catch (callbackError, callbackTrace) {
      // A callback that throws must not turn a blocked device into an open one.
      FlutterError.reportError(
        FlutterErrorDetails(
          exception: callbackError,
          stack: callbackTrace,
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
    if (!_blocked || !widget.forceExit || !_monitor.isForeground) {
      _cancelExit();
      return;
    }
    if (_exitTimer != null) return; // Already counting down.
    // A rescan is running (for example after a trip to Settings): wait for
    // its result before counting down again.
    if (_monitor.isScanning) return;
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
    // A web page cannot close itself; the blocking screen stays.
    if (kIsWeb) return;
    if (defaultTargetPlatform == TargetPlatform.android && !widget.hardExit) {
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
    final loading = _state is GuardScanning && widget.waitForScan;
    final Widget? cover = loading
        ? (widget.loadingBuilder?.call(context) ?? const _DefaultLoading())
        : blocked
        ? Builder(
            // A context below the scope, so the builder can call
            // [AntiVirtualGuard.rescan].
            builder: (context) =>
                widget.blockedBuilder?.call(context, _matches) ??
                _DefaultBlockedScreen(
                  matches: _matches,
                  messages:
                      widget.messages ??
                      AntiVirtualMessages.forLocale(_resolveLocale()),
                  remainingSeconds: widget.forceExit ? _remaining : null,
                  onRetry: widget.showRetry ? _monitor.rescan : null,
                  retrying: _monitor.isScanning,
                ),
          )
        : null;
    final showChild =
        _childAllowed && !(cover != null && widget.unmountWhileBlocked);
    return _GuardScope(
      monitor: _monitor,
      child: Stack(
        textDirection: Directionality.maybeOf(context) ?? TextDirection.ltr,
        children: <Widget>[
          // Not built before the first clean scan. Afterwards it stays mounted
          // so state survives, but while covered it is hidden, unfocusable,
          // cannot be hit and its tickers (animations) are paused.
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
      ),
    );
  }
}

class _GuardScope extends InheritedWidget {
  const _GuardScope({required this.monitor, required super.child});

  final AntiVirtualMonitor monitor;

  @override
  bool updateShouldNotify(_GuardScope old) => old.monitor != monitor;
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
    this.onRetry,
    this.retrying = false,
  });

  final List<AntiVirtualSignal> matches;
  final AntiVirtualMessages messages;
  final int? remainingSeconds;
  final VoidCallback? onRetry;
  final bool retrying;

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
                    if (onRetry != null) ...<Widget>[
                      const SizedBox(height: 16),
                      Center(
                        child: OutlinedButton.icon(
                          onPressed: retrying ? null : onRetry,
                          style: OutlinedButton.styleFrom(
                            foregroundColor: white,
                            disabledForegroundColor: const Color(0x99FFFFFF),
                            side: const BorderSide(color: Color(0x99FFFFFF)),
                          ),
                          icon: retrying
                              ? const SizedBox.square(
                                  dimension: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: white,
                                  ),
                                )
                              : const Icon(Icons.refresh),
                          label: Text(text.retry),
                        ),
                      ),
                    ],
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
