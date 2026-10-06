import 'dart:async';
import 'dart:io' show Platform, exit;
import 'dart:math' as math;
import 'dart:ui' show Locale, PlatformDispatcher, TextDirection;

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
/// Place it around the app, ideally through `MaterialApp.builder` so the
/// default screen picks up the app's locale:
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
/// The wrapped app stays mounted (its state is kept) but is hidden and cannot
/// be interacted with while blocked. If the scan itself fails, [onError] is
/// called and the app is let through (fail open).
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
    this.rescanOnResume = true,
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

  /// Overrides the default screen's text. Missing languages fall back to the
  /// built-in English, Arabic, French and Spanish messages.
  final AntiVirtualMessages? messages;

  /// Language of the default screen. Defaults to the surrounding
  /// `Localizations` locale, then the device locale.
  final Locale? locale;

  /// Close the app [forceExitAfter] after it gets blocked. Off by default:
  /// Apple's App Review Guidelines discourage apps from quitting themselves,
  /// so this carries App Store risk on iOS.
  final bool forceExit;

  /// How long the blocking screen stays before the app exits (when
  /// [forceExit] is on).
  final Duration forceExitAfter;

  /// Scan again every time the app returns to the foreground.
  final bool rescanOnResume;

  /// Called with every completed scan, blocking or not.
  final ValueChanged<AntiVirtualReport>? onReport;

  /// Called when a scan throws (for example a missing plugin).
  final void Function(Object error, StackTrace stackTrace)? onError;

  /// Replaces the platform exit, for tests.
  final Future<void> Function()? exitApp;

  @override
  State<AntiVirtualGuard> createState() => _AntiVirtualGuardState();
}

class _AntiVirtualGuardState extends State<AntiVirtualGuard>
    with WidgetsBindingObserver {
  late final ScanOptions _options = widget.options ?? ScanOptions();
  bool _scanned = false;
  List<AntiVirtualSignal> _matches = const <AntiVirtualSignal>[];
  int _generation = 0;
  Timer? _exitTimer;
  Timer? _tickTimer;
  int _remaining = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _scan();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _cancelExit();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && widget.rescanOnResume) _scan();
  }

  Future<void> _scan() async {
    final id = ++_generation;
    try {
      final report = await FlutterAntiVirtualsPlatform.instance.scan(_options);
      if (!mounted || id != _generation) return;
      widget.onReport?.call(report);
      setState(() {
        _scanned = true;
        _matches = <AntiVirtualSignal>[
          for (final signal in AntiVirtualSignal.values)
            if (widget.blockOn.contains(signal) && report.isDetected(signal))
              signal,
        ];
      });
      _syncExit();
    } catch (error, stackTrace) {
      if (!mounted || id != _generation) return;
      widget.onError?.call(error, stackTrace);
      setState(() => _scanned = true);
    }
  }

  void _syncExit() {
    if (_matches.isEmpty || !widget.forceExit) {
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
    if (Platform.isAndroid) {
      await SystemNavigator.pop();
    } else {
      exit(0);
    }
  }

  @override
  Widget build(BuildContext context) {
    final blocked = _matches.isNotEmpty;
    final loading = !_scanned && widget.waitForScan;
    final cover = loading
        ? (widget.loadingBuilder?.call(context) ?? const _DefaultLoading())
        : blocked
        ? (widget.blockedBuilder?.call(context, _matches) ??
              _DefaultBlockedScreen(
                matches: _matches,
                messages: widget.messages,
                locale:
                    widget.locale ??
                    Localizations.maybeLocaleOf(context) ??
                    PlatformDispatcher.instance.locale,
                remainingSeconds: widget.forceExit ? _remaining : null,
              ))
        : null;
    return Stack(
      textDirection: Directionality.maybeOf(context) ?? TextDirection.ltr,
      children: <Widget>[
        // Kept mounted so app state survives, but hidden and inert while covered.
        Positioned.fill(
          child: Offstage(offstage: cover != null, child: widget.child),
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
    required this.locale,
    required this.remainingSeconds,
  });

  final List<AntiVirtualSignal> matches;
  final AntiVirtualMessages? messages;
  final Locale locale;
  final int? remainingSeconds;

  @override
  Widget build(BuildContext context) {
    // A custom [messages] object wins; otherwise pick by locale.
    final text = messages ?? AntiVirtualMessages.forLocale(locale);
    const white = Color(0xFFFFFFFF);
    return Directionality(
      textDirection: AntiVirtualMessages.isRtl(locale)
          ? TextDirection.rtl
          : TextDirection.ltr,
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
                    Text(text.subtitle),
                    const SizedBox(height: 16),
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
