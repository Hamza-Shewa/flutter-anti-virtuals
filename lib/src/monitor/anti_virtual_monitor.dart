import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';

import '../../flutter_anti_virtuals_platform_interface.dart';
import '../report.dart';
import '../scan_options.dart';
import '../signal.dart';
import 'guard_state.dart';

/// Scans the device when it starts, when the app returns to the foreground,
/// when the network or screen-capture state changes and, optionally, on a
/// timer, and decides from each report whether the app should be blocked.
///
/// This is the logic behind [AntiVirtualGuard], without any UI. Use it when
/// the decision belongs somewhere other than a widget at the top of the tree,
/// for example a repository, a Bloc or a Riverpod provider:
///
/// ```dart
/// final monitor = AntiVirtualMonitor(blockOn: {AntiVirtualSignal.vpn})
///   ..start();
/// monitor.addListener(() {
///   if (monitor.value case GuardBlocked(:final matches)) pauseTrading(matches);
/// });
/// ```
///
/// Call [dispose] when it is no longer needed.
class AntiVirtualMonitor extends ChangeNotifier
    with WidgetsBindingObserver
    implements ValueListenable<GuardState> {
  AntiVirtualMonitor({
    ScanOptions? options,
    Set<AntiVirtualSignal> blockOn = defaultBlockingSignals,
    bool failClosed = false,
    bool blockOnInstalledApps = false,
    Duration? rescanInterval,
    bool liveMonitoring = true,
    this.rescanOnResume = true,
    this.rescanDebounce = const Duration(seconds: 3),
    this.liveDebounce = const Duration(milliseconds: 500),
    this.onReport,
    this.onError,
  }) : _options = options ?? ScanOptions(),
       _blockOn = blockOn,
       _failClosed = failClosed,
       _blockOnInstalledApps = blockOnInstalledApps,
       _rescanInterval = rescanInterval,
       _liveMonitoring = liveMonitoring;

  /// Signals that block unless told otherwise: the clear integrity
  /// violations. Softer signals (developer options, an untrusted installer,
  /// which also fires for adb installs) only reach [onReport]. So do
  /// [AntiVirtualSignal.emulator], which would block your own emulator during
  /// development, [AntiVirtualSignal.rooted], which would lock out legitimate
  /// users in some markets, and [AntiVirtualSignal.hooked] and
  /// [AntiVirtualSignal.debugger], which a debug build run from your IDE
  /// reports. Add them where your app needs them.
  static const Set<AntiVirtualSignal> defaultBlockingSignals =
      <AntiVirtualSignal>{
        AntiVirtualSignal.vpn,
        AntiVirtualSignal.proxy,
        AntiVirtualSignal.mockLocation,
        AntiVirtualSignal.virtualCamera,
        AntiVirtualSignal.signatureMismatch,
      };

  /// Scan again when the app comes back to the foreground. Returning from the
  /// background always rescans; a shorter interruption (notification shade,
  /// quick settings, Control Center, permission dialogs) rescans only when
  /// the last scan is older than [rescanDebounce].
  bool rescanOnResume;

  /// Minimum age of the last scan before a short interruption rescans.
  Duration rescanDebounce;

  /// Waits this long after a network or capture change before scanning, so a
  /// burst of changes causes one scan.
  Duration liveDebounce;

  /// Called with every completed scan, blocking or not. Exceptions thrown
  /// here are reported through `FlutterError.reportError` and never unblock.
  ValueChanged<AntiVirtualReport>? onReport;

  /// Called when a scan or the live monitoring fails. Without it the error is
  /// reported through `FlutterError.reportError`.
  void Function(Object error, StackTrace stackTrace)? onError;

  ScanOptions _options;
  Set<AntiVirtualSignal> _blockOn;
  bool _failClosed;
  bool _blockOnInstalledApps;
  Duration? _rescanInterval;
  bool _liveMonitoring;

  GuardState _state = const GuardScanning();
  AntiVirtualReport? _report;
  Object? _error;
  bool _started = false;
  bool _disposed = false;
  bool _inFlight = false;
  bool _rescanQueued = false;
  bool _wasBackgrounded = false;
  bool _foreground = true;
  DateTime? _lastScanAt;
  Timer? _intervalTimer;
  Timer? _liveTimer;
  Timer? _liveMaxTimer;
  Timer? _liveRetryTimer;
  StreamSubscription<void>? _liveSubscription;
  // A change that arrived while the app was in the background: scanned on
  // resume whatever [rescanOnResume] says.
  bool _liveChangePending = false;
  final StreamController<AntiVirtualReport> _reports =
      StreamController<AntiVirtualReport>.broadcast();

  /// The current decision.
  @override
  GuardState get value => _state;

  /// Every completed scan, blocking or not. The same reports reach
  /// [onReport].
  Stream<AntiVirtualReport> get reports => _reports.stream;

  /// True while a scan runs.
  bool get isScanning => _inFlight;

  /// False while the app is in the background.
  bool get isForeground => _foreground;

  /// Which checks run. Setting a different value rescans.
  ScanOptions get options => _options;
  set options(ScanOptions value) {
    if (value == _options) return;
    _options = value;
    if (_started) rescan();
  }

  /// Detected signals from this set block.
  Set<AntiVirtualSignal> get blockOn => _blockOn;
  set blockOn(Set<AntiVirtualSignal> value) {
    if (setEquals(value, _blockOn)) return;
    _blockOn = value;
    _decide();
  }

  /// Block when a scan fails, or when the check of a signal in [blockOn]
  /// fails ([SignalResult.failed]). Without it a failing first scan allows
  /// the app, a failed rescan keeps the previous decision and a failed check
  /// does not block.
  bool get failClosed => _failClosed;
  set failClosed(bool value) {
    if (value == _failClosed) return;
    _failClosed = value;
    _decide();
  }

  /// Also block when the only evidence for a signal is an installed tool
  /// ([SignalResult.onlyInstalledApps]).
  bool get blockOnInstalledApps => _blockOnInstalledApps;
  set blockOnInstalledApps(bool value) {
    if (value == _blockOnInstalledApps) return;
    _blockOnInstalledApps = value;
    _decide();
  }

  /// Also scan this often while the app is in the foreground. `null` turns
  /// the periodic scan off.
  Duration? get rescanInterval => _rescanInterval;
  set rescanInterval(Duration? value) {
    if (value == _rescanInterval) return;
    _rescanInterval = value;
    if (_started) _syncInterval();
  }

  /// Scan as soon as the network or screen-capture state changes, see
  /// `FlutterAntiVirtuals.environmentChanges`.
  bool get liveMonitoring => _liveMonitoring;
  set liveMonitoring(bool value) {
    if (value == _liveMonitoring) return;
    _liveMonitoring = value;
    if (_started) _syncLive();
  }

  /// Starts watching and runs the first scan. Calling it again does nothing.
  void start() {
    if (_started || _disposed) return;
    _started = true;
    WidgetsBinding.instance.addObserver(this);
    _syncInterval();
    _syncLive();
    unawaited(rescan());
  }

  /// Scans now. A scan that is already running is kept and another one runs
  /// right after it, so the result reflects the state at the time of the
  /// call.
  Future<void> rescan() async {
    if (_disposed) return;
    if (_inFlight) {
      _rescanQueued = true;
      return;
    }
    _inFlight = true;
    notifyListeners();
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
    if (_disposed) return;
    _lastScanAt = DateTime.now();
    if (report != null) {
      _error = null;
      _report = report;
      _decide(force: true);
      _guard(() => onReport?.call(report!));
      _reports.add(report);
    } else {
      // A failed first scan fails open (unless [failClosed]); a failed rescan
      // keeps the last known result instead of discarding a known-bad one.
      _error = failure;
      _decide(force: true);
      _reportError(failure!, failureTrace!);
    }
    if (_rescanQueued) {
      _rescanQueued = false;
      unawaited(rescan());
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        _foreground = false;
        _wasBackgrounded = true;
        notifyListeners();
      case AppLifecycleState.resumed:
        _foreground = true;
        final stale =
            _lastScanAt == null ||
            DateTime.now().difference(_lastScanAt!) >= rescanDebounce;
        final changed = _liveChangePending;
        _liveChangePending = false;
        if (changed || (rescanOnResume && (_wasBackgrounded || stale))) {
          unawaited(rescan());
        } else {
          notifyListeners();
        }
        _wasBackgrounded = false;
      case AppLifecycleState.inactive:
        break;
    }
  }

  @override
  void dispose() {
    _disposed = true;
    if (_started) WidgetsBinding.instance.removeObserver(this);
    _intervalTimer?.cancel();
    _cancelLiveTimers();
    _liveRetryTimer?.cancel();
    _liveSubscription?.cancel();
    _reports.close();
    super.dispose();
  }

  /// Recomputes the decision from the last report. Before the first scan has
  /// finished there is nothing to decide, unless [force] says one just did.
  void _decide({bool force = false}) {
    if (_disposed || (!force && _state is GuardScanning)) return;
    final report = _report;
    final matches = report == null
        ? const <AntiVirtualSignal>[]
        : List<AntiVirtualSignal>.unmodifiable(<AntiVirtualSignal>[
            for (final signal in AntiVirtualSignal.values)
              if (_blockOn.contains(signal) && _blocks(report[signal])) signal,
          ]);
    final blockingCheckFailed = report != null && _blockOn.any(report.isFailed);
    final unverified = _failClosed && (_error != null || blockingCheckFailed);
    _state = matches.isNotEmpty || unverified
        ? GuardBlocked(matches: matches, report: report, error: _error)
        : GuardAllowed(report: report, error: _error);
    notifyListeners();
  }

  bool _blocks(SignalResult? result) =>
      result != null &&
      result.detected &&
      (_blockOnInstalledApps || !result.onlyInstalledApps);

  void _syncInterval() {
    _intervalTimer?.cancel();
    _intervalTimer = null;
    final interval = _rescanInterval;
    if (interval == null) return;
    _intervalTimer = Timer.periodic(interval, (_) {
      if (_foreground) unawaited(rescan());
    });
  }

  void _syncLive() {
    _cancelLiveTimers();
    _liveRetryTimer?.cancel();
    _liveRetryTimer = null;
    _liveSubscription?.cancel();
    _liveSubscription = null;
    if (!_liveMonitoring || _disposed) return;
    _liveSubscription = FlutterAntiVirtualsPlatform.instance.environmentChanges
        .listen(_onEnvironmentChange, onError: _onLiveError);
  }

  void _cancelLiveTimers() {
    _liveTimer?.cancel();
    _liveTimer = null;
    _liveMaxTimer?.cancel();
    _liveMaxTimer = null;
  }

  void _onEnvironmentChange(void _) {
    if (!_foreground) {
      _liveChangePending = true; // Scanned on resume.
      return;
    }
    // Wait for a burst to settle, but never longer than a few debounce periods
    // after its first event, so a flapping network cannot postpone the scan.
    _liveTimer?.cancel();
    _liveTimer = Timer(liveDebounce, _liveScan);
    _liveMaxTimer ??= Timer(liveDebounce * 4, _liveScan);
  }

  void _liveScan() {
    _cancelLiveTimers();
    if (_disposed) return;
    if (_foreground) {
      unawaited(rescan());
    } else {
      _liveChangePending = true;
    }
  }

  // Live monitoring is best effort: the other rescans still run. A native side
  // that could not start watching (for example a callback limit) is retried
  // later instead of staying off for the life of the monitor.
  void _onLiveError(Object error, StackTrace stackTrace) {
    _reportError(error, stackTrace, 'while monitoring network changes');
    _liveRetryTimer?.cancel();
    _liveRetryTimer = Timer(const Duration(seconds: 30), _syncLive);
  }

  void _reportError(
    Object error,
    StackTrace stackTrace, [
    String context = 'while scanning the device',
  ]) {
    final handler = onError;
    if (handler == null) {
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
    _guard(() => handler(error, stackTrace));
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
            'while calling an AntiVirtualGuard or AntiVirtualMonitor callback',
          ),
        ),
      );
    }
  }
}
