import '../report.dart';
import '../signal.dart';

/// What an [AntiVirtualMonitor] has decided about the device.
///
/// Switch over it to build a screen or to gate an action:
///
/// ```dart
/// switch (monitor.value) {
///   GuardScanning() => const CircularProgressIndicator(),
///   GuardAllowed() => const HomePage(),
///   GuardBlocked(:final matches) => BlockedPage(matches: matches),
/// }
/// ```
sealed class GuardState {
  const GuardState();

  /// The last successful scan, or null when none has finished yet.
  AntiVirtualReport? get report;

  /// The error of the last scan when it failed, otherwise null. A failed
  /// rescan keeps [report] from the scan before it.
  Object? get error;

  bool get isBlocked => this is GuardBlocked;
}

/// No scan has finished yet.
final class GuardScanning extends GuardState {
  const GuardScanning();

  @override
  AntiVirtualReport? get report => null;

  @override
  Object? get error => null;

  @override
  String toString() => 'GuardScanning()';
}

/// Nothing that blocks was found, or the scan failed and the monitor fails
/// open (see [AntiVirtualMonitor.failClosed]).
final class GuardAllowed extends GuardState {
  const GuardAllowed({this.report, this.error});

  @override
  final AntiVirtualReport? report;

  @override
  final Object? error;

  @override
  String toString() =>
      'GuardAllowed(${report?.detected ?? 'no report'}'
      '${error == null ? '' : ', error: $error'})';
}

/// A blocking signal was detected, or the device could not be verified and
/// the monitor fails closed.
final class GuardBlocked extends GuardState {
  const GuardBlocked({required this.matches, this.report, this.error});

  /// The blocking detections in [AntiVirtualSignal] order, for example
  /// `[vpn, mockLocation]`. Empty when the block is [unverified].
  final List<AntiVirtualSignal> matches;

  @override
  final AntiVirtualReport? report;

  @override
  final Object? error;

  /// Blocked because a scan or a blocking check failed with
  /// [AntiVirtualMonitor.failClosed] on, not because something was detected.
  bool get unverified => matches.isEmpty;

  @override
  String toString() =>
      'GuardBlocked(${unverified ? 'unverified' : matches}'
      '${error == null ? '' : ', error: $error'})';
}
