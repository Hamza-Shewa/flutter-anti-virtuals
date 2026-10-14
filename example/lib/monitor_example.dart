// Usage 3: AntiVirtualMonitor, the guard's logic without its widget. Use it
// from a state management layer (Bloc, Riverpod, a service) or to gate one
// action instead of a whole screen.
//
// Run with: flutter run -t lib/monitor_example.dart
import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';

void main() => runApp(const MonitorExampleApp());

class MonitorExampleApp extends StatefulWidget {
  const MonitorExampleApp({super.key});

  @override
  State<MonitorExampleApp> createState() => _MonitorExampleAppState();
}

class _MonitorExampleAppState extends State<MonitorExampleApp> {
  // Rescans on resume and on network changes, like the guard.
  final _monitor = AntiVirtualMonitor(
    blockOn: {
      ...AntiVirtualMonitor.defaultBlockingSignals,
      AntiVirtualSignal.rooted,
    },
    onError: (error, stackTrace) => debugPrint('scan failed: $error'),
  );

  @override
  void initState() {
    super.initState();
    _monitor.start();
    // Every report, for logging or analytics.
    _monitor.reports.listen((report) => debugPrint('${report.detected}'));
  }

  @override
  void dispose() {
    _monitor.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('AntiVirtualMonitor example')),
        body: Center(
          child: ValueListenableBuilder<GuardState>(
            valueListenable: _monitor,
            builder: (context, state, _) => switch (state) {
              GuardScanning() => const CircularProgressIndicator(),
              GuardAllowed() => FilledButton(
                onPressed: () => ScaffoldMessenger.of(
                  context,
                ).showSnackBar(const SnackBar(content: Text('Paid'))),
                child: const Text('Pay'),
              ),
              GuardBlocked(:final matches, :final unverified) => Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    unverified
                        ? 'This device could not be checked.'
                        : 'Payments are off: ${matches.map((s) => s.name).join(', ')}',
                  ),
                  TextButton(
                    onPressed: _monitor.rescan,
                    child: const Text('Check again'),
                  ),
                ],
              ),
            },
          ),
        ),
      ),
    );
  }
}
