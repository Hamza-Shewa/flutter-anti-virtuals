import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatefulWidget {
  const ExampleApp({super.key});

  @override
  State<ExampleApp> createState() => _ExampleAppState();
}

class _ExampleAppState extends State<ExampleApp> {
  AntiVirtualReport? _report;

  @override
  void initState() {
    super.initState();
    _scan();
  }

  Future<void> _scan() async {
    final report = await FlutterAntiVirtuals.instance.scan();
    if (mounted) setState(() => _report = report);
  }

  @override
  Widget build(BuildContext context) {
    final report = _report;
    return MaterialApp(
      // Blocks the whole app while VPN, proxy, mock location, a virtual camera
      // or a tampered signature is detected.
      builder: (context, child) => AntiVirtualGuard(
        forceExit: false, // set true to close the app after forceExitAfter (5s)
        child: child!,
      ),
      home: Scaffold(
        appBar: AppBar(title: const Text('Anti virtuals')),
        floatingActionButton: FloatingActionButton(
          onPressed: _scan,
          child: const Icon(Icons.refresh),
        ),
        body: report == null
            ? const Center(child: CircularProgressIndicator())
            : ListView(
                children: [
                  for (final entry in report.results.entries)
                    ListTile(
                      leading: Icon(
                        !entry.value.supported
                            ? Icons.remove_circle_outline
                            : entry.value.detected
                            ? Icons.warning_amber
                            : Icons.check_circle_outline,
                        color: entry.value.detected ? Colors.red : null,
                      ),
                      title: Text(entry.key.name),
                      subtitle: entry.value.details.isEmpty
                          ? null
                          : Text(entry.value.details.join('\n')),
                    ),
                ],
              ),
      ),
    );
  }
}
