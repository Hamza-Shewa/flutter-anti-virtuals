// Usage 1: call scan() yourself and decide what to do with the result.
//
// Run with: flutter run -t lib/scan_example.dart
import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';

void main() => runApp(const ScanExampleApp());

class ScanExampleApp extends StatelessWidget {
  const ScanExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'scan() example',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.teal),
      home: const _ScanPage(),
    );
  }
}

class _ScanPage extends StatefulWidget {
  const _ScanPage();

  @override
  State<_ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<_ScanPage> {
  String _output = 'Nothing scanned yet.';

  // 1. A full scan with every check on (the default).
  Future<void> _scanEverything() async {
    final report = await FlutterAntiVirtuals.instance.scan();
    setState(() => _output = _describe(report));
  }

  // 2. Only the checks you need, with the configuration some of them require.
  Future<void> _scanForPayments() async {
    final report = await FlutterAntiVirtuals.instance.scan(
      ScanOptions(
        checkDeveloperOptions: false,
        checkAdb: false,
        checkClockTampering: false,
        // Pass your release certificate's SHA-256 (from
        // `keytool -list -v -keystore <keystore>`) to also detect a
        // repackaged app. Debug builds never match, so leave it out there:
        // expectedSignatureSha256: ['<sha256>'],
        allowedAccessibilityServices: ['com.google.android.marvin.talkback'],
      ),
    );
    setState(() => _output = _describe(report));
  }

  // 3. One signal.
  Future<void> _checkOne() async {
    final result = await FlutterAntiVirtuals.instance.check(
      AntiVirtualSignal.vpn,
    );
    setState(() {
      _output =
          'vpn: ${result.detected ? 'DETECTED' : 'clean'}'
          '${result.supported ? '' : ' (not supported here)'}\n'
          '${result.details.join('\n')}';
    });
  }

  // 4. Decide before a sensitive action. A failed scan is not a clean device:
  //    here it blocks, which is the safe default for money movements.
  Future<void> _pay() async {
    const risky = {
      AntiVirtualSignal.rooted,
      AntiVirtualSignal.hooked,
      AntiVirtualSignal.mockLocation,
      AntiVirtualSignal.vpn,
      AntiVirtualSignal.proxy,
      AntiVirtualSignal.screenCapture,
    };
    String message;
    try {
      final report = await FlutterAntiVirtuals.instance.scan();
      final found = report.detected.intersection(risky);
      message = found.isEmpty
          ? 'Payment sent.'
          : 'Payment refused: ${found.map((s) => s.name).join(', ')}.';
    } catch (error) {
      message = 'Payment refused: this device could not be verified ($error).';
    }
    if (mounted) setState(() => _output = message);
  }

  String _describe(AntiVirtualReport report) {
    if (report.isClean) return 'Clean: nothing detected.';
    final lines = <String>[];
    for (final signal in report.detected) {
      lines.add('${signal.name}: ${report[signal]!.details.join('; ')}');
    }
    // report.toJson() is what you would send to your server.
    return lines.join('\n');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('scan() example')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilledButton(
                onPressed: _scanEverything,
                child: const Text('Scan everything'),
              ),
              FilledButton(
                onPressed: _scanForPayments,
                child: const Text('Scan for payments'),
              ),
              FilledButton(
                onPressed: _checkOne,
                child: const Text('Check VPN only'),
              ),
              OutlinedButton(onPressed: _pay, child: const Text('Pay')),
            ],
          ),
          const SizedBox(height: 24),
          SelectableText(_output),
        ],
      ),
    );
  }
}
