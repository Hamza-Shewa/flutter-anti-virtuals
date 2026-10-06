import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatefulWidget {
  const ExampleApp({super.key});

  @override
  State<ExampleApp> createState() => _ExampleAppState();
}

class _ExampleAppState extends State<ExampleApp> {
  // The guard blocks the whole app while a blocking signal is detected. It is
  // off here so every signal of the device can be read on this screen; flip
  // the switch to see the blocking screen.
  bool _block = false;
  bool _protectScreen = false;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Anti virtuals',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.indigo),
      builder: (context, child) => AntiVirtualGuard(
        blockOn: _block
            ? AntiVirtualGuard.defaultBlockingSignals
            : const <AntiVirtualSignal>{},
        // Shows the guard's own screen protection; also works with
        // FlutterAntiVirtuals.instance.protectScreen().
        protectScreen: _protectScreen ? const ScreenProtectionOptions() : null,
        forceExit: false, // true closes the app after forceExitAfter (5s)
        child: child!,
      ),
      home: _HomePage(
        block: _block,
        protectScreen: _protectScreen,
        onBlock: (value) => setState(() => _block = value),
        onProtectScreen: (value) => setState(() => _protectScreen = value),
      ),
    );
  }
}

class _HomePage extends StatefulWidget {
  const _HomePage({
    required this.block,
    required this.protectScreen,
    required this.onBlock,
    required this.onProtectScreen,
  });

  final bool block;
  final bool protectScreen;
  final ValueChanged<bool> onBlock;
  final ValueChanged<bool> onProtectScreen;

  @override
  State<_HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<_HomePage> {
  AntiVirtualReport? _report;
  Object? _error;
  SignedReport? _signed;
  Object? _verifyError;
  int _changes = 0;
  bool _busy = false;
  StreamSubscription<void>? _changesSub;

  @override
  void initState() {
    super.initState();
    _scan();
    // Emits when a VPN or proxy may have been switched on or off, or the
    // screen starts being recorded or mirrored.
    _changesSub = FlutterAntiVirtuals.instance.environmentChanges.listen((_) {
      setState(() => _changes++);
      _scan();
    }, onError: (Object error) => setState(() => _error = error));
  }

  @override
  void dispose() {
    _changesSub?.cancel();
    super.dispose();
  }

  Future<void> _scan() async {
    try {
      final report = await FlutterAntiVirtuals.instance.scan();
      if (mounted) {
        setState(() {
          _report = report;
          _error = null;
        });
      }
    } catch (error) {
      if (mounted) setState(() => _error = error);
    }
  }

  Future<void> _verify({required bool attest}) async {
    setState(() {
      _busy = true;
      _verifyError = null;
    });
    try {
      // In a real app the nonce comes from your backend (single use). It is
      // generated here only so the example runs without a server.
      final random = Random.secure();
      final nonce = base64Url.encode(
        List<int>.generate(24, (_) => random.nextInt(256)),
      );
      final signed = await FlutterAntiVirtuals.instance.verify(
        nonce: nonce,
        // Needs a Google Cloud project number on Android (or the Play
        // Console link) and the App Attest capability on iOS.
        attestation: attest ? const AttestationOptions() : null,
      );
      if (mounted) setState(() => _signed = signed);
    } catch (error) {
      if (mounted) setState(() => _verifyError = error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final report = _report;
    final signed = _signed;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Anti virtuals'),
        actions: [
          IconButton(
            tooltip: 'Scan again',
            onPressed: _scan,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text('Block the app on VPN, proxy, mock location…'),
            subtitle: const Text('AntiVirtualGuard.blockOn'),
            value: widget.block,
            onChanged: widget.onBlock,
          ),
          SwitchListTile(
            title: const Text('Protect the screen'),
            subtitle: const Text(
              'No screenshots, recording or casting; touches through overlays '
              'are ignored (Android). Blur while recorded (iOS).',
            ),
            value: widget.protectScreen,
            onChanged: widget.onProtectScreen,
          ),
          ListTile(
            leading: const Icon(Icons.sensors),
            title: Text('Environment changes seen: $_changes'),
            subtitle: const Text(
              'Switch a VPN or a proxy on or off, or cast the screen.',
            ),
          ),
          const Divider(),
          const _Heading('Signals'),
          if (_error != null)
            ListTile(
              leading: const Icon(Icons.error_outline, color: Colors.red),
              title: Text('$_error'),
            ),
          if (report == null && _error == null)
            const Padding(
              padding: EdgeInsets.all(24),
              child: Center(child: CircularProgressIndicator()),
            ),
          if (report != null)
            for (final signal in AntiVirtualSignal.values)
              if (report[signal] case final result?)
                ListTile(
                  leading: Icon(
                    !result.supported
                        ? Icons.remove_circle_outline
                        : result.detected
                        ? Icons.warning_amber
                        : Icons.check_circle_outline,
                    color: result.detected ? Colors.red : null,
                  ),
                  title: Text(signal.name),
                  subtitle: result.details.isEmpty
                      ? null
                      : Text(result.details.join('\n')),
                ),
          const Divider(),
          const _Heading('Verify before a sensitive action'),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Wrap(
              spacing: 8,
              children: [
                FilledButton(
                  onPressed: _busy ? null : () => _verify(attest: false),
                  child: const Text('Sign report'),
                ),
                OutlinedButton(
                  onPressed: _busy ? null : () => _verify(attest: true),
                  child: const Text('Sign + Play Integrity / App Attest'),
                ),
              ],
            ),
          ),
          if (_verifyError != null)
            ListTile(
              leading: const Icon(Icons.error_outline, color: Colors.red),
              title: Text('$_verifyError'),
            ),
          if (signed != null) ...[
            ListTile(
              title: Text(
                'Key: ${signed.signature.protection.name}, attested: '
                '${signed.signature.attested}',
              ),
              subtitle: Text(
                'Certificates: ${signed.signature.certificateChain.length}'
                '${signed.attestation == null ? '' : ', ${signed.attestation}'}',
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
              child: SelectableText(
                signed.payload,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _Heading extends StatelessWidget {
  const _Heading(this.text);

  final String text;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
    child: Text(text, style: Theme.of(context).textTheme.titleMedium),
  );
}
