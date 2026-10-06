// Usage 2: wrap the app (or one screen) in AntiVirtualGuard and let it block.
//
// Run with: flutter run -t lib/guard_example.dart
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';

void main() => runApp(const GuardExampleApp());

class GuardExampleApp extends StatelessWidget {
  const GuardExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AntiVirtualGuard example',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.deepOrange),
      // A. Around the whole app: nothing is built until the first scan is
      //    clean, and the app is covered again whenever a blocking signal
      //    shows up (a VPN switched on, a mock location app started, ...).
      builder: (context, child) => AntiVirtualGuard(
        // Pass your release certificate's SHA-256 to also block a repackaged
        // app (it is skipped without it):
        // options: ScanOptions(expectedSignatureSha256: ['<sha256>']),
        // What blocks. Everything else only reaches onReport.
        blockOn: {
          ...AntiVirtualGuard.defaultBlockingSignals,
          // Refuse emulators and rooted devices in release builds only, so
          // you can still develop on an emulator.
          if (kReleaseMode) ...{
            AntiVirtualSignal.emulator,
            AntiVirtualSignal.rooted,
          },
        },
        // Your own blocking screen instead of the built-in one. `matches` is
        // what was detected, e.g. [vpn, proxy].
        blockedBuilder: (context, matches) => _BlockedScreen(matches: matches),
        // Every completed scan: log it, or send it to your server.
        onReport: (report) =>
            debugPrint('scan finished, detected: ${report.detected}'),
        onError: (error, stackTrace) => debugPrint('scan failed: $error'),
        // Close the app a few seconds after blocking (Android and iOS; Apple
        // discourages it, see the README). Off by default.
        forceExit: false,
        child: child!,
      ),
      home: const _HomePage(),
    );
  }
}

class _HomePage extends StatelessWidget {
  const _HomePage();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('AntiVirtualGuard example')),
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('This app is only visible while the device is clean.'),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () => Navigator.of(context).push(
                MaterialPageRoute<void>(builder: (_) => const _VaultPage()),
              ),
              child: const Text('Open the vault'),
            ),
          ],
        ),
      ),
    );
  }
}

/// B. Around one screen: a stricter guard for the sensitive part of the app.
///    The screen is protected from screenshots and recording while it is
///    shown, and screen capture also blocks it. Guards can be nested: the app
///    guard above still applies.
class _VaultPage extends StatelessWidget {
  const _VaultPage();

  @override
  Widget build(BuildContext context) {
    return AntiVirtualGuard(
      blockOn: {
        ...AntiVirtualGuard.defaultBlockingSignals,
        AntiVirtualSignal.screenCapture,
        AntiVirtualSignal.hooked,
      },
      protectScreen: const ScreenProtectionOptions(),
      // Without this the built-in screen is used.
      messages: AntiVirtualMessages.english,
      child: Scaffold(
        appBar: AppBar(title: const Text('Vault')),
        body: const Center(child: Text('Account number 1234 5678')),
      ),
    );
  }
}

class _BlockedScreen extends StatelessWidget {
  const _BlockedScreen({required this.matches});

  final List<AntiVirtualSignal> matches;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Theme.of(context).colorScheme.errorContainer,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.shield_outlined, size: 64),
              const SizedBox(height: 16),
              Text(
                'This device is not allowed',
                style: Theme.of(context).textTheme.headlineSmall,
              ),
              const SizedBox(height: 8),
              Text(
                matches.isEmpty
                    ? 'It could not be verified.'
                    : 'Detected: ${matches.map((s) => s.name).join(', ')}.',
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
