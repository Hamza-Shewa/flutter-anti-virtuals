import 'package:flutter_anti_virtuals/flutter_anti_virtuals.dart';
import 'package:flutter_anti_virtuals/flutter_anti_virtuals_platform_interface.dart';
import 'package:flutter_anti_virtuals/src/platform/checks/clock_check.dart';
import 'package:flutter_anti_virtuals/src/platform/checks/signal_check.dart';
import 'package:flutter_anti_virtuals/src/platform/desktop/desktop_checks.dart';
import 'package:flutter_anti_virtuals/src/platform/desktop/desktop_environment.dart';
import 'package:flutter_anti_virtuals/src/platform/desktop/desktop_platform.dart';
import 'package:flutter_anti_virtuals/src/platform/desktop/desktop_rules.dart';
import 'package:flutter_test/flutter_test.dart';

/// A desktop whose tools print what a test hands it.
class _FakeDesktop implements DesktopEnvironment {
  _FakeDesktop(
    this.os, {
    this.adapters = const [],
    this.outputs = const {},
    this.files = const {},
    this.variables = const {},
    this.debugger,
  });

  @override
  final DesktopOs os;
  final List<NetworkAdapter> adapters;
  final Map<String, String> outputs;
  final Map<String, String> files;
  final bool? debugger;
  final calls = <String>[];

  @override
  final Map<String, String> variables;

  @override
  int get pid => 42;

  @override
  Future<List<NetworkAdapter>> networkAdapters() async => adapters;

  @override
  Future<String?> run(String executable, List<String> arguments) async {
    final command = [executable, ...arguments].join(' ');
    calls.add(command);
    return outputs[command];
  }

  @override
  Future<String?> readFile(String path) async => files[path];

  @override
  bool? nativeDebuggerPresent() => debugger;
}

class _ThrowingCheck implements SignalCheck {
  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.vpn;

  @override
  Future<SignalResult> run(ScanOptions options) => throw StateError('boom');
}

void main() {
  group('CheckRunner', () {
    test(
      'answers every requested signal, unsupported where it has no check',
      () async {
        final report = await CheckRunner([ClockCheck()]).scan(ScanOptions());
        expect(report.results.keys.toSet(), ScanOptions().enabledSignals);
        expect(report[AntiVirtualSignal.mockLocation]!.supported, isFalse);
        expect(report.isClean, isTrue);
      },
    );

    test('a check that throws is failed, not clean', () async {
      final report = await CheckRunner([_ThrowingCheck()]).scan(ScanOptions());
      expect(report.isFailed(AntiVirtualSignal.vpn), isTrue);
      expect(report.isClean, isFalse);
    });
  });

  group('ClockCheck', () {
    final now = DateTime.utc(2026, 10, 14, 12);
    final check = ClockCheck(now: () => now);

    test('is unsupported without a trusted time', () async {
      expect((await check.run(ScanOptions())).supported, isFalse);
    });

    test('reports a skew beyond the limit', () async {
      final late = await check.run(
        ScanOptions(trustedTime: now.subtract(const Duration(minutes: 10))),
      );
      expect(late.detected, isTrue);
      final fine = await check.run(
        ScanOptions(trustedTime: now.add(const Duration(seconds: 30))),
      );
      expect(fine.detected, isFalse);
    });
  });

  group('vpn', () {
    test('tunnel interfaces by system', () {
      expect(
        DesktopRules.vpnInterfaces(DesktopOs.linux, const [
          NetworkAdapter('eth0'),
          NetworkAdapter('docker0'),
          NetworkAdapter('wg0'),
          NetworkAdapter('tun1'),
        ]),
        ['interface wg0', 'interface tun1'],
      );
      expect(
        DesktopRules.vpnInterfaces(DesktopOs.macOS, const [
          NetworkAdapter('en0'),
          NetworkAdapter('utun4'),
        ]),
        ['interface utun4'],
      );
      expect(
        DesktopRules.vpnInterfaces(DesktopOs.windows, const [
          NetworkAdapter('Wi-Fi'),
          NetworkAdapter('Teredo Tunneling Pseudo-Interface'),
          NetworkAdapter('ProtonVPN'),
          NetworkAdapter('wg-office'),
        ]),
        ['interface ProtonVPN', 'interface wg-office'],
      );
    });

    test('connected macOS VPN services', () {
      const list = '''
Available network connection services in the current set (*=enabled):
* (Connected)      1A2B3C4D-0000 VPN (com.wireguard.macos) "Office"  [VPN/com.wireguard.macos]
* (Disconnected)   5E6F7A8B-0000 VPN (com.example) "Home"  [VPN/com.example]
''';
      expect(DesktopRules.macVpnServices(list), [
        'VPN service Office connected',
      ]);
      expect(DesktopRules.macVpnServices(null), isEmpty);
    });

    test('the check asks scutil on macOS only', () async {
      final mac = _FakeDesktop(
        DesktopOs.macOS,
        outputs: {'/usr/sbin/scutil --nc list': '* (Connected) x "Work"'},
      );
      final result = await DesktopVpnCheck(mac).run(ScanOptions());
      expect(result.details, ['VPN service Work connected']);
      final linux = _FakeDesktop(DesktopOs.linux);
      expect(
        (await DesktopVpnCheck(linux).run(ScanOptions())).detected,
        isFalse,
      );
      expect(linux.calls, isEmpty);
    });
  });

  group('proxy', () {
    test('environment variables in either case', () {
      expect(
        DesktopRules.proxyVariables({
          'https_proxy': 'http://10.0.0.1:8080',
          'HTTP_PROXY': ' ',
          'NO_PROXY': 'localhost',
        }),
        ['environment https_proxy'],
      );
    });

    test('macOS system proxy settings', () {
      const proxy = '''
<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : 10.0.0.1
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad/proxy.pac
}
''';
      expect(DesktopRules.macProxy(proxy), [
        'HTTP proxy 10.0.0.1:8080',
        'PAC http://wpad/proxy.pac',
      ]);
      expect(
        DesktopRules.macProxy('<dictionary> {\n  HTTPEnable : 0\n}'),
        isEmpty,
      );
    });

    test('Windows Internet Settings', () {
      const registry = r'''
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    127.0.0.1:8888
''';
      expect(DesktopRules.windowsProxy(registry), [
        'system proxy 127.0.0.1:8888',
      ]);
      expect(
        DesktopRules.windowsProxy('    ProxyEnable    REG_DWORD    0x0\n'),
        isEmpty,
      );
    });

    test('GNOME proxy mode', () {
      expect(DesktopRules.gnomeProxy("'manual'\n"), hasLength(1));
      expect(DesktopRules.gnomeProxy("'none'\n"), isEmpty);
      expect(DesktopRules.gnomeProxy(null), isEmpty);
    });

    test('the check combines the environment and the system', () async {
      final windows = _FakeDesktop(
        DesktopOs.windows,
        variables: {'ALL_PROXY': 'socks5://127.0.0.1:9050'},
        outputs: {
          r'reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings':
              '    ProxyEnable    REG_DWORD    0x1\n    ProxyServer    REG_SZ    p:1\n',
        },
      );
      expect((await DesktopProxyCheck(windows).run(ScanOptions())).details, [
        'environment ALL_PROXY',
        'system proxy p:1',
      ]);
    });
  });

  group('debugger', () {
    test('Linux TracerPid', () {
      expect(DesktopRules.linuxTracer('Name:\tapp\nTracerPid:\t0\n'), isEmpty);
      expect(DesktopRules.linuxTracer('TracerPid:\t4242\n'), [
        'traced by process 4242',
      ]);
    });

    test('macOS process state', () {
      expect(DesktopRules.macTraced('SX+\n'), hasLength(1));
      expect(DesktopRules.macTraced('S+\n'), isEmpty);
    });

    test('Windows asks IsDebuggerPresent and fails without it', () async {
      Future<SignalResult> on(bool? attached) => DesktopDebuggerCheck(
        _FakeDesktop(DesktopOs.windows, debugger: attached),
      ).run(ScanOptions());
      expect((await on(true)).detected, isTrue);
      expect((await on(false)).detected, isFalse);
      expect((await on(null)).failed, isTrue);
    });

    test('macOS asks ps about its own process', () async {
      final mac = _FakeDesktop(
        DesktopOs.macOS,
        outputs: {'/bin/ps -o stat= -p 42': 'SX\n'},
      );
      expect(
        (await DesktopDebuggerCheck(mac).run(ScanOptions())).detected,
        isTrue,
      );
    });
  });

  group('virtual machine', () {
    test('hypervisor names in hardware descriptions', () {
      expect(DesktopRules.virtualMachine(['innotek GmbH\n', 'VirtualBox\n']), [
        'virtual machine (VirtualBox)',
      ]);
      expect(
        DesktopRules.virtualMachine([
          'Microsoft Corporation',
          'Virtual Machine',
        ]),
        ['virtual machine (Hyper-V)'],
      );
      expect(
        DesktopRules.virtualMachine(['Dell Inc.', 'XPS 13', null]),
        isEmpty,
      );
      expect(DesktopRules.macHypervisor('1\n'), hasLength(1));
      expect(DesktopRules.macHypervisor('0\n'), isEmpty);
    });

    test('Linux reads DMI and reports under emulator', () async {
      final linux = _FakeDesktop(
        DesktopOs.linux,
        files: {'/sys/class/dmi/id/sys_vendor': 'QEMU\n'},
      );
      final check = DesktopVirtualMachineCheck(linux);
      expect(check.signal, AntiVirtualSignal.emulator);
      expect((await check.run(ScanOptions())).details, [
        'virtual machine (QEMU)',
      ]);
    });
  });

  group('FlutterAntiVirtualsDesktop', () {
    late FlutterAntiVirtualsPlatform original;
    setUp(() => original = FlutterAntiVirtualsPlatform.instance);
    tearDown(() => FlutterAntiVirtualsPlatform.instance = original);

    test('registerWith installs it', () {
      FlutterAntiVirtualsDesktop.registerWith();
      expect(
        FlutterAntiVirtualsPlatform.instance,
        isA<FlutterAntiVirtualsDesktop>(),
      );
    });

    test('scans with its checks and leaves the rest unsupported', () async {
      FlutterAntiVirtualsPlatform.instance = FlutterAntiVirtualsDesktop(
        system: _FakeDesktop(
          DesktopOs.linux,
          adapters: const [NetworkAdapter('wg0')],
          files: {'/proc/self/status': 'TracerPid:\t0\n'},
        ),
      );
      final report = await FlutterAntiVirtuals.instance.scan();
      expect(report.detected, {AntiVirtualSignal.vpn});
      expect(report[AntiVirtualSignal.debugger]!.supported, isTrue);
      expect(report[AntiVirtualSignal.rooted]!.supported, isFalse);
      expect(report.failed, isEmpty);
    });

    test('the real system answers without failures', () async {
      final report = await FlutterAntiVirtualsDesktop().scan(ScanOptions());
      expect(report.failed, isEmpty);
      for (final signal in [
        AntiVirtualSignal.vpn,
        AntiVirtualSignal.proxy,
        AntiVirtualSignal.emulator,
      ]) {
        expect(report[signal]!.supported, isTrue, reason: signal.name);
      }
    }, testOn: 'linux || mac-os');
  });
}
