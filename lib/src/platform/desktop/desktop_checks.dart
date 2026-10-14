import '../../scan_options.dart';
import '../../signal.dart';
import '../checks/signal_check.dart';
import 'desktop_environment.dart';
import 'desktop_rules.dart';

/// A tunnel interface is up, or (macOS) a VPN service is connected.
final class DesktopVpnCheck implements SignalCheck {
  const DesktopVpnCheck(this._system);

  final DesktopEnvironment _system;

  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.vpn;

  @override
  Future<SignalResult> run(ScanOptions options) async {
    final adapters = await _system.networkAdapters();
    return resultOf([
      ...DesktopRules.vpnInterfaces(_system.os, adapters),
      if (_system.os == DesktopOs.macOS)
        ...DesktopRules.macVpnServices(
          await _system.run('/usr/sbin/scutil', ['--nc', 'list']),
        ),
    ]);
  }
}

/// A system proxy or PAC file is set, or the process inherited proxy
/// environment variables.
final class DesktopProxyCheck implements SignalCheck {
  const DesktopProxyCheck(this._system);

  final DesktopEnvironment _system;

  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.proxy;

  @override
  Future<SignalResult> run(ScanOptions options) async => resultOf([
    ...DesktopRules.proxyVariables(_system.variables),
    ...switch (_system.os) {
      DesktopOs.macOS => DesktopRules.macProxy(
        await _system.run('/usr/sbin/scutil', ['--proxy']),
      ),
      DesktopOs.windows => DesktopRules.windowsProxy(
        await _system.run('reg', [
          'query',
          r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
        ]),
      ),
      DesktopOs.linux => DesktopRules.gnomeProxy(
        await _system.run('gsettings', [
          'get',
          'org.gnome.system.proxy',
          'mode',
        ]),
      ),
    },
  ]);
}

/// A native debugger is attached to the app's process.
final class DesktopDebuggerCheck implements SignalCheck {
  const DesktopDebuggerCheck(this._system);

  final DesktopEnvironment _system;

  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.debugger;

  @override
  Future<SignalResult> run(ScanOptions options) async => switch (_system.os) {
    DesktopOs.linux => resultOf(
      DesktopRules.linuxTracer(await _system.readFile('/proc/self/status')),
    ),
    DesktopOs.macOS => resultOf(
      DesktopRules.macTraced(
        await _system.run('/bin/ps', ['-o', 'stat=', '-p', '${_system.pid}']),
      ),
    ),
    DesktopOs.windows => switch (_system.nativeDebuggerPresent()) {
      null => const SignalResult.failed('IsDebuggerPresent is unavailable'),
      final attached => resultOf([if (attached) 'debugger attached']),
    },
  };
}

/// The app runs in a virtual machine: the desktop counterpart of an Android
/// emulator or the iOS Simulator.
final class DesktopVirtualMachineCheck implements SignalCheck {
  const DesktopVirtualMachineCheck(this._system);

  final DesktopEnvironment _system;

  @override
  AntiVirtualSignal get signal => AntiVirtualSignal.emulator;

  @override
  Future<SignalResult> run(ScanOptions options) async => switch (_system.os) {
    DesktopOs.linux => resultOf(
      DesktopRules.virtualMachine([
        for (final field in ['sys_vendor', 'product_name', 'board_vendor'])
          await _system.readFile('/sys/class/dmi/id/$field'),
      ]),
    ),
    DesktopOs.windows => resultOf(
      DesktopRules.virtualMachine([
        await _system.run('reg', [
          'query',
          r'HKLM\HARDWARE\DESCRIPTION\System\BIOS',
        ]),
      ]),
    ),
    DesktopOs.macOS => resultOf([
      ...DesktopRules.macHypervisor(
        await _system.run('/usr/sbin/sysctl', ['-n', 'kern.hv_vmm_present']),
      ),
      ...DesktopRules.virtualMachine([
        await _system.run('/usr/sbin/sysctl', ['-n', 'hw.model']),
      ]),
    ]),
  };
}

/// Every desktop check, for [system].
List<SignalCheck> desktopChecks(DesktopEnvironment system) => [
  DesktopVpnCheck(system),
  DesktopProxyCheck(system),
  DesktopDebuggerCheck(system),
  DesktopVirtualMachineCheck(system),
];
