import 'desktop_environment.dart';

/// Pure decision logic of the desktop checks, kept free of `dart:io` so it
/// can be unit tested with captured system output.
abstract final class DesktopRules {
  static const _unixTunnels = [
    'tun', 'tap', 'wg', 'ppp', 'ipsec', 'vti', 'nordlynx', 'tailscale', //
    'proton', 'zt',
  ];

  // macOS keeps its own `utun` tunnels up (iCloud, Continuity), but they only
  // carry link-local addresses, which the adapters list leaves out.
  static const _macTunnels = ['utun', 'ipsec', 'ppp', 'tun', 'tap'];

  // Windows interfaces carry the names their drivers or users gave them.
  static const _windowsTunnels = [
    'vpn', 'tap-windows', 'wireguard', 'wintun', 'openvpn', 'nordlynx', //
    'proton', 'anyconnect', 'fortinet', 'forticlient', 'globalprotect',
    'pangp', 'zerotier', 'tailscale',
  ];

  static List<String> vpnInterfaces(
    DesktopOs os,
    List<NetworkAdapter> adapters,
  ) => [
    for (final adapter in adapters)
      if (_isTunnel(os, adapter.name.toLowerCase()))
        'interface ${adapter.name}',
  ];

  static bool _isTunnel(DesktopOs os, String name) => switch (os) {
    DesktopOs.linux => _unixTunnels.any(name.startsWith),
    DesktopOs.macOS => _macTunnels.any(name.startsWith),
    DesktopOs.windows =>
      name.startsWith('wg') || _windowsTunnels.any(name.contains),
  };

  /// Connected services in `scutil --nc list` (macOS VPN configurations,
  /// including Network Extension VPN apps).
  static List<String> macVpnServices(String? scutilList) => [
    for (final line in _lines(scutilList))
      if (line.contains('(Connected)'))
        'VPN service ${RegExp(r'"([^"]*)"').firstMatch(line)?.group(1) ?? 'unnamed'} connected',
  ];

  static const _proxyVariables = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'];

  static List<String> proxyVariables(Map<String, String> variables) => [
    for (final MapEntry(:key, :value) in variables.entries)
      if (_proxyVariables.contains(key.toUpperCase()) &&
          value.trim().isNotEmpty)
        'environment $key',
  ];

  /// `scutil --proxy` on macOS.
  static List<String> macProxy(String? scutilProxy) {
    final values = <String, String>{};
    for (final line in _lines(scutilProxy)) {
      final match = RegExp(r'^\s*(\w+)\s*:\s*(.+?)\s*$').firstMatch(line);
      if (match != null) {
        values.putIfAbsent(match.group(1)!, () => match.group(2)!);
      }
    }
    String server(String kind) =>
        '${values['${kind}Proxy'] ?? ''}:${values['${kind}Port'] ?? ''}';
    return [
      if (values['HTTPEnable'] == '1') 'HTTP proxy ${server('HTTP')}',
      if (values['HTTPSEnable'] == '1') 'HTTPS proxy ${server('HTTPS')}',
      if (values['SOCKSEnable'] == '1') 'SOCKS proxy ${server('SOCKS')}',
      if (values['ProxyAutoConfigEnable'] == '1')
        'PAC ${values['ProxyAutoConfigURLString'] ?? ''}',
    ];
  }

  /// `reg query` of the current user's Internet Settings on Windows.
  static List<String> windowsProxy(String? registry) {
    final values = <String, String>{};
    for (final line in _lines(registry)) {
      final match = RegExp(r'^\s*(\w+)\s+REG_\w+\s+(.*?)\s*$').firstMatch(line);
      if (match != null) values[match.group(1)!] = match.group(2)!;
    }
    final enabled = int.tryParse(
      (values['ProxyEnable'] ?? '0').replaceFirst('0x', ''),
      radix: 16,
    );
    return [
      if (enabled != null && enabled != 0)
        'system proxy ${values['ProxyServer'] ?? ''}',
      if ((values['AutoConfigURL'] ?? '').isNotEmpty)
        'PAC ${values['AutoConfigURL']}',
    ];
  }

  /// `gsettings get org.gnome.system.proxy mode` on Linux.
  static List<String> gnomeProxy(String? mode) =>
      switch (mode?.trim().replaceAll("'", '')) {
        'manual' => ['system proxy (GNOME, manual)'],
        'auto' => ['system proxy (GNOME, automatic configuration)'],
        _ => const [],
      };

  /// `/proc/self/status` on Linux.
  static List<String> linuxTracer(String? status) {
    final pid = RegExp(
      r'^TracerPid:\s*(\d+)',
      multiLine: true,
    ).firstMatch(status ?? '')?.group(1);
    return pid == null || pid == '0' ? const [] : ['traced by process $pid'];
  }

  /// `ps -o stat= -p <pid>` on macOS; `X` marks a traced process.
  static List<String> macTraced(String? state) => (state ?? '').contains('X')
      ? const ['process is being traced']
      : const [];

  static const _hypervisors = {
    'vmware': 'VMware',
    'virtualbox': 'VirtualBox',
    'innotek': 'VirtualBox',
    'qemu': 'QEMU',
    'kvm': 'KVM',
    'bochs': 'Bochs',
    'parallels': 'Parallels',
    'xen': 'Xen',
    'bhyve': 'bhyve',
    'virtual machine': 'Hyper-V',
    'virtualmac': 'Apple Virtualization',
  };

  /// Hardware descriptions (DMI on Linux, the BIOS registry key on Windows,
  /// `hw.model` on macOS) that name a hypervisor.
  static List<String> virtualMachine(Iterable<String?> descriptions) {
    final text = descriptions.whereType<String>().join(' ').toLowerCase();
    return {
      for (final MapEntry(:key, :value) in _hypervisors.entries)
        if (text.contains(key)) 'virtual machine ($value)',
    }.toList();
  }

  /// `sysctl -n kern.hv_vmm_present` on macOS.
  static List<String> macHypervisor(String? present) =>
      present?.trim() == '1' ? const ['running under a hypervisor'] : const [];

  static Iterable<String> _lines(String? text) =>
      (text ?? '').split(RegExp(r'\r?\n'));
}
