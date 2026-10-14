import 'dart:async';
import 'dart:ffi';
import 'dart:io' as io;

import 'desktop_environment.dart';

/// [DesktopEnvironment] backed by `dart:io` and, on Windows, `kernel32`.
final class IoDesktopEnvironment implements DesktopEnvironment {
  IoDesktopEnvironment({this.timeout = const Duration(seconds: 3)});

  /// How long a system tool may take before its answer is dropped.
  final Duration timeout;

  @override
  DesktopOs get os => io.Platform.isMacOS
      ? DesktopOs.macOS
      : io.Platform.isWindows
      ? DesktopOs.windows
      : DesktopOs.linux;

  @override
  Map<String, String> get variables => io.Platform.environment;

  @override
  int get pid => io.pid;

  @override
  Future<List<NetworkAdapter>> networkAdapters() async => [
    for (final adapter in await io.NetworkInterface.list())
      NetworkAdapter(
        adapter.name,
        addresses: [for (final address in adapter.addresses) address.address],
      ),
  ];

  @override
  Future<String?> run(String executable, List<String> arguments) async {
    try {
      final result = await io.Process.run(
        executable,
        arguments,
      ).timeout(timeout);
      return result.exitCode == 0 ? '${result.stdout}' : null;
    } on Object {
      return null;
    }
  }

  @override
  Future<String?> readFile(String path) async {
    try {
      return await io.File(path).readAsString();
    } on Object {
      return null;
    }
  }

  @override
  bool? nativeDebuggerPresent() {
    if (!io.Platform.isWindows) return null;
    try {
      final isDebuggerPresent = DynamicLibrary.open(
        'kernel32.dll',
      ).lookupFunction<Int32 Function(), int Function()>('IsDebuggerPresent');
      return isDebuggerPresent() != 0;
    } on Object {
      return null;
    }
  }
}
