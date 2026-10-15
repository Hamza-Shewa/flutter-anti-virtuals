/// The desktop operating systems the Dart checks know.
enum DesktopOs { macOS, windows, linux }

/// A network interface that is up, with the addresses it has.
final class NetworkAdapter {
  const NetworkAdapter(this.name, {this.addresses = const <String>[]});

  final String name;
  final List<String> addresses;
}

/// What the desktop checks read from the system. The checks only see this
/// port, so tests give them a fake one.
abstract interface class DesktopEnvironment {
  DesktopOs get os;

  /// The process environment variables.
  Map<String, String> get variables;

  int get pid;

  /// Interfaces that are up, without loopback and link-local addresses.
  Future<List<NetworkAdapter>> networkAdapters();

  /// Runs a system tool and returns what it printed, or null when it is
  /// missing, fails or takes too long.
  Future<String?> run(String executable, List<String> arguments);

  /// The text of a file, or null when it cannot be read.
  Future<String?> readFile(String path);

  /// Windows: whether a native debugger is attached to the process. Null on
  /// other systems or when it cannot be asked.
  bool? nativeDebuggerPresent();
}
