import AVFoundation
import CFNetwork
import CoreLocation
import Flutter
import Foundation
import MachO
import Network
import UIKit

public class FlutterAntiVirtualsPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private let worker = DispatchQueue(label: "dev.shewa.flutter_anti_virtuals")
  private var channel: FlutterMethodChannel?
  private var changes: FlutterEventChannel?
  private var monitor: NWPathMonitor?
  // Bumped on every listen and cancel, so updates queued by an old monitor are ignored.
  private var generation = 0

  public static func register(with registrar: FlutterPluginRegistrar) {
    let instance = FlutterAntiVirtualsPlugin()
    let channel = FlutterMethodChannel(
      name: "flutter_anti_virtuals", binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(instance, channel: channel)
    let changes = FlutterEventChannel(
      name: "flutter_anti_virtuals/changes", binaryMessenger: registrar.messenger())
    changes.setStreamHandler(instance)
    instance.channel = channel
    instance.changes = changes
    // Published so that detachFromEngine is called.
    registrar.publish(instance)
  }

  public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
    _ = onCancel(withArguments: nil)
    changes?.setStreamHandler(nil)
    channel?.setMethodCallHandler(nil)
    changes = nil
    channel = nil
  }

  // Emits on every path update after the first one (which only describes the current
  // state). The key is not narrowed to the interface list: whether every kind of VPN shows
  // up there is not guaranteed, and Dart debounces the events anyway. A changed system
  // proxy does not produce a path update; it is caught on the next scan.
  public func onListen(
    withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink
  ) -> FlutterError? {
    _ = onCancel(withArguments: nil)
    let current = generation
    let monitor = NWPathMonitor()
    var first = true
    monitor.pathUpdateHandler = { [weak self] _ in
      // Runs on the monitor's queue, so `first` is only touched here.
      if first {
        first = false
        return
      }
      DispatchQueue.main.async {
        guard let self = self, self.generation == current else { return }
        events("network")
      }
    }
    monitor.start(queue: DispatchQueue(label: "dev.shewa.flutter_anti_virtuals.path"))
    self.monitor = monitor
    return nil
  }

  public func onCancel(withArguments arguments: Any?) -> FlutterError? {
    generation += 1
    monitor?.pathUpdateHandler = nil
    monitor?.cancel()
    monitor = nil
    return nil
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard call.method == "scan" else {
      result(FlutterMethodNotImplemented)
      return
    }
    let args = call.arguments as? [String: Any]
    let wanted = (args?["signals"] as? [String]).map(Set.init)
    let skewMs = (args?["maxClockSkewMs"] as? NSNumber)?.int64Value ?? 300_000
    let trustedMs = (args?["trustedTimeMs"] as? NSNumber)?.int64Value
    worker.async {
      let scanner = AntiVirtualScanner()
      let report = scanner.scan(wanted: wanted, maxSkewMs: skewMs, trustedMs: trustedMs)
      DispatchQueue.main.async { result(report) }
    }
  }
}

struct Detection {
  var detected: Bool
  var supported = true
  var details: [String] = []

  static let unsupported = Detection(detected: false, supported: false)
  static func of(_ details: [String]) -> Detection {
    Detection(detected: !details.isEmpty, details: details)
  }
  var map: [String: Any] {
    ["detected": detected, "supported": supported, "details": details]
  }
}

final class AntiVirtualScanner {
  private static let allSignals = [
    "vpn", "proxy", "mockLocation", "virtualCamera", "developerOptions", "adb",
    "clockTampering", "untrustedInstaller", "signatureMismatch", "accessibilityAbuse",
    "remoteControlApp", "clonedApp", "userCertificates", "sideloaded", "emulator", "rooted",
  ]

  func scan(wanted: Set<String>?, maxSkewMs: Int64, trustedMs: Int64?) -> [String: Any] {
    var out: [String: Any] = [:]
    for signal in Self.allSignals where wanted == nil || wanted!.contains(signal) {
      switch signal {
      case "vpn": out[signal] = vpn().map
      case "proxy": out[signal] = proxy().map
      case "mockLocation": out[signal] = mockLocation().map
      case "virtualCamera": out[signal] = virtualCamera().map
      case "clockTampering":
        out[signal] = clock(maxSkewMs: maxSkewMs, trustedMs: trustedMs).map
      case "sideloaded": out[signal] = sideloaded().map
      case "emulator": out[signal] = emulator().map
      case "rooted": out[signal] = jailbroken().map
      default: out[signal] = Detection.unsupported.map  // Android-only concepts.
      }
    }
    return out
  }

  private func vpn() -> Detection {
    // Only interfaces listed under `__SCOPED__` count. The system's own tunnels
    // (Wi-Fi Calling / VoLTE `ipsec*`, Private Relay and Continuity `utun*`) are up
    // without a scoped network configuration, so they are not listed there, while a
    // connected VPN is: NetworkExtension VPNs as `utun*`, built-in IKEv2 as `ipsec*`.
    // Scanning every interface with getifaddrs would flag those system tunnels.
    var details: [String] = []
    if let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
      let scoped = settings["__SCOPED__"] as? [String: Any]
    {
      for key in scoped.keys where ["tap", "tun", "utun", "ppp", "ipsec"].contains(where: key.hasPrefix) {
        details.append("interface \(key)")
      }
    }
    return .of(details.sorted())
  }

  private func proxy() -> Detection {
    guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
    else { return .of([]) }
    var details: [String] = []
    if (settings["HTTPEnable"] as? Int) == 1 {
      details.append("HTTP proxy \(settings["HTTPProxy"] ?? ""):\(settings["HTTPPort"] ?? "")")
    }
    if (settings["HTTPSEnable"] as? Int) == 1 {
      details.append("HTTPS proxy \(settings["HTTPSProxy"] ?? ""):\(settings["HTTPSPort"] ?? "")")
    }
    if (settings["ProxyAutoConfigEnable"] as? Int) == 1 {
      details.append("PAC \(settings["ProxyAutoConfigURLString"] ?? "")")
    }
    return .of(details)
  }

  private func mockLocation() -> Detection {
    // CLLocationManager needs a thread with a run loop; use the main thread so the
    // cached `location` is populated. The scan runs on a worker queue, so this
    // cannot deadlock.
    if Thread.isMainThread { return mockLocationOnMain() }
    return DispatchQueue.main.sync { mockLocationOnMain() }
  }

  private func mockLocationOnMain() -> Detection {
    #if targetEnvironment(simulator)
      return .unsupported
    #else
      guard #available(iOS 15.0, *) else { return .unsupported }
      var details: [String] = []
      let manager = CLLocationManager()
      let status = manager.authorizationStatus
      guard status == .authorizedAlways || status == .authorizedWhenInUse else {
        return Detection(detected: false, supported: false, details: ["location not authorised"])
      }
      if let info = manager.location?.sourceInformation {
        if info.isSimulatedBySoftware { details.append("location simulated by software") }
        if info.isProducedByAccessory { details.append("location produced by accessory") }
      }
      return .of(details)
    #endif
  }

  private func virtualCamera() -> Detection {
    guard #available(iOS 17.0, *) else { return .unsupported }
    let session = AVCaptureDevice.DiscoverySession(
      deviceTypes: [.external], mediaType: .video, position: .unspecified)
    return .of(session.devices.map { "external camera \($0.localizedName)" })
  }

  private func clock(maxSkewMs: Int64, trustedMs: Int64?) -> Detection {
    guard let trustedMs else { return .unsupported }
    let deviceMs = Int64(Date().timeIntervalSince1970 * 1000)
    let skew = abs(deviceMs - trustedMs)
    return skew > maxSkewMs ? .of(["clock differs from trusted time by \(skew)ms"]) : .of([])
  }

  private func emulator() -> Detection {
    var details: [String] = []
    #if targetEnvironment(simulator)
      details.append("built for the iOS Simulator")
    #endif
    // Set by the Simulator runtime; a device build launched there would still carry them.
    let env = ProcessInfo.processInfo.environment
    for key in ["SIMULATOR_DEVICE_NAME", "SIMULATOR_MODEL_IDENTIFIER", "SIMULATOR_UDID"]
    where env[key] != nil {
      details.append("environment \(key)")
    }
    // Devices report a model such as "iPhone15,2"; the Simulator reports the host CPU.
    // iPad apps running on Apple silicon Macs are excluded: they are not simulated.
    var isAppOnMac = false
    if #available(iOS 14.0, *) { isAppOnMac = ProcessInfo.processInfo.isiOSAppOnMac }
    if !isAppOnMac {
      var info = utsname()
      uname(&info)
      let machine = withUnsafeBytes(of: &info.machine) { raw in
        String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
      }
      if ["x86_64", "i386", "arm64"].contains(machine) {
        details.append("simulator hardware \(machine)")
      }
    }
    return .of(details)
  }

  // Files and directories that exist only on a jailbroken device. Each one is enough on its
  // own: stock iOS has none of them. Rootless jailbreaks (Dopamine, palera1n) use /var/jb and
  // /var/binpack.
  private static let jailbreakPaths = [
    "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
    "/Applications/Installer.app", "/Applications/Filza.app", "/Applications/Icy.app",
    "/Applications/SBSettings.app", "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate/DynamicLibraries",
    "/Library/PreferenceLoader", "/usr/lib/libjailbreak.dylib", "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate", "/usr/lib/TweakInject", "/usr/libexec/cydia",
    "/usr/libexec/sftp-server", "/usr/sbin/sshd", "/usr/bin/ssh", "/bin/bash",
    "/usr/bin/cycript", "/usr/local/bin/cycript", "/etc/apt", "/private/var/lib/apt",
    "/private/var/lib/cydia", "/private/var/stash", "/private/var/tmp/cydia.log",
    "/var/jb", "/private/var/jb", "/var/binpack", "/private/var/binpack",
    "/.bootstrapped_electra", "/.installed_unc0ver",
  ]

  // Libraries a jailbreak injects into apps. Frida and other hooking tools are not listed.
  private static let jailbreakImages = [
    "mobilesubstrate", "libsubstrate", "libsubstitute", "libhooker", "ellekit", "tweakinject",
    "tweakloader", "libjailbreak",
  ]

  private func jailbroken() -> Detection {
    #if targetEnvironment(simulator)
      // Not a jailbreak; the `emulator` signal reports the Simulator.
      return .of([])
    #else
      var details: [String] = []
      let fm = FileManager.default
      for path in Self.jailbreakPaths where fm.fileExists(atPath: path) {
        details.append("jailbreak file \(path)")
      }
      // The sandbox does not let an app write outside its container.
      let probe = "/private/anti_virtuals_\(UUID().uuidString)"
      if (try? "x".write(toFile: probe, atomically: true, encoding: .utf8)) != nil {
        details.append("wrote outside the sandbox")
        try? fm.removeItem(atPath: probe)
      }
      // Very old jailbreaks moved system directories and left symbolic links behind.
      if (try? fm.destinationOfSymbolicLink(atPath: "/Applications")) != nil {
        details.append("/Applications is a symbolic link")
      }
      if let value = getenv("DYLD_INSERT_LIBRARIES"), strlen(value) > 0 {
        details.append("DYLD_INSERT_LIBRARIES is set")
      }
      for index in 0..<_dyld_image_count() {
        guard let raw = _dyld_get_image_name(index) else { continue }
        let image = String(cString: raw).lowercased()
        if let token = Self.jailbreakImages.first(where: { image.contains($0) }) {
          details.append("jailbreak library \(token)")
        }
      }
      return .of(Array(Set(details)).sorted())
    #endif
  }

  private func sideloaded() -> Detection {
    #if targetEnvironment(simulator)
      return .unsupported
    #else
      // App Store builds carry no embedded provisioning profile; development,
      // ad-hoc and enterprise (sideloaded) builds do.
      if Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") != nil {
        return .of(["embedded provisioning profile present (not an App Store build)"])
      }
      return .of([])
    #endif
  }
}
