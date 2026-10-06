import AVFoundation
import CFNetwork
import CoreLocation
import Flutter
import Foundation
import MachO
import Network
import Security
import UIKit

public class FlutterAntiVirtualsPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private let worker = DispatchQueue(label: "dev.shewa.flutter_anti_virtuals")
  private var channel: FlutterMethodChannel?
  private var changes: FlutterEventChannel?
  private var monitor: NWPathMonitor?
  private var captureObservers: [NSObjectProtocol] = []
  private var protectionObservers: [NSObjectProtocol] = []
  private var privacyView: UIView?
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
    setPrivacyCover(enabled: false)
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
    // Recording, mirroring and a cable or AirPlay display are as relevant as a VPN.
    let center = NotificationCenter.default
    for name in [
      UIScreen.capturedDidChangeNotification, UIScreen.didConnectNotification,
      UIScreen.didDisconnectNotification,
    ] {
      captureObservers.append(
        center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
          guard let self = self, self.generation == current else { return }
          events("capture")
        })
    }
    return nil
  }

  public func onCancel(withArguments arguments: Any?) -> FlutterError? {
    generation += 1
    monitor?.pathUpdateHandler = nil
    monitor?.cancel()
    monitor = nil
    captureObservers.forEach { NotificationCenter.default.removeObserver($0) }
    captureObservers = []
    return nil
  }

  // Apple has no way to block screenshots or recordings. What an app can do is cover its
  // content: while the screen is recorded or mirrored, and when the app goes to the app
  // switcher (the snapshot taken there shows whatever is on screen).
  private func setPrivacyCover(enabled: Bool) {
    protectionObservers.forEach { NotificationCenter.default.removeObserver($0) }
    protectionObservers = []
    showPrivacyView(false)
    guard enabled else { return }
    let center = NotificationCenter.default
    protectionObservers = [
      center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) {
        [weak self] _ in self?.showPrivacyView(true)
      },
      center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) {
        [weak self] _ in self?.showPrivacyView(UIScreen.main.isCaptured)
      },
      center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) {
        [weak self] _ in self?.showPrivacyView(UIScreen.main.isCaptured)
      },
    ]
    showPrivacyView(UIScreen.main.isCaptured)
  }

  private func showPrivacyView(_ visible: Bool) {
    guard visible else {
      privacyView?.removeFromSuperview()
      privacyView = nil
      return
    }
    guard privacyView == nil else { return }
    let window = UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .flatMap { $0.windows }
      .first { $0.isKeyWindow }
    guard let window = window else { return }
    let cover = UIVisualEffectView(effect: UIBlurEffect(style: .systemThickMaterial))
    cover.frame = window.bounds
    cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    window.addSubview(cover)
    privacyView = cover
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    if call.method == "setScreenProtection" {
      let secure = (call.arguments as? [String: Any])?["secureWindow"] as? Bool ?? false
      DispatchQueue.main.async {
        self.setPrivacyCover(enabled: secure)
        result(true)
      }
      return
    }
    if call.method == "signPayload" {
      guard let args = call.arguments as? [String: Any], let payload = args["payload"] as? String
      else {
        result(FlutterError(code: "bad_arguments", message: "nonce and payload are required", details: nil))
        return
      }
      worker.async {
        let signed = DeviceKey.sign(Data(payload.utf8))
        DispatchQueue.main.async {
          switch signed {
          case .success(let map): result(map)
          case .failure(let error):
            result(FlutterError(code: "sign_failed", message: error.message, details: nil))
          }
        }
      }
      return
    }
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
    "remoteControlApp", "clonedApp", "userCertificates", "sideloaded", "emulator", "rooted", "hooked", "debugger", "screenCapture",
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
      case "hooked": out[signal] = hooked().map
      case "debugger": out[signal] = debugger().map
      case "screenCapture": out[signal] = screenCapture().map
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

  // Instrumentation frameworks loaded into the app. Substrate-style libraries are listed here
  // and under `rooted`, because a jailbreak injects them and a hooking tool uses them.
  private static let hookImages = [
    "frida", "fridagadget", "cynject", "libcycript", "cycript", "mobilesubstrate", "libsubstrate",
    "libsubstitute", "libhooker", "ellekit", "sslkillswitch",
  ]
  private static let hookClasses = [
    "FridaGadget", "FridaScriptEngine", "CydiaSubstrate", "SubstrateLoader", "SubstrateBootstrap",
    "CaptainHook", "CYListenServer",
  ]
  private static let fridaPort: UInt16 = 27042

  private func hooked() -> Detection {
    var details: [String] = []
    for index in 0..<_dyld_image_count() {
      guard let raw = _dyld_get_image_name(index) else { continue }
      let image = String(cString: raw).lowercased()
      if let token = Self.hookImages.first(where: { image.contains($0) }) {
        details.append("hooking library \(token) loaded")
      }
    }
    for name in Self.hookClasses where NSClassFromString(name) != nil {
      details.append("hooking class \(name)")
    }
    if let value = getenv("DYLD_INSERT_LIBRARIES"), strlen(value) > 0 {
      details.append("DYLD_INSERT_LIBRARIES is set")
    }
    if Self.portOpen(Self.fridaPort) {
      details.append("Frida server port \(Self.fridaPort) is open")
    }
    return .of(Array(Set(details)).sorted())
  }

  // True when something accepts connections on 127.0.0.1:port. Gives up after 200 ms.
  private static func portOpen(_ port: UInt16) -> Bool {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    if fd < 0 { return false }
    defer { close(fd) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
    let result = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
      }
    }
    if result == 0 { return true }
    guard errno == EINPROGRESS else { return false }
    var poller = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
    guard poll(&poller, 1, 200) > 0 else { return false }
    var error: Int32 = 0
    var length = socklen_t(MemoryLayout<Int32>.size)
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)
    return error == 0
  }

  private func debugger() -> Detection {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    let result = name.withUnsafeMutableBufferPointer { pointer in
      sysctl(pointer.baseAddress, 4, &info, &size, nil, 0)
    }
    if result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0 {
      return .of(["process is being traced"])
    }
    return .of([])
  }

  private func screenCapture() -> Detection {
    // UIKit state is read on the main thread; the scan runs on a worker queue.
    var details: [String] = []
    let read = {
      if UIScreen.main.isCaptured { details.append("screen is being recorded or mirrored") }
      if UIScreen.screens.count > 1 { details.append("external display connected") }
    }
    if Thread.isMainThread { read() } else { DispatchQueue.main.sync(execute: read) }
    return .of(details)
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

struct DeviceKeyError: Error {
  let message: String
}

/// Signs a payload with a key created for this request. The Secure Enclave is used where it
/// exists; the Simulator falls back to a software key, reported as such. iOS has no key
/// attestation, so the signature alone does not prove the device: pair it with App Attest.
enum DeviceKey {
  static func sign(_ payload: Data) -> Result<[String: Any], DeviceKeyError> {
    var protection = "hardware"
    var key = makeKey(secureEnclave: true)
    if key == nil {
      protection = "software"
      key = makeKey(secureEnclave: false)
    }
    guard let privateKey = key, let publicKey = SecKeyCopyPublicKey(privateKey) else {
      return .failure(DeviceKeyError(message: "could not create a signing key"))
    }
    var error: Unmanaged<CFError>?
    guard
      let signature = SecKeyCreateSignature(
        privateKey, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error) as Data?,
      let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
    else {
      let reason = error?.takeRetainedValue().localizedDescription ?? "signing failed"
      return .failure(DeviceKeyError(message: reason))
    }
    return .success([
      "signature": signature.base64EncodedString(),
      "publicKey": publicData.base64EncodedString(),
      "algorithm": "SHA256withECDSA",
      "protection": protection,
      "attested": false,
      "certificateChain": [String](),
    ])
  }

  private static func makeKey(secureEnclave: Bool) -> SecKey? {
    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
    ]
    var privateAttributes: [String: Any] = [kSecAttrIsPermanent as String: false]
    if secureEnclave {
      guard
        let access = SecAccessControlCreateWithFlags(
          nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)
      else { return nil }
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
      privateAttributes[kSecAttrAccessControl as String] = access
    }
    attributes[kSecPrivateKeyAttrs as String] = privateAttributes
    return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
  }
}
