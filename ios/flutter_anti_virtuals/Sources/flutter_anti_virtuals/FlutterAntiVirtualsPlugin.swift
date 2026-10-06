import AVFoundation
import CFNetwork
import CoreLocation
import Flutter
import Foundation
import UIKit

public class FlutterAntiVirtualsPlugin: NSObject, FlutterPlugin {
  private let worker = DispatchQueue(label: "dev.shewa.flutter_anti_virtuals")

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "flutter_anti_virtuals", binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(FlutterAntiVirtualsPlugin(), channel: channel)
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
    "remoteControlApp", "clonedApp", "userCertificates", "sideloaded",
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
      default: out[signal] = Detection.unsupported.map  // Android-only concepts.
      }
    }
    return out
  }

  private func vpn() -> Detection {
    // Only `tap`, `tun` and `ppp` scoped interfaces count. `ipsec*` is kept up by
    // Wi-Fi Calling / VoLTE and `utun3+` by Private Relay and Continuity, so those
    // would flag ordinary iPhones. VPNs that only use utun are therefore not seen.
    var details: [String] = []
    if let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
      let scoped = settings["__SCOPED__"] as? [String: Any]
    {
      for key in scoped.keys where ["tap", "tun", "ppp"].contains(where: key.hasPrefix) {
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
