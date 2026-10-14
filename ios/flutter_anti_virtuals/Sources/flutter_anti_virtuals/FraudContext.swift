import Foundation
import LocalAuthentication

/// Whether a phone or VoIP call is in progress, from CallKit's call observer. CallKit is loaded
/// at run time instead of linked, because apps distributed in mainland China must not link it.
enum CallState {
  private static let observerType: NSObject.Type? = {
    _ = dlopen("/System/Library/Frameworks/CallKit.framework/CallKit", RTLD_LAZY)
    return NSClassFromString("CXCallObserver") as? NSObject.Type
  }()

  /// Main thread only.
  static func detection() -> Detection {
    guard let type = observerType else { return .unsupported }
    let calls = type.init().value(forKey: "calls") as? [NSObject] ?? []
    let active = calls.filter {
      ($0.value(forKey: "hasConnected") as? Bool) == true
        && ($0.value(forKey: "hasEnded") as? Bool) == false
    }
    return .of(active.isEmpty ? [] : ["call in progress"])
  }
}

/// Whether the device has a passcode. Without one, anybody holding the phone gets into the app's
/// data and any session that is still signed in.
enum ScreenLock {
  static func detection() -> Detection {
    var error: NSError?
    if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) { return .of([]) }
    if error?.code == LAError.Code.passcodeNotSet.rawValue { return .of(["no passcode is set"]) }
    return .failed(error?.localizedDescription ?? "could not read the passcode state")
  }
}

/// How the app's data relates to this device. See `DeviceBinding`.
enum BindingState: Equatable {
  case unbound, bound, migrated

  /// `dataId` is the id kept in the app's data; `deviceId` the one this device keeps.
  static func of(dataId: String?, deviceId: String?) -> BindingState {
    guard let dataId else { return .unbound }
    return dataId == deviceId ? .bound : .migrated
  }
}

/// Notices app data that was created on another device: restored from an iCloud or computer
/// backup onto a new phone, moved with Quick Start, or copied off a jailbroken phone. A random
/// id is kept twice, in `UserDefaults`, which backups and transfers carry, and in a Keychain item
/// that stays on this device. Data whose id this device does not hold came from somewhere else.
///
/// Called from the plugin's worker queue only, so checks and rebinds never interleave.
enum DeviceBinding {
  private static let defaultsKey = "dev.shewa.flutter_anti_virtuals.bindingId"
  private static let item = KeychainItem(account: "dev.shewa.flutter_anti_virtuals.binding")

  static func detection() -> Detection {
    let dataId = UserDefaults.standard.string(forKey: defaultsKey)
    let deviceId: String?
    switch item.load() {
    case .success(let stored): deviceId = stored
    case .failure(let error): return .failed(error.message)
    }
    switch BindingState.of(dataId: dataId, deviceId: deviceId) {
    case .unbound: return rebind() ? .of([]) : .failed("could not save the device binding")
    case .bound: return .of([])
    case .migrated:
      return .of(["app data was created on another device or restored from a backup"])
    }
  }

  /// Accepts the current data on this device by binding it to a new id.
  @discardableResult
  static func rebind() -> Bool {
    let id = UUID().uuidString
    guard item.save(id) else { return false }
    UserDefaults.standard.set(id, forKey: defaultsKey)
    return true
  }
}
