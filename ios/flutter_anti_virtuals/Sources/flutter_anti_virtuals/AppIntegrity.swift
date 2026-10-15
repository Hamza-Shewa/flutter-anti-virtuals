import DeviceCheck
import Foundation
import MachO

/// The pure part of the iOS `signatureMismatch` check.
enum AppIntegrityRules {
  /// `teamId` signed the running app; `expected` are the team IDs it may be signed by, in upper
  /// case. `encrypted` is nil when it could not be read.
  static func details(teamId: String, expected: [String], appStoreBuild: Bool, encrypted: Bool?)
    -> [String]
  {
    var details: [String] = []
    if !expected.contains(teamId.uppercased()) { details.append("signed by team \(teamId)") }
    // App Store and TestFlight builds are encrypted by Apple; a dumped copy is not.
    if appStoreBuild && encrypted == false { details.append("the app binary was decrypted") }
    return details
  }
}

/// Whether the running app is the one its developer shipped: signed by an expected team and, for
/// an App Store build, still encrypted by Apple. A re-signed or cracked copy fails one of them.
enum AppIntegrity {
  private static let probe = KeychainItem(account: "dev.shewa.flutter_anti_virtuals.teamId")

  static func detection(expectedTeamIds: [String]) -> Detection {
    guard !expectedTeamIds.isEmpty else { return .unsupported }
    let teamId: String
    switch probe.accessGroup() {
    case .success(let group): teamId = String(group.prefix(while: { $0 != "." }))
    case .failure(let error): return .failed(error.message)
    }
    #if targetEnvironment(simulator)
      let appStoreBuild = false
    #else
      // App Store and TestFlight builds carry no embedded provisioning profile.
      let appStoreBuild =
        Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") == nil
    #endif
    return .of(
      AppIntegrityRules.details(
        teamId: teamId, expected: expectedTeamIds, appStoreBuild: appStoreBuild,
        encrypted: executableEncrypted()))
  }

  /// Reads `cryptid` from the main executable's encryption load command.
  static func executableEncrypted() -> Bool? {
    for index in 0..<_dyld_image_count() {
      guard let header = _dyld_get_image_header(index),
        header.pointee.filetype == UInt32(MH_EXECUTE),
        header.pointee.magic == UInt32(MH_MAGIC_64)
      else { continue }
      var cursor = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
      for _ in 0..<header.pointee.ncmds {
        let command = cursor.load(as: load_command.self)
        if command.cmd == UInt32(LC_ENCRYPTION_INFO_64) {
          return cursor.load(as: encryption_info_command_64.self).cryptid != 0
        }
        cursor = cursor.advanced(by: Int(command.cmdsize))
      }
      return nil
    }
    return nil
  }
}

/// An Apple DeviceCheck token, which lets a backend read and set two bits Apple keeps for this
/// device.
enum DeviceCheckToken {
  static func generate(completion: @escaping (Result<String, DeviceKeyError>) -> Void) {
    let device = DCDevice.current
    guard device.isSupported else {
      completion(.failure(DeviceKeyError(message: "DeviceCheck is not supported on this device")))
      return
    }
    device.generateToken { token, error in
      guard let token else {
        completion(
          .failure(
            DeviceKeyError(
              message: error?.localizedDescription ?? "could not generate a DeviceCheck token")))
        return
      }
      completion(.success(token.base64EncodedString()))
    }
  }
}
