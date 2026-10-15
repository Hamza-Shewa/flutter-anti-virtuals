import Foundation
import Security

/// One generic-password item of the plugin in the Keychain, readable only on this device. Such
/// items are not carried to another device by a backup, a restore or Quick Start, which is what
/// the device binding and the App Attest key id rely on.
struct KeychainItem {
  static let service = "dev.shewa.flutter_anti_virtuals"

  let account: String

  private var query: [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: account,
    ]
  }

  /// The stored text, nil when there is none, or the Keychain status when it could not be read
  /// (for example before the first unlock after a restart).
  func load() -> Result<String?, KeychainError> {
    var lookup = query
    lookup[kSecReturnData as String] = true
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(lookup as CFDictionary, &item)
    if status == errSecItemNotFound { return .success(nil) }
    guard status == errSecSuccess, let data = item as? Data else {
      return .failure(KeychainError(status: status))
    }
    return .success(String(data: data, encoding: .utf8))
  }

  @discardableResult
  func save(_ value: String) -> Bool {
    SecItemDelete(query as CFDictionary)
    var item = query
    item[kSecValueData as String] = Data(value.utf8)
    item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
  }

  func delete() {
    SecItemDelete(query as CFDictionary)
  }

  /// The access group the item lives in, creating the item when needed. Apps get a default
  /// access group named after their App ID prefix (the team ID), so this tells which team
  /// signed the running app.
  func accessGroup() -> Result<String, KeychainError> {
    var lookup = query
    lookup[kSecReturnAttributes as String] = true
    var item: CFTypeRef?
    var status = SecItemCopyMatching(lookup as CFDictionary, &item)
    if status == errSecItemNotFound {
      var add = lookup
      add[kSecValueData as String] = Data()
      add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      status = SecItemAdd(add as CFDictionary, &item)
    }
    guard status == errSecSuccess, let attributes = item as? [String: Any],
      let group = attributes[kSecAttrAccessGroup as String] as? String
    else { return .failure(KeychainError(status: status)) }
    return .success(group)
  }
}

struct KeychainError: Error {
  let status: OSStatus

  var message: String { "Keychain error \(status)" }
}
