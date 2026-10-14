import Flutter
import UIKit
import XCTest

// If your plugin has been explicitly set to "type: .dynamic" in the Package.swift,
// you will need to add your plugin as a dependency of RunnerTests within Xcode.

@testable import flutter_anti_virtuals

class RunnerTests: XCTestCase {
  private func call(_ method: String, _ arguments: Any? = nil) -> Any? {
    let plugin = FlutterAntiVirtualsPlugin()
    let done = expectation(description: "\(method) answers")
    var answer: Any?
    plugin.handle(FlutterMethodCall(methodName: method, arguments: arguments)) { result in
      answer = result
      done.fulfill()
    }
    waitForExpectations(timeout: 5)
    return answer
  }

  func testScanAnswersExactlyTheRequestedSignals() {
    let report = call("scan", ["signals": ["vpn", "adb"]]) as? [String: Any]
    XCTAssertEqual(Set(report?.keys.map { $0 } ?? []), Set(["vpn", "adb"]))
    let vpn = report?["vpn"] as? [String: Any]
    XCTAssertEqual(vpn?["supported"] as? Bool, true)
    XCTAssertNotNil(vpn?["detected"] as? Bool)
  }

  func testAndroidOnlySignalsAreUnsupported() {
    let report =
      call("scan", ["signals": ["adb", "signatureMismatch", "automation"]]) as? [String: Any]
    for key in ["adb", "signatureMismatch", "automation"] {
      let result = report?[key] as? [String: Any]
      XCTAssertEqual(result?["supported"] as? Bool, false, key)
      XCTAssertEqual(result?["detected"] as? Bool, false, key)
    }
  }

  func testFraudContextSignalsAreChecked() {
    let report =
      call("scan", ["signals": ["activeCall", "noScreenLock", "appDataMigrated"]])
      as? [String: Any]
    let activeCall = report?["activeCall"] as? [String: Any]
    XCTAssertEqual(activeCall?["supported"] as? Bool, true)
    XCTAssertEqual(activeCall?["detected"] as? Bool, false)
    for key in ["noScreenLock", "appDataMigrated"] {
      XCTAssertNotNil(report?[key] as? [String: Any], key)
    }
  }

  func testAnUnexpectedTeamIsNeverClean() {
    let report =
      call("scan", ["signals": ["signatureMismatch"], "expectedTeamIds": ["zzzzzzzzzz"]])
      as? [String: Any]
    let result = report?["signatureMismatch"] as? [String: Any]
    XCTAssertTrue(
      (result?["detected"] as? Bool) == true || (result?["failed"] as? Bool) == true,
      "\(String(describing: result))")
  }

  func testIntegrityRules() {
    XCTAssertEqual(
      AppIntegrityRules.details(
        teamId: "ABCDE12345", expected: ["ABCDE12345"], appStoreBuild: true, encrypted: true), [])
    XCTAssertEqual(
      AppIntegrityRules.details(
        teamId: "OTHER12345", expected: ["ABCDE12345"], appStoreBuild: false, encrypted: false),
      ["signed by team OTHER12345"])
    XCTAssertEqual(
      AppIntegrityRules.details(
        teamId: "ABCDE12345", expected: ["ABCDE12345"], appStoreBuild: true, encrypted: false),
      ["the app binary was decrypted"])
  }

  func testBindingRules() {
    XCTAssertEqual(BindingState.of(dataId: nil, deviceId: "a"), .unbound)
    XCTAssertEqual(BindingState.of(dataId: "a", deviceId: "a"), .bound)
    XCTAssertEqual(BindingState.of(dataId: "a", deviceId: nil), .migrated)
    XCTAssertEqual(BindingState.of(dataId: "a", deviceId: "b"), .migrated)
  }

  func testDataWithoutItsKeychainIdCameFromElsewhere() throws {
    let first = DeviceBinding.detection()
    try XCTSkipIf(first.error != nil, "no Keychain access in this test host")
    XCTAssertFalse(first.detected)
    // What a restore onto another device looks like: the data arrives, the Keychain item not.
    KeychainItem(account: "dev.shewa.flutter_anti_virtuals.binding").delete()
    XCTAssertTrue(DeviceBinding.detection().detected)
    XCTAssertEqual(call("rebindDevice") as? Bool, true)
    XCTAssertFalse(DeviceBinding.detection().detected)
  }

  func testSignPayloadReturnsAKeyAndSignature() {
    let signed = call("signPayload", ["nonce": "nonce-0123456789ab", "payload": "{}"]) as? [String: Any]
    XCTAssertFalse((signed?["signature"] as? String ?? "").isEmpty)
    XCTAssertFalse((signed?["publicKey"] as? String ?? "").isEmpty)
    XCTAssertEqual(signed?["algorithm"] as? String, "SHA256withECDSA")
  }

  func testUnknownMethodsAreNotImplemented() {
    XCTAssertTrue((call("getPlatformVersion") as AnyObject) === FlutterMethodNotImplemented)
  }
}
