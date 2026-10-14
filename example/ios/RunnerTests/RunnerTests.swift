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
    let report = call("scan", ["signals": ["adb", "signatureMismatch"]]) as? [String: Any]
    for key in ["adb", "signatureMismatch"] {
      let result = report?[key] as? [String: Any]
      XCTAssertEqual(result?["supported"] as? Bool, false, key)
      XCTAssertEqual(result?["detected"] as? Bool, false, key)
    }
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
