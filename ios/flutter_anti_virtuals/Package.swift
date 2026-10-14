// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "flutter_anti_virtuals",
    platforms: [
        .iOS("15.0")
    ],
    products: [
        .library(name: "flutter-anti-virtuals", targets: ["flutter_anti_virtuals"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "flutter_anti_virtuals",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework")
            ],
            resources: [
                // Declares the required-reason APIs the plugin uses (UserDefaults).
                .process("PrivacyInfo.xcprivacy")
            ]
        )
    ]
)
