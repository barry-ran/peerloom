// swift-tools-version: 6.0
// MIT — Copyright (c) 2026 Peerloom contributors.
import PackageDescription
import Foundation
let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let binary = FileManager.default.fileExists(atPath: packageRoot.appendingPathComponent("Artifacts/CPeerloom.xcframework").path)
let native: Target = binary
    ? .binaryTarget(name: "CPeerloom", path: "Artifacts/CPeerloom.xcframework")
    : .systemLibrary(name: "CPeerloom", path: "Sources/CPeerloom")
let package = Package(
    name: "PeerloomApple",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "PeerloomSwift", targets: ["PeerloomSwift"])],
    targets: [native,
        .target(name: "PeerloomSwift", dependencies: ["CPeerloom"],
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("Foundation"), .linkedFramework("LocalAuthentication"),
                                 .linkedFramework("SystemConfiguration"), .linkedLibrary("resolv"),
                                 .linkedLibrary("iconv"), .linkedLibrary("objc")]),
        .executableTarget(name: "PeerloomStoreProbe", dependencies: ["PeerloomSwift"]),
        .testTarget(name: "PeerloomSwiftTests", dependencies: ["PeerloomSwift", "CPeerloom"])
    ],
    swiftLanguageModes: [.v5]
)
