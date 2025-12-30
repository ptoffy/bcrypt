// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "bcrypt",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .library(
            name: "Bcrypt",
            targets: ["Bcrypt"]
        ),
    ],
    targets: [
        .target(
            name: "Bcrypt",
            swiftSettings: settings
        ),
        .testTarget(
            name: "BcryptTests",
            dependencies: ["Bcrypt"],
            swiftSettings: settings
        ),
    ]
)

var settings: [SwiftSetting] {
    [.enableExperimentalFeature("Lifetimes")]
}
