// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "bcrypt",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .library(
            name: "Bcrypt",
            targets: ["Bcrypt"],
        )
    ],
    targets: [
        .target(
            name: "Bcrypt",
        ),
        .testTarget(
            name: "BcryptTests",
            dependencies: ["Bcrypt"]
        ),
    ]
)
