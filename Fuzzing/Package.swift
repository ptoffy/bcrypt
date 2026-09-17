// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "Fuzzing",
    platforms: [
        .macOS(.v26)
    ],
    dependencies: [
        .package(path: "../"),
        .package(url: "https://github.com/brokenhandsio/swift-fuzz.git", from: "0.4.1"),
    ],
    targets: [
        .executableTarget(
            name: "BcryptFuzz",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "Bcrypt", package: "bcrypt"),
            ],
            path: "FuzzTargets/BcryptFuzz",
            plugins: [
                .plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")
            ]
        )
    ]
)
