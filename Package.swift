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
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "BcryptTests",
            dependencies: ["Bcrypt"]
        ),
    ]
)

var swiftSettings: [SwiftSetting] {
    [
        .strictMemorySafety(),
        //    .treatAllWarnings(as: .error),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("InferIsolatedConformances"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableUpcomingFeature("ImmutableWeakCaptures"),
        .enableExperimentalFeature("SuppressedAssociatedTypesWithDefaults"),
        .enableExperimentalFeature("LifetimeDependence"),
        .enableExperimentalFeature("Lifetimes"),
        .enableUpcomingFeature("LifetimeDependence"),
        .enableUpcomingFeature("ImmutableWeakCaptures"),
    ]
}
