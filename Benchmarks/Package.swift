// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v10_15)
    ],
    dependencies: [
        .package(path: "../"),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.29.0"),
    ],
    targets: [
        .executableTarget(
            name: "Hashing",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "Bcrypt", package: "bcrypt"),
            ],
            path: "Hashing",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        )
    ]
)
