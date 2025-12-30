// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v26)
    ],
    dependencies: [
        .package(path: "../"),
        // .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.29.0"),
        .package(url: "https://github.com/ptoffy/package-benchmark", branch: "debug-mode-benchmarks")
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
