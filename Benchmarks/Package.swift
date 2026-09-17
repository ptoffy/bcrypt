// swift-tools-version: 6.4
import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v26)
    ],
    dependencies: [
        .package(path: "../"),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.29.9"),
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
        ),
        .executableTarget(
            name: "Verifying",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "Bcrypt", package: "bcrypt"),
            ],
            path: "Verifying",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
    ]
)
