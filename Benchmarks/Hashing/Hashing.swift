import Bcrypt
import Benchmark

let benchmarks = { @Sendable in
    Benchmark.defaultConfiguration = .init(
        metrics: [.mallocCountTotal, .wallClock]
    )

    Benchmark("Hash 12") { benchmark in
        _ = try Bcrypt.hash(password: "password", cost: 12)
    }
}
