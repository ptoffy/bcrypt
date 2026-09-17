import Bcrypt
import Benchmark

let benchmarks = { @Sendable in
    #if os(Linux)
        let metrics: [BenchmarkMetric] = [.mallocCountTotal, .wallClock]
    #else
        let metrics: [BenchmarkMetric] = [.mallocCountTotal, .instructions, .wallClock]
    #endif

    Benchmark.defaultConfiguration = .init(
        metrics: metrics,
        thresholds: [
            .mallocCountTotal: .init(absolute: BenchmarkThresholds.Absolute.strict),
            .instructions: .init(relative: BenchmarkThresholds.Relative.default),
            .wallClock: .init(relative: BenchmarkThresholds.Relative.none),
        ]
    )

    let cost = 12
    let password = "password"
    let passwordBytes = Array(password.utf8)
    let salt = "R9h/cIPz0gi.URNNX3kh2O"
    let saltBytes = Array(salt.utf8)

    Benchmark("Hash 12 String") { benchmark in
        blackHole(try Bcrypt.hash(password: password, cost: cost))
    }

    Benchmark("Hash 12 [UInt8]") { benchmark in
        blackHole(try Bcrypt.hash(password: passwordBytes, cost: cost))
    }

    Benchmark("Hash 12 Span") { benchmark in
        blackHole(try Bcrypt.hash(password: passwordBytes.span, cost: cost))
    }

    Benchmark("Hash 12 [UInt8] with salt") { benchmark in
        blackHole(try Bcrypt.hash(password: passwordBytes, cost: cost, salt: saltBytes))
    }

    Benchmark("Hash 12 Span with salt") { benchmark in
        blackHole(try Bcrypt.hash(password: passwordBytes.span, cost: cost, salt: saltBytes.span))
    }

    Benchmark("Hash 12 into OutputSpan") { benchmark in
        let output = try InlineArray<60, UInt8>(initializingWith: { (output: inout OutputSpan<UInt8>) in
            try Bcrypt.hash(password: passwordBytes.span, cost: cost, salt: saltBytes.span, into: &output)
        })
        blackHole(output)
    }
}
