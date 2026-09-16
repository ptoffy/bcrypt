import Bcrypt
import Benchmark

let benchmarks = { @Sendable in
    Benchmark.defaultConfiguration = .init(
        metrics: [.mallocCountTotal, .instructions, .wallClock]
    )

    let cost = 12
    let password = "password"
    let passwordBytes = Array(password.utf8)

    // Hashed once up front so the benchmarks measure verification only.
    let hashString = try! Bcrypt.hash(password: password, cost: cost)
    let hashBytes = Array(hashString.utf8)

    Benchmark("Verify 12 String") { benchmark in
        blackHole(try Bcrypt.verify(password: password, against: hashString))
    }

    Benchmark("Verify 12 [UInt8]") { benchmark in
        blackHole(try Bcrypt.verify(password: passwordBytes, against: hashBytes))
    }

    Benchmark("Verify 12 Span") { benchmark in
        blackHole(try Bcrypt.verify(password: passwordBytes.span, against: hashBytes.span))
    }
}
