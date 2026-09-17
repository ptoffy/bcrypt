import Bcrypt
import Fuzzing

let fuzzCost = 4

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget.structured("Hash") { data in
        let salt = data.chunk()
        let password = data.remainingBytes()

        guard let hash = try? Bcrypt.hash(password: password, cost: fuzzCost, salt: salt) else {
            return
        }
        precondition(hash.count == 60, "hash is \(hash.count) bytes, expected 60")
        precondition(
            (try? Bcrypt.verify(password: password, against: hash)) == true,
            "a freshly produced hash did not verify"
        )
    }

    FuzzTarget.bytes("Verify") { bytes in
        var hash = bytes
        if hash.count >= 6, isDigit(hash[4]), isDigit(hash[5]) {
            let cost = Int(hash[4] &- 0x30) * 10 + Int(hash[5] &- 0x30)
            if cost > fuzzCost {
                hash[4] = 0x30
                hash[5] = 0x30 &+ UInt8(fuzzCost)
            }
        }
        _ = try? Bcrypt.verify(password: Array("password".utf8), against: hash)
    }
}

private func isDigit(_ byte: UInt8) -> Bool {
    (0x30...0x39).contains(byte)
}
