import Bcrypt
import Testing

@Suite("Bcrypt Tests")
struct BcryptTests {
    @Test("Test Vectors", arguments: TestVector.all)
    func testVectorsHashing(testVector: TestVector) throws {
        let hash = try Bcrypt.hash(
            password: Array(testVector.password.utf8), cost: testVector.cost, salt: Array(testVector.salt.utf8), version: .v2a
        )

        #expect(
            hash == Array(testVector.expectedHash.utf8),
            "Expected: \(testVector.expectedHash), got: \(String(decoding: hash, as: UTF8.self))"
        )
    }

    @Test("Test Vectors via settings string", arguments: TestVector.all)
    func testVectorsHashingWithSettings(testVector: TestVector) throws {
        let settings = Array(testVector.expectedHash.utf8.prefix(29))
        let hash = try Bcrypt.hash(password: Array(testVector.password.utf8).span, settings: settings.span)

        #expect(
            hash == Array(testVector.expectedHash.utf8),
            "Expected: \(testVector.expectedHash), got: \(String(decoding: hash, as: UTF8.self))"
        )
    }

    @Test("Settings string round trip")
    func settingsRoundTrip() throws {
        let hash = try Bcrypt.hash(password: "password", cost: 4, version: .v2y)
        let settings = String(hash.prefix(29))

        #expect(try Bcrypt.hash(password: "password", settings: settings) == hash)
        #expect(try Bcrypt.hash(password: "wrong", settings: settings) != hash)
    }

    @Test("Settings string into OutputSpan")
    func settingsIntoOutputSpan() throws {
        let expected = "$2y$12$3cVe95jlT26PkfwkJ1Jl4uHBWGEFfdI3L95clNilo3p82rLvh6GwK"
        let settings = Array(expected.utf8.prefix(29))
        let hash = try InlineArray<60, UInt8> { output throws(BcryptError) in
            try Bcrypt.hash(password: Array("test".utf8).span, settings: settings.span, into: &output)
        }

        var bytes: [UInt8] = []
        for i in hash.indices {
            bytes.append(hash[i])
        }
        #expect(bytes == Array(expected.utf8))
    }

    @Test("Malformed settings")
    func malformedSettings() throws {
        let salt = String(repeating: "A", count: 22)

        for settings in ["$2a$10$", "$2a$10$" + salt + "A", "$2a$10$" + salt + salt + "AAAAAAA"] {
            #expect(throws: BcryptError.invalidSettings) {
                try Bcrypt.hash(password: "test", settings: settings)
            }
        }

        #expect(throws: BcryptError.invalidSettings) {
            try Bcrypt.hash(password: "test", settings: "$2a$10x" + salt)
        }

        #expect(throws: BcryptError.invalidVersion) {
            try Bcrypt.hash(password: "test", settings: "$2z$10$" + salt)
        }

        #expect(throws: BcryptError.invalidCost) {
            try Bcrypt.hash(password: "test", settings: "$2a$99$" + salt)
        }

        #expect(throws: BcryptError.invalidSalt) {
            try Bcrypt.hash(password: "test", settings: "$2a$10$" + String(repeating: "!", count: 22))
        }
    }

    @Test("End to end")
    func endToEnd() throws {
        let password = "password"
        let cost = 12

        let hash = try Bcrypt.hash(password: password, cost: cost)

        #expect(try Bcrypt.verify(password: password, against: hash))
    }

    @Test("Correct Version")
    func correctVersion() throws {
        let hash = try Bcrypt.hash(password: "password", cost: 6)

        #expect(hash.hasPrefix("$2b$06$"))
    }

    @Test("Empty password")
    func emptyPassword() throws {
        #expect(throws: Error.self) {
            try Bcrypt.hash(password: "", cost: 6)
        }
    }

    @Test("Maximum length password (72 bytes)")
    func maximumLengthPassword() throws {
        let password = String(repeating: "a", count: 72)
        let hash = try Bcrypt.hash(password: password, cost: 6)
        #expect(try Bcrypt.verify(password: password, against: hash))
    }

    @Test("Password too long")
    func passwordTooLong() throws {
        let password = String(repeating: "a", count: 73)
        #expect(throws: BcryptError.passwordTooLong) {
            try Bcrypt.hash(password: password, cost: 6)
        }
    }

    @Test("UTF-8 bytes exceed limit but character count is OK")
    func utf8TooLongButCharsOk() throws {
        // 72 characters, but each 'é' is 2 bytes in UTF-8 => 144 bytes
        let password = String(repeating: "é", count: 72)

        #expect(throws: BcryptError.passwordTooLong) {
            try Bcrypt.hash(password: password, cost: 6)
        }
    }

    @Test("Different passwords produce different hashes")
    func differentPasswordsDifferentHashes() throws {
        let hash1 = try Bcrypt.hash(password: "password1", cost: 6)
        let hash2 = try Bcrypt.hash(password: "password2", cost: 6)

        #expect(hash1 != hash2)
    }

    @Test("Same password with different salts produces different hashes")
    func samePwDifferentSalts() throws {
        let password = "test"
        let hash1 = try Bcrypt.hash(password: password, cost: 6)
        let hash2 = try Bcrypt.hash(password: password, cost: 6)

        // Different salts should produce different hashes
        #expect(hash1 != hash2)

        // But both should verify
        #expect(try Bcrypt.verify(password: password, against: hash1))
        #expect(try Bcrypt.verify(password: password, against: hash2))
    }

    @Test("Unicode password handling")
    func unicodePassword() throws {
        let passwords = ["πάσσω", "密码", "🔐🔑", "Ñoño"]

        for password in passwords {
            let hash = try Bcrypt.hash(password: password, cost: 4)
            #expect(try Bcrypt.verify(password: password, against: hash))
        }
    }

    @Test("Wrong password fails verification")
    func wrongPasswordFails() throws {
        let hash = try Bcrypt.hash(password: "correct", cost: 6)
        #expect(try !Bcrypt.verify(password: "wrong", against: hash))
    }

    @Test("Malformed hashes")
    func malformedHashes() throws {
        let malformed = [
            "$2a$10$invalid",
            "$2a$10",
            "not a hash",
        ]

        for hash in malformed {
            #expect(throws: BcryptError.invalidHash) {
                try Bcrypt.verify(password: "test", against: hash)
            }
        }

        #expect(throws: BcryptError.invalidCost) {
            try Bcrypt.verify(password: "test", against: "$2a$99$" + String(repeating: "A", count: 53))
        }

        #expect(throws: BcryptError.invalidVersion) {
            try Bcrypt.verify(password: "test", against: "$2z$10$" + String(repeating: "A", count: 53))
        }

        #expect(throws: BcryptError.invalidHash) {
            try Bcrypt.verify(password: "test", against: "$2a$10x" + String(repeating: "A", count: 53))
        }
    }

    @Test("Verify $2y$ hash")
    func verify2y() throws {
        let hash = "$2y$12$3cVe95jlT26PkfwkJ1Jl4uHBWGEFfdI3L95clNilo3p82rLvh6GwK"
        #expect(try Bcrypt.verify(password: "test", against: hash))
        #expect(try !Bcrypt.verify(password: "wrong", against: hash))
        #expect(try Bcrypt.hash(password: "test", cost: 4, version: .v2y).hasPrefix("$2y$04$"))
    }

    @Test("Verify legacy hash of a password longer than 72 bytes")
    func verifyLegacyLongPassword() throws {
        let hash = "$2y$04$NpsZn6lJmcKCKlJWJMvLuuH/volE4xvrPM5Z0uMURrn3kPAgNiLvG"
        #expect(try Bcrypt.verify(password: String(repeating: "a", count: 73), against: hash))
        #expect(try Bcrypt.verify(password: String(repeating: "a", count: 72), against: hash))
        #expect(try !Bcrypt.verify(password: String(repeating: "a", count: 71), against: hash))
    }

    @Test("Non-canonical salt is normalised in the output")
    func nonCanonicalSalt() throws {
        let canonical = "abcdefghijklmnopqrstue"  // 'e' = 0b100000
        let nonCanonical = "abcdefghijklmnopqrstuf"  // 'f' = 0b100001
        let h1 = try Bcrypt.hash(password: Array("x".utf8), cost: 4, salt: Array(canonical.utf8))
        let h2 = try Bcrypt.hash(password: Array("x".utf8), cost: 4, salt: Array(nonCanonical.utf8))
        #expect(h1 == h2)
        #expect(String(decoding: h1, as: UTF8.self).hasPrefix("$2b$04$" + canonical))
    }

    @Test("Property: Any valid password should hash and verify", arguments: 1...100)
    func propertyHashAndVerify(iteration: Int) throws {
        let passwords = [
            String(repeating: "a", count: Int.random(in: 1...72)),
            randomASCII(),
            randomUTF8(),
        ]

        func randomUTF8() -> String {
            // Mix of single-byte, 2-byte, 3-byte, and 4-byte UTF-8 characters
            let unicodeRanges: [ClosedRange<Int>] = [
                0x0020...0x007E,  // ASCII (1 byte)
                0x00A0...0x00FF,  // Latin-1 Supplement: é, ñ, ü (2 bytes)
                0x0370...0x03FF,  // Greek: α, β, γ (2 bytes)
                0x0400...0x04FF,  // Cyrillic: Д, Ж, Л (2 bytes)
                0x4E00...0x4E20,  // CJK: 一, 丁, 七 (3 bytes)
                0x1F300...0x1F320,  // Emojis: 🌀, 🌁, 🌂 (4 bytes)
            ]

            var result = ""
            var byteCount = 0

            while byteCount < 60 {
                let range = unicodeRanges.randomElement()!
                let value = Int.random(in: range)

                guard let scalar = UnicodeScalar(value) else { continue }
                let char = Character(scalar)
                let charString = String(char)

                if byteCount + charString.utf8.count <= 72 {
                    result += charString
                    byteCount += charString.utf8.count
                } else {
                    break
                }
            }

            return result.isEmpty ? "a" : result
        }

        func randomASCII() -> String {
            let length = Int.random(in: 1...72)

            let characters = (1...length).map { _ in  // from space to tilde, all ASCII
                let randomASCIIValue = Int.random(in: 0x20...0x7E)
                let unicodeScalar = UnicodeScalar(randomASCIIValue)!
                return Character(unicodeScalar)
            }

            return String(characters)
        }

        for password in passwords {
            let hash = try Bcrypt.hash(password: password, cost: 4)
            #expect(try Bcrypt.verify(password: password, against: hash))
            if password.count != 72 {
                #expect(try !Bcrypt.verify(password: password + "x", against: hash))
            }
        }
    }
}
