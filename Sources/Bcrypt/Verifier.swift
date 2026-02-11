extension Bcrypt {
    /// Verifies a password against a hash.
    /// - Parameters:
    ///   - password: the password to verify.
    ///   - hash: the hash to verify against.
    /// - Throws: ``BcryptError``
    /// - Returns: `true` if the password matches the hash, `false` otherwise.
    @inlinable
    public static func verify(password: String, against hash: String) throws(BcryptError) -> Bool {
        try verify(password: Array(password.utf8), against: Array(hash.utf8))
    }

    /// Verifies a password against a hash.
    /// - Parameters:
    ///   - password: the password to verify.
    ///   - hash: the hash to verify against.
    /// - Throws: ``BcryptError``
    /// - Returns: `true` if the password matches the hash, `false` otherwise.
    @inlinable
    public static func verify(password: [UInt8], against hash: [UInt8]) throws(BcryptError) -> Bool {
        // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
        // \__/\/ \____________________/\_____________________________/
        // Alg Cost      Salt                        Hash

        guard hash.count == Bcrypt.hashSpace else {
            throw BcryptError.invalidHash
        }

        guard let version = BcryptVersion(identifier: hash[0...3]) else {
            throw BcryptError.invalidVersion
        }

        let tens = Int(hash[4]) - 48
        let ones = Int(hash[5]) - 48
        guard (0...9).contains(tens) && (0...9).contains(ones) else {
            throw BcryptError.invalidCost
        }
        let cost = tens * 10 + ones

        let salt = Array(hash[7...28])

        let newHash = try Bcrypt.hash(password: password, cost: cost, salt: salt, version: version)

        return constantTimeEquals(newHash, hash)
    }
}

@usableFromInline func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var areEqual: UInt8 = 0
    var i = a.count - 1
    while i >= 0 {
        areEqual |= a[i] ^ b[i]
        i -= 1
    }
    return areEqual == 0
}
