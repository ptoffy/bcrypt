extension Bcrypt {
    /// "OrpheanBeholderScryDoubt" as six big-endian words; the block that bcrypt encrypts 64 times with the derived key.
    @usableFromInline static let cipherText: InlineArray<6, UInt32> = [
        0x4f72_7068, 0x6561_6e42, 0x6568_6f6c,
        0x6465_7253, 0x6372_7944, 0x6f75_6274,
    ]
    @usableFromInline static let maxSalt = 16
    @usableFromInline static let saltSpace = 22
    @usableFromInline static let words = 6
    @usableFromInline static let hashSpace = 60

    /// Hashes a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost). Must be between 4 and 31.
    ///   - version: the version of the bcrypt algorithm to use. Defaults to `v2b`.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(password: String, cost: Int = 10, version: BcryptVersion = .v2b) throws(BcryptError) -> String {
        String(decoding: try hash(password: password.utf8Span.span, cost: cost, version: version), as: UTF8.self)
    }

    /// Hashes a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost). Must be between 4 and 31.
    ///   - version: the version of the bcrypt algorithm to use. Defaults to `v2b`.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(password: [UInt8], cost: Int = 10, version: BcryptVersion = .v2b) throws(BcryptError) -> [UInt8] {
        try hash(password: password.span, cost: cost, version: version)
    }

    /// Hashes a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost). Must be between 4 and 31.
    ///   - version: the version of the bcrypt algorithm to use. Defaults to `v2b`.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(password: Span<UInt8>, cost: Int = 10, version: BcryptVersion = .v2b) throws(BcryptError) -> [UInt8] {
        let salt = Self.generateRandomSalt()
        return try hash(password: password, cost: cost, salt: salt.span, version: version)
    }

    /// Hashes a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost). Must be between 4 and 31.
    ///   - salt: the 22 character, base64 encoded salt to use for the hash.
    ///   - version: the version of the bcrypt algorithm to use. Defaults to `v2b`.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(
        password: [UInt8], cost: Int = 10, salt: [UInt8], version: BcryptVersion = .v2b
    ) throws(BcryptError) -> [UInt8] {
        try hash(password: password.span, cost: cost, salt: salt.span, version: version)
    }

    /// Hashes a password using the bcrypt algorithm.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost). Must be between 4 and 31.
    ///   - salt: the 22 character, base64 encoded salt to use for the hash.
    ///   - version: the version of the bcrypt algorithm to use. Defaults to `v2b`.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(
        password: Span<UInt8>, cost: Int = 10, salt: Span<UInt8>, version: BcryptVersion = .v2b
    ) throws(BcryptError) -> [UInt8] {
        try [UInt8](capacity: Self.hashSpace) { output throws(BcryptError) in
            try hash(password: password, cost: cost, salt: salt, version: version, into: &output)
        }
    }

    /// Hashes a password using the bcrypt algorithm, writing the 60 byte hash into `output`.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - cost: number of rounds to apply the key derivation function, used as log2(cost). Must be between 4 and 31.
    ///   - salt: the 22 character, base64 encoded salt to use for the hash.
    ///   - version: the version of the bcrypt algorithm to use. Defaults to `v2b`.
    ///   - output: receives the 60 bytes of the hash. Must have room for at least 60 more elements.
    /// - Throws: ``BcryptError``
    public static func hash(
        password: Span<UInt8>,
        cost: Int = 10,
        salt: Span<UInt8>,
        version: BcryptVersion = .v2b,
        into output: inout OutputSpan<UInt8>
    ) throws(BcryptError) {
        guard salt.count == Self.saltSpace else {
            throw BcryptError.invalidSaltLength
        }

        let cSalt: InlineArray<16, UInt8>
        do {
            cSalt = try InlineArray<16, UInt8>(initializingWith: { (output: inout OutputSpan<UInt8>) throws(Base64Error) in
                try Base64.decode(salt, count: Self.maxSalt, into: &output)
                guard output.count == Self.maxSalt else {
                    throw .invalidLength
                }
            })
        } catch {
            throw BcryptError.invalidSalt
        }

        guard password.count > 0 else {
            throw BcryptError.emptyPassword
        }

        // The key schedule streams a NUL terminator after the password itself (see `EksBlowfish.stream2word`).
        // If the caller already supplied one, drop it so that it is not counted twice.
        let key = password[password.count - 1] == 0 ? password.extracting(..<(password.count &- 1)) : password

        switch version {
        case .v2a: break
        case .v2b:
            guard key.count <= 72 else {
                throw BcryptError.passwordTooLong
            }
        }

        if cost < 4 || cost > 31 {
            throw BcryptError.invalidCost
        }

        var (p, s) = EksBlowfish.setup(password: key, salt: cSalt.span, cost: cost)
        // these aren't actually being mutated but having them as Span instead would require
        // us to have two separate encipher methods
        let pSpan = p.mutableSpan
        let sSpan = s.mutableSpan

        var cData = Self.cipherText

        var i = 0
        while i < 64 {
            var j = 0
            var xl: UInt32 = 0
            var xr: UInt32 = 0
            while j < Self.words / 2 {
                xl = cData[j &* 2]
                xr = cData[j &* 2 &+ 1]
                EksBlowfish.encipher(xl: &xl, xr: &xr, p: pSpan, s: sSpan)
                cData[j &* 2] = xl
                cData[j &* 2 &+ 1] = xr
                j &+= 1
            }
            i &+= 1
        }

        // Big-endian bytes of cData; only the first 23 are part of the hash.
        let cipherBytes = InlineArray<24, UInt8> { i in
            UInt8(truncatingIfNeeded: cData[i / 4] &>> (24 &- 8 &* (i % 4)))
        }

        for index in version.identifier.indices {
            output.append(version.identifier[index])
        }

        switch cost {
        case 0...9:
            output.append(0x30)
            output.append(UInt8(cost &+ 0x30))
        default:
            output.append(UInt8(cost / 10 + 0x30))
            output.append(UInt8(cost % 10 + 0x30))
        }

        output.append(36)

        for index in salt.indices {
            output.append(salt[index])
        }

        Base64.encode(cipherBytes.span, count: 4 * Self.words - 1, into: &output)
    }

    // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
    // \__/\/ \____________________/\_____________________________/
    // Alg Cost      Salt                        Hash
    @usableFromInline
    static func generateRandomSalt() -> InlineArray<22, UInt8> {
        let cSalt = InlineArray<16, UInt8> {
            _ in UInt8.random(in: .min ... .max)
        }
        return InlineArray<22, UInt8>(initializingWith: { outputSpan in
            Base64.encode(cSalt.span, count: Self.hashSpace, into: &outputSpan)
        })
    }
}
