// Ported from OpenBSD's bcrypt implementation (lib/libc/crypt/bcrypt.c).
// Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>, Copyright (c) 1997 Niels Provos <provos@umich.edu>.
// Redistributed under the ISC license; the full notice is reproduced in LICENSE.

extension Bcrypt {
    /// Verifies a password against a hash.
    /// - Parameters:
    ///   - password: the password to verify.
    ///   - hash: the hash to verify against.
    /// - Throws: ``BcryptError``
    /// - Returns: `true` if the password matches the hash, `false` otherwise.
    @inlinable
    public static func verify(password: String, against hash: String) throws(BcryptError) -> Bool {
        try verify(password: password.utf8Span.span, against: hash.utf8Span.span)
    }

    /// Verifies a password against a hash.
    /// - Parameters:
    ///   - password: the password to verify.
    ///   - hash: the hash to verify against.
    /// - Throws: ``BcryptError``
    /// - Returns: `true` if the password matches the hash, `false` otherwise.
    @inlinable
    public static func verify(password: [UInt8], against hash: [UInt8]) throws(BcryptError) -> Bool {
        try verify(password: password.span, against: hash.span)
    }

    /// Verifies a password against a hash.
    /// - Parameters:
    ///   - password: the password to verify.
    ///   - hash: the hash to verify against.
    /// - Throws: ``BcryptError``
    /// - Returns: `true` if the password matches the hash, `false` otherwise.
    @inlinable
    public static func verify(password: Span<UInt8>, against hash: Span<UInt8>) throws(BcryptError) -> Bool {
        // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
        // \__/\/ \____________________/\_____________________________/
        // Alg Cost      Salt                        Hash

        guard hash.count == Bcrypt.hashSpace else {
            throw BcryptError.invalidHash
        }

        guard let version = BcryptVariant(identifier: hash.extracting(0...3)) else {
            throw BcryptError.invalidVersion
        }

        let tens = Int(hash[4]) - 48
        let ones = Int(hash[5]) - 48
        guard (0...9).contains(tens) && (0...9).contains(ones) else {
            throw BcryptError.invalidCost
        }
        let cost = tens * 10 + ones

        guard hash[6] == UInt8.separator else {
            throw BcryptError.invalidHash
        }

        let key = password.count > Bcrypt.maxPasswordLength ? password.extracting(..<Bcrypt.maxPasswordLength) : password

        let newHash = try InlineArray<60, UInt8> { outputSpan throws(BcryptError) in
            try Bcrypt.hash(password: key, cost: cost, salt: hash.extracting(7..<29), version: version, into: &outputSpan)
        }

        return constantTimeEquals(newHash.span, hash)
    }
}

@usableFromInline func constantTimeEquals(_ a: Span<UInt8>, _ b: Span<UInt8>) -> Bool {
    guard a.count == b.count else { return false }
    var areEqual: UInt8 = 0
    var i = a.count - 1
    while i >= 0 {
        areEqual |= a[i] ^ b[i]
        i -= 1
    }
    return areEqual == 0
}
