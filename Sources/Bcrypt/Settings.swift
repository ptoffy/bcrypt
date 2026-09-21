// Ported from OpenBSD's bcrypt implementation (lib/libc/crypt/bcrypt.c).
// Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>, Copyright (c) 1997 Niels Provos <provos@umich.edu>.
// Redistributed under the ISC license; the full notice is reproduced in LICENSE.

extension Bcrypt {
    /// The length of a settings string: the 7 byte `$2x$NN$` prefix followed by the 22 character salt.
    @usableFromInline static let settingsSpace = 29

    /// Hashes a password using the bcrypt algorithm, taking the version, cost and salt from a settings string.
    ///
    /// `settings` is the `$2x$NN$` prefix plus the 22-character salt, i.e. the first 29 bytes of a hash. This is
    /// the `crypt(3)`-style interface; pass the first 29 characters of an existing hash to recompute it.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - settings: the 29 character `$2x$NN$` prefix and salt to use for the hash.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(password: String, settings: String) throws(BcryptError) -> String {
        String(decoding: try hash(password: password.utf8Span.span, settings: settings.utf8Span.span), as: UTF8.self)
    }

    /// Hashes a password using the bcrypt algorithm, taking the version, cost and salt from a settings string.
    ///
    /// `settings` is the `$2x$NN$` prefix plus the 22-character salt, i.e. the first 29 bytes of a hash. This is
    /// the `crypt(3)`-style interface; pass the first 29 bytes of an existing hash to recompute it.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - settings: the 29 byte `$2x$NN$` prefix and salt to use for the hash.
    /// - Throws: ``BcryptError``
    /// - Returns: the hashed password.
    @inlinable
    public static func hash(password: Span<UInt8>, settings: Span<UInt8>) throws(BcryptError) -> [UInt8] {
        try [UInt8](capacity: Self.hashSpace) { output throws(BcryptError) in
            try hash(password: password, settings: settings, into: &output)
        }
    }

    /// Hashes a password using the bcrypt algorithm, taking the version, cost and salt from a settings string and
    /// writing the 60 byte hash into `output`.
    ///
    /// `settings` is the `$2x$NN$` prefix plus the 22-character salt, i.e. the first 29 bytes of a hash. This is
    /// the `crypt(3)`-style interface; pass the first 29 bytes of an existing hash to recompute it.
    /// - Parameters:
    ///   - password: the password to hash.
    ///   - settings: the 29 byte `$2x$NN$` prefix and salt to use for the hash.
    ///   - output: receives the 60 bytes of the hash. Must have room for at least 60 more elements.
    /// - Throws: ``BcryptError``
    @inlinable
    public static func hash(
        password: Span<UInt8>, settings: Span<UInt8>, into output: inout OutputSpan<UInt8>
    ) throws(BcryptError) {
        guard settings.count == Self.settingsSpace else {
            throw BcryptError.invalidSettings
        }

        let (version, cost) = try parseVersionAndCost(settings)

        guard settings[6] == UInt8.separator else {
            throw BcryptError.invalidSettings
        }

        try hash(password: password, cost: cost, salt: settings.extracting(7..<Self.settingsSpace), version: version, into: &output)
    }

    /// Reads the variant and cost out of the leading `$2x$NN` bytes of a hash or settings string.
    ///
    /// `prefix` must be at least 6 bytes long. The separator that follows the cost is not checked, so that callers
    /// can report a missing one as an invalid hash or invalid settings as appropriate.
    /// - Throws: ``BcryptError/invalidVersion`` or ``BcryptError/invalidCost``.
    @usableFromInline
    static func parseVersionAndCost(_ prefix: Span<UInt8>) throws(BcryptError) -> (version: BcryptVariant, cost: Int) {
        // $2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
        // \__/\/ \____________________/\_____________________________/
        // Alg Cost      Salt                        Hash

        guard let version = BcryptVariant(identifier: prefix.extracting(0...3)) else {
            throw BcryptError.invalidVersion
        }

        let tens = Int(prefix[4]) - 48
        let ones = Int(prefix[5]) - 48
        guard (0...9).contains(tens) && (0...9).contains(ones) else {
            throw BcryptError.invalidCost
        }

        return (version, tens * 10 + ones)
    }
}
