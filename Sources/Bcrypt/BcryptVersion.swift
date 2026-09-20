/// The variant identifier written at the start of a bcrypt hash.
///
/// All three variants compute the same hash from the same password and salt; they differ only in the
/// prefix and in how over-long passwords are treated. `verify` accepts any of them and preserves the
/// prefix, so a hash created with one variant round-trips unchanged.
public enum BcryptVersion: Equatable, Sendable {
    /// `$2a$`, the original 1999 revision.
    ///
    /// Passwords longer than 72 bytes are truncated rather than rejected, for compatibility with hashes
    /// created by implementations that predate the length check.
    case v2a
    /// `$2b$`, OpenBSD's 2014 revision and the default.
    ///
    /// Passwords longer than 72 bytes are rejected with ``BcryptError/passwordTooLong`` when hashing.
    case v2b
    /// `$2y$`, the prefix used by PHP's `password_hash` and Apache `htpasswd`.
    ///
    /// Identical to ``v2b`` in every respect other than the prefix.
    case v2y

    @usableFromInline
    var majorVersion: UInt8 {
        switch self {
        case .v2a, .v2b, .v2y: 0x32
        }
    }

    @usableFromInline
    var minorVersion: UInt8 {
        switch self {
        case .v2a: 0x61
        case .v2b: 0x62
        case .v2y: 0x79
        }
    }

    @usableFromInline
    var identifier: InlineArray<4, UInt8> {
        [.separator, majorVersion, minorVersion, .separator]  // $2x$
    }

    @usableFromInline
    init?(identifier: Span<UInt8>) {
        guard identifier.count == 4 else { return nil }
        switch (identifier[0], identifier[1], identifier[2], identifier[3]) {
        case (0x24, 0x32, 0x61, 0x24): self = .v2a
        case (0x24, 0x32, 0x62, 0x24): self = .v2b
        case (0x24, 0x32, 0x79, 0x24): self = .v2y
        default: return nil
        }
    }
}

extension UInt8 {
    @usableFromInline
    static let separator: UInt8 = 0x24  // $
}
