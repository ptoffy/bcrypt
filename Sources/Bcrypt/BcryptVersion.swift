public enum BcryptVersion: Equatable, Sendable {
    case v2a
    case v2b
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
        case (0x24, 0x32, 0x62, 0x24): self = .v2b  // 2y is an alias for 2b
        case (0x24, 0x32, 0x79, 0x24): self = .v2y
        default: return nil
        }
    }
}

extension UInt8 {
    @usableFromInline
    static let separator: UInt8 = 0x24  // $
}
