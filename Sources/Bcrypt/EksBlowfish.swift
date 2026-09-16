/// EksBlowfish (Expensive key schedule Blowfish) is a block cipher based on Blowfish.
///
/// This work is based on
/// 1. Applied Cryptography, Second Edition by Bruce Schneier, section 14 and the corresponding code in Part V.
/// 2. The OpenBSD implementation of bcrypt at https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c.
///    The function names and variable names are kept the same as in the OpenBSD implementation.
@usableFromInline enum EksBlowfish {
    @usableFromInline static let N = 16  // Cipher Rounds

    @usableFromInline
    static func setup(password: Span<UInt8>, salt: Span<UInt8>, cost: Int) -> (p: InlineArray<18, UInt32>, s: InlineArray<1024, UInt32>) {
        precondition(cost >= 4 && cost <= 31, "Cost must be between 4 and 31, is \(cost)")
        precondition(salt.count == 16, "Salt must be 16 bytes long, is \(salt.count)")
        // No length limit on the password here: the key stream only reads 72 bytes (18 words) into P,
        // so longer keys are implicitly truncated. The `2b` limit is enforced by the caller.

        var (p, s) = (Self.initialP, Self.initialS)

        var pSpan = p.mutableSpan
        var sSpan = s.mutableSpan

        expandState(password: password, salt: salt, p: &pSpan, s: &sSpan)

        var i = 1 &<< cost

        while i > 0 {
            expand0State(key: password, nulTerminated: true, p: &pSpan, s: &sSpan)
            expand0State(key: salt, nulTerminated: false, p: &pSpan, s: &sSpan)
            i &-= 1
        }

        return (p, s)
    }

    /// Reads the next big-endian word from `data`, wrapping around to the start when the end is reached.
    ///
    /// With `nulTerminated`, a virtual NUL byte is streamed after the last byte of `data`, matching the C
    /// implementations that feed `strlen(key) + 1` bytes of the password into the key schedule, without
    /// having to copy the password into a terminated buffer.
    @usableFromInline
    static func stream2word(data: Span<UInt8>, nulTerminated: Bool, j: inout Int) -> UInt32 {
        let length = nulTerminated ? data.count &+ 1 : data.count
        var word: UInt32 = 0

        for _ in 0..<4 {
            if j >= length { j = 0 }
            let byte: UInt8 = j < data.count ? data[unchecked: j] : 0
            word = (word &<< 8) | UInt32(byte)
            j &+= 1
        }

        return word
    }

    @usableFromInline
    static func expand0State(
        key: Span<UInt8>,
        nulTerminated: Bool,
        p: inout MutableSpan<UInt32>,
        s: inout MutableSpan<UInt32>
    ) {
        var j = 0
        var i = 0
        while i < Self.N &+ 2 {
            p[i] ^= stream2word(data: key, nulTerminated: nulTerminated, j: &j)
            i &+= 1
        }

        var dataL: UInt32 = 0
        var dataR: UInt32 = 0

        i = 0
        j = 0
        while i < Self.N &+ 2 {
            encipher(xl: &dataL, xr: &dataR, p: p, s: s)

            p[i] = dataL
            p[i &+ 1] = dataR
            i &+= 2
        }

        i = 0
        while i < 4 {
            var k = 0
            while k < 256 {
                encipher(xl: &dataL, xr: &dataR, p: p, s: s)

                s[i &* 0x100 &+ k] = dataL
                s[i &* 0x100 &+ (k &+ 1)] = dataR
                k &+= 2
            }
            i &+= 1
        }
    }

    @usableFromInline
    static func expandState(
        password: Span<UInt8>,
        salt: Span<UInt8>,
        p: inout MutableSpan<UInt32>,
        s: inout MutableSpan<UInt32>
    ) {
        var j = 0
        var i = 0
        while i < Self.N &+ 2 {
            p[i] ^= stream2word(data: password, nulTerminated: true, j: &j)
            i &+= 1
        }

        j = 0
        i = 0
        var dataL: UInt32 = 0
        var dataR: UInt32 = 0

        while i < Self.N &+ 2 {
            dataL ^= stream2word(data: salt, nulTerminated: false, j: &j)
            dataR ^= stream2word(data: salt, nulTerminated: false, j: &j)
            encipher(xl: &dataL, xr: &dataR, p: p, s: s)

            p[i] = dataL
            p[i &+ 1] = dataR
            i &+= 2
        }

        i = 0
        while i < 4 {
            var k = 0
            while k < 256 {
                dataL ^= stream2word(data: salt, nulTerminated: false, j: &j)
                dataR ^= stream2word(data: salt, nulTerminated: false, j: &j)
                encipher(xl: &dataL, xr: &dataR, p: p, s: s)

                s[i &* 0x100 &+ k] = dataL
                s[i &* 0x100 &+ (k &+ 1)] = dataR
                k &+= 2
            }
            i &+= 1
        }
    }

    @_transparent
    @usableFromInline
    static func f(_ s: borrowing MutableSpan<UInt32>, _ x: UInt32) -> UInt32 {
        let a = s[unchecked: Int(truncatingIfNeeded: x &>> 24)]
        let b = s[unchecked: 0x100 &+ Int(truncatingIfNeeded: (x &>> 16) & 0xff)]
        let c = s[unchecked: 0x200 &+ Int(truncatingIfNeeded: (x &>> 8) & 0xff)]
        let d = s[unchecked: 0x300 &+ Int(truncatingIfNeeded: x & 0xff)]
        return ((a &+ b) ^ c) &+ d
    }

    @_transparent
    @usableFromInline
    static func encipher(xl: inout UInt32, xr: inout UInt32, p: borrowing MutableSpan<UInt32>, s: borrowing MutableSpan<UInt32>) {
        var l = xl ^ p[unchecked: 0]
        var r = xr
        r ^= f(s, l) ^ p[unchecked: 1]
        l ^= f(s, r) ^ p[unchecked: 2]
        r ^= f(s, l) ^ p[unchecked: 3]
        l ^= f(s, r) ^ p[unchecked: 4]
        r ^= f(s, l) ^ p[unchecked: 5]
        l ^= f(s, r) ^ p[unchecked: 6]
        r ^= f(s, l) ^ p[unchecked: 7]
        l ^= f(s, r) ^ p[unchecked: 8]
        r ^= f(s, l) ^ p[unchecked: 9]
        l ^= f(s, r) ^ p[unchecked: 10]
        r ^= f(s, l) ^ p[unchecked: 11]
        l ^= f(s, r) ^ p[unchecked: 12]
        r ^= f(s, l) ^ p[unchecked: 13]
        l ^= f(s, r) ^ p[unchecked: 14]
        r ^= f(s, l) ^ p[unchecked: 15]
        l ^= f(s, r) ^ p[unchecked: 16]
        xl = r ^ p[unchecked: 17]
        xr = l
    }
}
