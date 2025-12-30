/// EksBlowfish (Expensive key schedule Blowfish) is a block cipher based on Blowfish.
///
/// This work is based on
/// 1. Applied Cryptography, Second Edition by Bruce Schneier, section 14 and the corresponding code in Part V.
/// 2. The OpenBSD implementation of bcrypt at https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c.
///    The function names and variable names are kept the same as in the OpenBSD implementation.
@usableFromInline enum EksBlowfish {
    @usableFromInline static let N = 16  // Cipher Rounds

    @usableFromInline
    static func setup(password: [UInt8], salt: [UInt8], cost: Int) -> (p: [UInt32], s: [UInt32]) {
        precondition(cost >= 4 && cost <= 31, "Cost must be between 4 and 31, is \(cost)")
        precondition(salt.count == 16, "Salt must be 16 bytes long, is \(salt.count)")
        precondition(
            password.count > 0 && password.count <= 73,
            "Password must be between 1 and 73 bytes long counting the NULL terminator, is \(password.count)")

        var (p, s) = (Self.initialP, Self.initialS)

        var pSpan = p.mutableSpan
        var sSpan = s.mutableSpan

        expandState(password: password, salt: salt, p: &pSpan, s: &sSpan)

        var i = 1 &<< cost

        while i > 0 {
            expand0State(key: password, p: &pSpan, s: &sSpan)
            expand0State(key: salt, p: &pSpan, s: &sSpan)
            i &-= 1
        }

        return (p, s)
    }

    @usableFromInline
    static func stream2word(data: [UInt8], j: inout Int) -> UInt32 {
        var word: UInt32 = 0

        var i = 0
        while i < 4 {
            if j >= data.count {
                j = 0
            }
            word = (word &<< 8) | UInt32(truncatingIfNeeded: data[j])
            i &+= 1
            j &+= 1
        }

        return word
    }

    @usableFromInline
    @_lifetime(&p, &s)
    static func expand0State(
        key: [UInt8],
        p: inout MutableSpan<UInt32>,
        s: inout MutableSpan<UInt32>
    ) {
        var j = 0
        var i = 0
        while i < Self.N &+ 2 {
            p[i] ^= stream2word(data: key, j: &j)
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
    @_lifetime(&p, &s)
    static func expandState(
        password: [UInt8],
        salt: [UInt8],
        p: inout MutableSpan<UInt32>,
        s: inout MutableSpan<UInt32>
    ) {
        var j = 0
        var i = 0
        while i < Self.N &+ 2 {
            p[i] ^= stream2word(data: password, j: &j)
            i &+= 1
        }

        j = 0
        i = 0
        var dataL: UInt32 = 0
        var dataR: UInt32 = 0

        while i < Self.N &+ 2 {
            dataL ^= stream2word(data: salt, j: &j)
            dataR ^= stream2word(data: salt, j: &j)
            encipher(xl: &dataL, xr: &dataR, p: p, s: s)

            p[i] = dataL
            p[i &+ 1] = dataR
            i &+= 2
        }

        i = 0
        while i < 4 {
            var k = 0
            while k < 256 {
                dataL ^= stream2word(data: salt, j: &j)
                dataR ^= stream2word(data: salt, j: &j)
                encipher(xl: &dataL, xr: &dataR, p: p, s: s)

                s[i &* 0x100 &+ k] = dataL
                s[i &* 0x100 &+ (k &+ 1)] = dataR
                k &+= 2
            }
            i &+= 1
        }
    }

    @usableFromInline
    @inline(__always)
    static func encipher(xl: inout UInt32, xr: inout UInt32, p: borrowing MutableSpan<UInt32>, s: borrowing MutableSpan<UInt32>) {
        var Xl = xl
        var Xr = xr

        Xl ^= p[unchecked: 0]

        var i = 1
        while i <= 16 {
            // F(Xr)
            let a1 = s[unchecked: Int(truncatingIfNeeded: (Xl &>> 24) & 0xff)]
            let b1 = s[unchecked: 0x100 &+ Int(truncatingIfNeeded: (Xl &>> 16) & 0xff)]
            let c1 = s[unchecked: 0x200 &+ Int(truncatingIfNeeded: (Xl &>> 8) & 0xff)]
            let d1 = s[unchecked: 0x300 &+ Int(truncatingIfNeeded: Xl & 0xff)]
            Xr ^= ((a1 &+ b1) ^ c1 &+ d1) ^ p[unchecked: i]

            // F(Xl)
            let a2 = s[unchecked: Int(truncatingIfNeeded: (Xr &>> 24) & 0xff)]
            let b2 = s[unchecked: 0x100 &+ Int(truncatingIfNeeded: (Xr &>> 16) & 0xff)]
            let c2 = s[unchecked: 0x200 &+ Int(truncatingIfNeeded: (Xr &>> 8) & 0xff)]
            let d2 = s[unchecked: 0x300 &+ Int(truncatingIfNeeded: Xr & 0xff)]
            Xl ^= ((a2 &+ b2) ^ c2 &+ d2) ^ p[unchecked: i &+ 1]

            i &+= 2
        }

        xl = Xr ^ p[unchecked: 17]
        xr = Xl
    }
}
