# Bcrypt

[![Swift 6.4](https://img.shields.io/badge/Swift-6.4-F05138?logo=swift&logoColor=white)](https://www.swift.org)
[![Documentation](https://img.shields.io/badge/docs-DocC-blue)](https://swiftpackageindex.com/ptoffy/bcrypt/documentation/bcrypt)

A native, dependency and Foundation free Swift implementation of the bcrypt password hashing algorithm, based on the [OpenBSD implementation](https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c).

## Installation

```swift
.package(url: "https://github.com/ptoffy/bcrypt.git", from: "0.4.0")
```

```swift
.product(name: "Bcrypt", package: "bcrypt")
```

## Usage

```swift
import Bcrypt

let password = "password"
let hash = try Bcrypt.hash(password: password)
let isValid = try Bcrypt.verify(password: password, against: hash)
```

> [!NOTE]
> Hashing passwords longer than 72 characters will result in a `.passwordTooLong` error, whereas verifying them will result in the excess characters being ignored.

## Performance

Benchmarks for hashing the password "password" at cost factor 12 using the 
```swift
func hash(
    password: Span<UInt8>,
    cost: Int = 10,
    salt: Span<UInt8>,
    version: BcryptVariant = .v2b,
    into output: inout OutputSpan<UInt8>
) throws(BcryptError)
```
API, compared to Vapor's C bcrypt ([vapor/authentication](https://github.com/vapor/authentication)) and the Rust [bcrypt](https://crates.io/crates/bcrypt) crate, measured on an Apple M5 Pro. The Swift rows use the [benchmark](https://github.com/ordo-one/benchmark) package; the Rust row uses `bcrypt::hash` (the `String`-returning API) in a plain timing loop with a counting global allocator, `lto = true` and `codegen-units = 1` for release.

| | Release ms | Debug ms | Allocations Release | Allocations Debug |
|------|------------|----------|---------------------|-------------------|
| bcrypt | 149ms | 440ms | 0 | 0 |
| vapor/authentication | 170ms | 270ms | 11 | 181 |
| bcrypt (Rust 0.17) | 170ms | 650ms | 7 | 7 |

## Security Information

### Versions

A bcrypt hash starts with a version prefix, chosen with the `version` parameter when hashing. All three compute exactly the same hash from the same password and salt; they differ only in the prefix and in how passwords longer than 72 bytes are treated.

| Prefix | `BcryptVariant` | Origin | Passwords over 72 bytes |
|--------|-----------------|--------|-------------------------|
| `$2b$` | `.v2b` (default) | OpenBSD, 2014 | Rejected with `passwordTooLong` |
| `$2y$` | `.v2y` | PHP `password_hash`, Apache `htpasswd` | Rejected with `passwordTooLong` |
| `$2a$` | `.v2a` | Original 1999 revision | Silently truncated |

`verify` accepts any of the three and keeps the prefix. Use the default unless you need to emit hashes for a system that only accepts a specific prefix.

### Cost

The cost is the base-2 logarithm of the number of key schedule rounds, so every increment doubles the time to hash and to verify. It ranges from 4 to 31; on an Apple M5 Pro in release builds:

| Cost | Time |
|------|------|
| 4 | ~0.6 ms |
| 10 (default) | ~37 ms |
| 12 | ~150 ms |
| 14 | ~600 ms |
| 31 | ~22 hours |

At this time 12 is considered a reasonable default cost factor for balancing security and performance. The cost is stored on the hash so verification of old hashes continues to work even if the default cost is increased in the future.

### RNG

Bcrypt relies on a secure random number generator (RNG) to generate salts for hashing passwords. This package currently uses `SystemRandomNumberGenerator`.

### Zeroization

Zeroization is the process of securely erasing sensitive data from memory, usually by overwriting it with zeros or random data before deallocating the memory. After using it, bcrypt zeroizes the key state which is derived from the password to ensure that no sensitive information remains in memory. The password itself is never copied so wiping it is the caller's responsibility.
