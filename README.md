# Bcrypt

A native, dependency and Foundation free Swift implementation of the bcrypt password hashing algorithm, based on the [OpenBSD implementation](https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c).

## Installation

```swift
.package(url: "https://github.com/ptoffy/bcrypt.git", branch: "main")
```

```swift
.product(name: "Bcrypt", package: "bcrypt")
```

## Usage

```swift
import Bcrypt

let password = "password"
let hash = try Bcrypt.hash(password: password)
let isValid = try Bcrypt.verify(password: password, hash: hash)
```

## Performance

Benchmarks for hashing the password "password" at cost factor 12 using the 
```swift
func hash(
    password: Span<UInt8>,
    cost: Int = 10,
    salt: Span<UInt8>,
    version: BcryptVersion = .v2b,
    into output: inout OutputSpan<UInt8>
) throws(BcryptError)
```
API, compared to Vapor's C bcrypt ([vapor/authentication](https://github.com/vapor/authentication)), measured on an Apple M5 Pro with the [benchmark](https://github.com/ordo-one/benchmark) package.

| | Release ms | Debug ms | Allocations Release | Allocations Debug |
|------|------------|----------|---------------------|-------------------|
| vapor/authentication | 170ms | 270ms | 11 | 181 |
| bcrypt | 149ms | 440ms | 0 | 0 |
