# ``Bcrypt``

A native, dependency-free Swift implementation of the bcrypt password hashing function.

## Overview

bcrypt is the password hashing function designed by Niels Provos and David Mazières for OpenBSD. It derives a key
from the password and a 128-bit salt with the EksBlowfish key schedule, whose cost grows exponentially with a
tunable work factor, and encodes the result as a 60-character string that carries its own version, cost and salt:

```
$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
\__/\/ \____________________/\_____________________________/
Alg Cost      Salt                        Hash
```

This package is a port of the OpenBSD implementation. It produces hashes that are byte-for-byte interchangeable with OpenBSD, PHP, Apache `htpasswd` and every other conforming implementation.

### Hashing and verifying

```swift
import Bcrypt

let hash = try Bcrypt.hash(password: "correct horse battery staple", cost: 12)
// "$2b$12$..."

let ok = try Bcrypt.verify(password: "correct horse battery staple", against: hash)
// true
```

`hash` picks a random salt and returns the full 60-character string; store it as-is. `verify` reads the version, cost
and salt back out of the stored hash, recomputes it, and compares in constant time. Because the cost is stored in the
hash, you can raise the default for new passwords at any time and old hashes keep verifying.

Both functions have `String`, `[UInt8]` and `Span<UInt8>` overloads. The `Span` overloads and
``Bcrypt/Bcrypt/hash(password:cost:salt:version:into:)`` do not allocate.

### Settings strings

``Bcrypt/Bcrypt/hash(password:settings:)-(String,_)`` is the `crypt(3)`-style interface: instead of separate `cost`,
`salt` and `version` arguments it takes a *settings* string, the `$2x$NN$` prefix plus the 22-character salt, which is
exactly the first 29 characters of a hash. Passing the prefix of an existing hash recomputes that hash.

```swift
let stored = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
let settings = String(stored.prefix(29))
let recomputed = try Bcrypt.hash(password: "password", settings: settings)
```

### Errors

Every failure is a ``BcryptError`` describing a problem with the input. A password that simply does not match is not
an error; `verify` returns `false`.

## Topics

### Essentials

- ``Bcrypt/Bcrypt``
- <doc:SecurityConsiderations>

### Supporting types

- ``BcryptVariant``
- ``BcryptError``
