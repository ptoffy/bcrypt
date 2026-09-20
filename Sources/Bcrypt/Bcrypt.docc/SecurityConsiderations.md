# Security Considerations

How this implementation handles versions, cost, randomness and memory.

## Overview

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
