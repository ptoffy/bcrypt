/// A native Swift implementation of the bcrypt password hashing function.
///
/// bcrypt derives a key from a password and a 128-bit salt with the EksBlowfish key schedule, whose cost
/// grows exponentially with the `cost` parameter, and encodes the result as a 60-character modular crypt
/// string:
///
/// ```
/// $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
/// \__/\/ \____________________/\_____________________________/
/// Alg Cost      Salt                        Hash
/// ```
///
/// Use ``hash(password:cost:version:)-(String,_,_)`` to hash a new password with a random salt, and
/// ``verify(password:against:)-(String,_)`` to check a password against a stored hash. Both have overloads
/// for `[UInt8]` and `Span<UInt8>`; the `Span` overloads and
/// ``hash(password:cost:salt:version:into:)`` do not allocate.
///
/// ## Password length
///
/// bcrypt only keys on the first 72 bytes of the password (UTF-8 bytes), so anything past
/// that is not considered. To make sure no password is silently weakened, `hash` throws
/// ``BcryptError/passwordTooLong`` for longer inputs when creating ``BcryptVersion/v2b`` or
/// ``BcryptVersion/v2y`` hashes. `verify` instead truncates to 72 bytes, as OpenBSD, PHP and most other
/// implementations do when hashing, so hashes created elsewhere from longer passwords keep verifying.
///
/// A trailing NUL byte in the password is treated as the C string terminator and not counted twice.
/// An empty password is rejected with ``BcryptError/emptyPassword``.
///
/// ## Cost
///
/// `cost` is the base-2 logarithm of the number of key schedule rounds and must be between 4 and 31.
/// Each increment doubles the time to hash and to verify; cost 12 takes around 150 ms on an Apple M5 Pro.
/// The default of 10 matches other implementations; 12 or more is recommended for new deployments.
///
/// ## Salts and randomness
///
/// Salts are 16 random bytes from `SystemRandomNumberGenerator`, which is backed by the platform's
/// cryptographic random source. Callers that supply their own salt must pass the 22-character
/// bcrypt-base64 encoding; the trailing bits that do not fit into 16 bytes are ignored and the salt
/// is re-encoded in the output.
///
/// ## Timing
///
/// Verification compares the full recomputed hash against the stored one without early exit. Malformed
/// hashes are rejected before any key schedule work is done, so invalid input costs nothing. The expanded
/// Blowfish state is zeroed after each hash; the password itself is never copied, so clearing it is the
/// caller's responsibility.
public enum Bcrypt: Sendable {}
