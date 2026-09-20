/// The namespace for hashing and verifying passwords with bcrypt.
///
/// Use ``hash(password:cost:version:)-(String,_,_)`` to hash a new password with a random salt, and
/// ``verify(password:against:)-(String,_)`` to check a password against a stored hash. Both have overloads
/// for `[UInt8]` and `Span<UInt8>`; the `Span` overloads and ``hash(password:cost:salt:version:into:)`` do not
/// allocate.
///
/// ```swift
/// let hash = try Bcrypt.hash(password: "correct horse battery staple", cost: 12)
/// let ok = try Bcrypt.verify(password: "correct horse battery staple", against: hash)
/// ```
///
/// Passwords are limited to 72 bytes when hashing and truncated to 72 bytes when verifying; the cost must be
/// between 4 and 31. See <doc:SecurityConsiderations> for the reasoning behind these and the other
/// security-relevant choices in this implementation.
public enum Bcrypt: Sendable {}
