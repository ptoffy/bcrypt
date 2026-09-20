/// An error thrown by ``Bcrypt`` when a password, salt or hash cannot be processed.
@nonexhaustive public enum BcryptError: Error {
    /// A caller-supplied salt is not exactly 22 characters long.
    case invalidSaltLength
    /// A caller-supplied salt contains a character outside the bcrypt-base64 alphabet (`./A-Za-z0-9`).
    case invalidSalt
    /// The hash passed to `verify` is not 60 characters long or does not have the `$2x$nn$` prefix layout.
    case invalidHash
    /// The password is empty.
    case emptyPassword
    /// The cost is outside the range 4...31, or the two cost digits in a hash are not decimal digits.
    case invalidCost
    /// The password is longer than 72 bytes and the version is ``BcryptVersion/v2b`` or ``BcryptVersion/v2y``.
    ///
    /// Only thrown when creating a hash; `verify` truncates instead, see ``Bcrypt``.
    case passwordTooLong
    /// The hash passed to `verify` starts with a version prefix other than `$2a$`, `$2b$` or `$2y$`.
    case invalidVersion
}
