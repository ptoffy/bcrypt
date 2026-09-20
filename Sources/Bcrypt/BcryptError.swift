@nonexhaustive public enum BcryptError: Error {
    case invalidSaltLength
    case invalidSalt
    case invalidHash
    case emptyPassword
    case invalidCost
    case passwordTooLong
    case invalidVersion
}
