import ExpoModulesCore

/// Every code a CSRModule promise can reject with. The raw values are part of the JS contract
/// (callers match on `error.code`), so treat them as API: rename one and a caller silently stops
/// matching.
enum CSRErrorCode: String {
  case invalidParam = "INVALID_PARAM"
  case invalidCurve = "INVALID_CURVE"
  case invalidIP = "INVALID_IP"
  case keyGenerationError = "KEY_GENERATION_ERROR"
  case publicKeyError = "PUBLIC_KEY_ERROR"
  case csrGenerationError = "CSR_GENERATION_ERROR"
  case keyExistsError = "KEY_EXISTS_ERROR"
  case keyNotFound = "KEY_NOT_FOUND"
  case getPublicKeyError = "GET_PUBLIC_KEY_ERROR"
}

/// A rejection that reaches JS as `error.code` / `error.message`. An Expo `Exception`, so Expo
/// rejects the promise with `code` when it is thrown from a module function.
final class CSRError: Exception, @unchecked Sendable {
  let errorCode: CSRErrorCode
  private let message: String

  init(_ errorCode: CSRErrorCode, _ message: String) {
    self.errorCode = errorCode
    self.message = message
    super.init()
  }

  convenience init(_ errorCode: CSRErrorCode, _ error: Error) {
    self.init(errorCode, error.localizedDescription)
  }

  override var code: String {
    errorCode.rawValue
  }

  override var reason: String {
    message
  }
}
