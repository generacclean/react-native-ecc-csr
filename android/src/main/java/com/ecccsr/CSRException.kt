package com.ecccsr

import expo.modules.kotlin.exception.CodedException

/**
 * Every code a CSRModule promise can reject with. The names are part of the JS contract (callers
 * match on `error.code`), so treat them as API: rename one and a caller silently stops matching.
 */
enum class ErrorCode {
  MISSING_ALIAS,
  INVALID_CURVE,
  INVALID_IP,
  CSR_GENERATION_ERROR,
  DELETE_KEY_ERROR,
  CAPABILITY_CHECK_ERROR,
  KEY_EXISTS_ERROR,
  KEY_NOT_FOUND,
  GET_PUBLIC_KEY_ERROR,

  /** Something other than an Exception (e.g. a missing BouncyCastle class) escaped CSRCore. */
  NATIVE_ERROR,
}

/**
 * A rejection that reaches JS as `error.code` / `error.message`. A [CodedException], so Expo
 * rejects the promise with [errorCode] when it is thrown from a module function.
 */
class CSRException(
  val errorCode: ErrorCode,
  message: String?,
  cause: Throwable? = null,
) : CodedException(errorCode.name, message, cause)
