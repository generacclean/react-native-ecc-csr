package com.ecccsr.testutil

import com.ecccsr.CSRException
import org.junit.Assert.assertEquals
import org.junit.Assert.fail

/** How a CSRCore call settled. */
sealed interface Outcome {
  data class Resolved(val value: Any?) : Outcome
  data class Rejected(val code: String, val message: String?, val cause: Throwable?) : Outcome

  /** The resolved value, failing the test if the call rejected. */
  fun value(): Any? = when (this) {
    is Resolved -> value
    is Rejected -> fail("Expected resolve, got reject $code: $message") as Nothing
  }

  @Suppress("UNCHECKED_CAST")
  fun map(): Map<String, Any?> = value() as Map<String, Any?>

  /** The rejection, failing the test if the call resolved or rejected with another code. */
  fun rejected(expectedCode: String): Rejected = when (this) {
    is Rejected -> also { assertEquals("Rejection code (message: $message)", expectedCode, code) }
    is Resolved -> fail("Expected reject $expectedCode, got resolve $value") as Nothing
  }
}

/**
 * Runs a CSRCore call and returns how it settled: resolved with its return value, or rejected
 * with the code of the CSRException it threw - the same mapping Expo applies to the promise.
 */
fun settle(call: () -> Any?): Outcome = try {
  Outcome.Resolved(call())
} catch (e: CSRException) {
  Outcome.Rejected(e.code, e.message, e.cause)
}
