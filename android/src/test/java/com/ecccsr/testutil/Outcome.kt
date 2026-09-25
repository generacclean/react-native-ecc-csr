package com.ecccsr.testutil

import com.ecccsr.CSRCore
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
 * Runs a CSRCore call and returns how it settled. Every test goes through this, so a change to
 * how CSRCore reports results only has to be reflected here.
 */
fun settle(call: (CSRCore.Reply) -> Unit): Outcome {
  var outcome: Outcome? = null
  call(object : CSRCore.Reply {
    override fun resolve(value: Any?) {
      check(outcome == null) { "Settled twice" }
      outcome = Outcome.Resolved(value)
    }

    override fun reject(code: String, message: String?, cause: Throwable?) {
      check(outcome == null) { "Settled twice" }
      outcome = Outcome.Rejected(code, message, cause)
    }
  })
  return outcome ?: fail("CSRCore call returned without settling") as Nothing
}
