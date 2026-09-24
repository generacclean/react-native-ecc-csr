package com.ecccsr

import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Expo module exposing [CSRCore] to JS as `CSRModule`.
 *
 * Deliberately thin: it adapts arguments and promises and nothing else, so that all behaviour -
 * including every rejection code - stays in [CSRCore] where the unit tests cover it.
 */
class CSRModule : Module() {
  private lateinit var core: CSRCore

  // Expo runs every module's AsyncFunctions on one shared serial queue. Key generation and the
  // PKCS12 keystore read/write can take long enough (StrongBox, secp521r1) to stall unrelated
  // modules queued behind it, so this module serialises its own work on a dedicated thread.
  // Serial rather than pooled because that is what the legacy bridge gave us; CSRCore's locks
  // make concurrent calls safe, but nothing has been tested under that ordering.
  private val executor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
    Thread(runnable, "ecc-csr")
  }

  override fun definition() = ModuleDefinition {
    Name("CSRModule")

    OnCreate {
      // Constructed here rather than lazily so the process-wide BouncyCastle provider swap in
      // CSRCore's constructor happens at module creation, as it did under the legacy bridge.
      val context = appContext.reactContext ?: throw Exceptions.ReactContextLost()
      core = CSRCore(context.applicationContext)
    }

    OnDestroy {
      executor.shutdown()
    }

    AsyncFunction("generateCSR") { params: Map<String, Any?>, promise: Promise ->
      dispatch(promise) { core.generateCSR(params, it) }
    }

    AsyncFunction("getHardwareKeystoreCapabilities") { promise: Promise ->
      dispatch(promise) { core.getHardwareKeystoreCapabilities(it) }
    }

    AsyncFunction("deleteKey") { privateKeyAlias: String, promise: Promise ->
      dispatch(promise) { core.deleteKey(privateKeyAlias, it) }
    }

    AsyncFunction("keyExists") { privateKeyAlias: String, promise: Promise ->
      dispatch(promise) { core.keyExists(privateKeyAlias, it) }
    }

    AsyncFunction("getPublicKey") { privateKeyAlias: String, promise: Promise ->
      dispatch(promise) { core.getPublicKey(privateKeyAlias, it) }
    }
  }

  private fun dispatch(promise: Promise, body: (CSRCore.Reply) -> Unit) {
    val reply = object : CSRCore.Reply {
      override fun resolve(value: Any?) = promise.resolve(value)

      override fun reject(code: String, message: String?, cause: Throwable?) =
        promise.reject(code, message, cause)
    }
    executor.execute {
      try {
        body(reply)
      } catch (t: Throwable) {
        // CSRCore catches Exception at every entry point, so only Errors (e.g. a missing
        // BouncyCastle class) get here. Without this the promise would never settle.
        promise.reject("NATIVE_ERROR", t.message, t)
      }
    }
  }
}
