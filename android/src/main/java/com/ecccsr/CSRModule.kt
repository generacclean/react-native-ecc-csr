package com.ecccsr

import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

/**
 * Expo module exposing [CSRCore] to JS as `CSRModule`.
 *
 * Deliberately thin: it moves each call onto the module's thread and nothing else, so that all
 * behaviour - including every rejection code - stays in [CSRCore] where the unit tests cover it.
 * Expo settles the promise from the return value, or from the thrown [CSRException]'s code.
 */
class CSRModule : Module() {
  private lateinit var core: CSRCore

  // Expo runs every module's AsyncFunctions on one shared serial queue. Key generation and the
  // PKCS12 keystore read/write can take long enough (StrongBox, secp521r1) to stall unrelated
  // modules queued behind it, so this module serialises its own work on a dedicated thread.
  // Serial rather than pooled because that is what the legacy bridge gave us; CSRCore's locks
  // make concurrent calls safe, but nothing has been tested under that ordering.
  private val dispatcher: ExecutorCoroutineDispatcher = Executors.newSingleThreadExecutor { runnable ->
    Thread(runnable, "ecc-csr")
  }.asCoroutineDispatcher()

  override fun definition() = ModuleDefinition {
    Name("CSRModule")

    OnCreate {
      // Constructed here rather than lazily so the process-wide BouncyCastle provider swap in
      // CSRCore's constructor happens at module creation, as it did under the legacy bridge.
      val context = appContext.reactContext ?: throw Exceptions.ReactContextLost()
      core = CSRCore(context.applicationContext)
    }

    OnDestroy {
      dispatcher.close()
    }

    AsyncFunction("generateCSR") Coroutine { params: CSRParams ->
      onModuleThread { core.generateCSR(params) }
    }

    AsyncFunction("getHardwareKeystoreCapabilities") Coroutine { ->
      onModuleThread { core.getHardwareKeystoreCapabilities() }
    }

    AsyncFunction("deleteKey") Coroutine { privateKeyAlias: String ->
      onModuleThread { core.deleteKey(privateKeyAlias) }
    }

    AsyncFunction("keyExists") Coroutine { privateKeyAlias: String ->
      onModuleThread { core.keyExists(privateKeyAlias) }
    }

    AsyncFunction("getPublicKey") Coroutine { privateKeyAlias: String ->
      onModuleThread { core.getPublicKey(privateKeyAlias) }
    }
  }

  private suspend fun <T> onModuleThread(body: () -> T): T = withContext(dispatcher) {
    try {
      body()
    } catch (e: CodedException) {
      throw e
    } catch (t: Throwable) {
      // CSRCore turns every Exception into a CSRException, so only Errors (e.g. a missing
      // BouncyCastle class) get here. Kept on NATIVE_ERROR, the code they had before.
      throw CSRException(ErrorCode.NATIVE_ERROR, t.message, t)
    }
  }
}
