import ExpoModulesCore

/**
 Expo module exposing `CSRCore` to JS as `CSRModule`.

 Deliberately thin: it moves each call onto the module's queue and nothing else, so that all
 behaviour - including every rejection code - stays in `CSRCore`. Expo settles the promise from
 the return value, or from the thrown `CSRError`'s code.
 */
public class CSRModule: Module {
  private let core = CSRCore()

  // Expo runs every module's AsyncFunctions on one shared serial queue. Key generation and
  // Keychain access can block long enough to stall unrelated modules queued behind it, so this
  // module serialises its own work on a dedicated queue - serial, matching the legacy bridge.
  private let queue = DispatchQueue(label: "com.ecccsr.CSRModule")

  public func definition() -> ModuleDefinition {
    Name("CSRModule")

    AsyncFunction("generateCSR") { (params: CSRParams) in
      try self.core.generateCSR(params)
    }.runOnQueue(queue)

    AsyncFunction("getHardwareKeystoreCapabilities") {
      self.core.getHardwareKeystoreCapabilities()
    }.runOnQueue(queue)

    AsyncFunction("deleteKey") { (privateKeyAlias: String) in
      self.core.deleteKey(privateKeyAlias)
    }.runOnQueue(queue)

    AsyncFunction("keyExists") { (privateKeyAlias: String) in
      try self.core.keyExists(privateKeyAlias)
    }.runOnQueue(queue)

    AsyncFunction("getPublicKey") { (privateKeyAlias: String) in
      try self.core.getPublicKey(privateKeyAlias)
    }.runOnQueue(queue)
  }
}
