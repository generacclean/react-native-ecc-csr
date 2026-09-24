import ExpoModulesCore

/**
 Expo module exposing `CSRCore` to JS as `CSRModule`.

 Deliberately thin: it adapts arguments and promises and nothing else, so that all behaviour -
 including every rejection code - stays in `CSRCore`.
 */
public class CSRModule: Module {
  private let core = CSRCore()

  // Expo runs every module's AsyncFunctions on one shared serial queue. Key generation and
  // Keychain access can block long enough to stall unrelated modules queued behind it, so this
  // module serialises its own work on a dedicated queue - serial, matching the legacy bridge.
  private let queue = DispatchQueue(label: "com.ecccsr.CSRModule")

  public func definition() -> ModuleDefinition {
    Name("CSRModule")

    AsyncFunction("generateCSR") { (params: [String: Any], promise: Promise) in
      self.core.generateCSR(params, resolve: promise.resolver, reject: Self.rejecter(promise))
    }.runOnQueue(queue)

    AsyncFunction("getHardwareKeystoreCapabilities") { (promise: Promise) in
      self.core.getHardwareKeystoreCapabilities(promise.resolver, reject: Self.rejecter(promise))
    }.runOnQueue(queue)

    AsyncFunction("deleteKey") { (privateKeyAlias: String, promise: Promise) in
      self.core.deleteKey(privateKeyAlias, resolve: promise.resolver, reject: Self.rejecter(promise))
    }.runOnQueue(queue)

    AsyncFunction("keyExists") { (privateKeyAlias: String, promise: Promise) in
      self.core.keyExists(privateKeyAlias, resolve: promise.resolver, reject: Self.rejecter(promise))
    }.runOnQueue(queue)

    AsyncFunction("getPublicKey") { (privateKeyAlias: String, promise: Promise) in
      self.core.getPublicKey(privateKeyAlias, resolve: promise.resolver, reject: Self.rejecter(promise))
    }.runOnQueue(queue)
  }

  private static func rejecter(_ promise: Promise) -> CSRRejectBlock {
    return { code, message, _ in
      promise.reject(code, message ?? "")
    }
  }
}
