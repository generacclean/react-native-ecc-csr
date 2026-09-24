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
      Self.settle(promise) { try self.core.generateCSR(params) }
    }.runOnQueue(queue)

    AsyncFunction("getHardwareKeystoreCapabilities") { (promise: Promise) in
      Self.settle(promise) { self.core.getHardwareKeystoreCapabilities() }
    }.runOnQueue(queue)

    AsyncFunction("deleteKey") { (privateKeyAlias: String, promise: Promise) in
      Self.settle(promise) { self.core.deleteKey(privateKeyAlias) }
    }.runOnQueue(queue)

    AsyncFunction("keyExists") { (privateKeyAlias: String, promise: Promise) in
      Self.settle(promise) { self.core.keyExists(privateKeyAlias) }
    }.runOnQueue(queue)

    AsyncFunction("getPublicKey") { (privateKeyAlias: String, promise: Promise) in
      Self.settle(promise) { try self.core.getPublicKey(privateKeyAlias) }
    }.runOnQueue(queue)
  }

  /// Rejects through `promise.reject(code, message)` rather than by throwing from the closure:
  /// a thrown error reaches JS wrapped in Expo's FunctionCallException, which replaces our code.
  private static func settle(_ promise: Promise, _ body: () throws -> Any) {
    do {
      promise.resolve(try body())
    } catch let error as CSRError {
      promise.reject(error.code, error.message)
    } catch {
      // CSRCore only throws CSRError; this keeps the promise from never settling if that changes.
      promise.reject("NATIVE_ERROR", error.localizedDescription)
    }
  }
}
