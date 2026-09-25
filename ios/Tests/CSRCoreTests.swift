import ExpoModulesCore
import Security
import XCTest

@testable import react_native_ecc_csr

final class CSRCoreTests: XCTestCase {
  private let core = CSRCore()
  private var alias = ""

  override func setUp() {
    super.setUp()
    alias = "csr_core_tests_\(UUID().uuidString)"
  }

  override func tearDown() {
    _ = core.deleteKey(alias)
    super.tearDown()
  }

  private func params(_ configure: (inout CSRParams) -> Void = { _ in }) -> CSRParams {
    var params = CSRParams()
    params.commonName = "test-device"
    params.privateKeyAlias = alias
    configure(&params)
    return params
  }

  /// Converts `dict` the way Expo converts a JS object argument.
  private func params(from dict: [String: Any]) throws -> CSRParams {
    try CSRParams(from: dict, appContext: AppContext())
  }

  // MARK: - Validation

  func testMissingCommonNameIsRejected() {
    assertRejects("INVALID_PARAM", params { $0.commonName = "" })
  }

  func testMissingAliasIsRejected() {
    assertRejects("INVALID_PARAM", params { $0.privateKeyAlias = nil })
    assertRejects("INVALID_PARAM", params { $0.privateKeyAlias = "" })
  }

  func testUnknownCurveIsRejected() {
    assertRejects("INVALID_CURVE", params { $0.curve = "secp192r1" })
  }

  func testInvalidIPAddressIsRejected() {
    for ip in ["not-an-ip", "256.1.1.1", "10.10.10", "example.com"] {
      assertRejects("INVALID_IP", params { $0.ipAddress = ip }, ip)
    }
  }

  func testWrongTypedParamIsRejectedByTheConverter() {
    XCTAssertThrowsError(try params(from: ["commonName": ["test-device"], "privateKeyAlias": alias]))
    XCTAssertThrowsError(try params(from: ["commonName": "test-device", "useHardwareKey": ["yes"]]))
  }

  func testRejectedParamsStoreNoKey() {
    assertRejects("INVALID_IP", params { $0.ipAddress = "not-an-ip" })
    XCTAssertFalse(try core.keyExists(alias))
  }

  /// Expo hands a JS object to the converter with `null` properties as NSNull and `undefined` ones
  /// dropped (EXJSIConversions.mm). Both must mean "not provided", as they do on Android.
  func testNullParamsTakeDefaults() throws {
    let converted = try params(from: [
      "commonName": "test-device",
      "privateKeyAlias": alias,
      "curve": NSNull(),
      "country": NSNull(),
      "ipAddress": NSNull(),
      "useHardwareKey": NSNull(),
    ])
    XCTAssertNil(converted.curve)
    XCTAssertNil(converted.country)
    XCTAssertNil(converted.ipAddress)
    XCTAssertNil(converted.useHardwareKey)

    let result = try core.generateCSR(converted)
    let csr = try CSR(pem: result.csr)
    XCTAssertEqual(csr.signatureAlgorithmOID, "1.2.840.10045.4.3.3", "Default curve is P-384")
    XCTAssertFalse(result.hardwareKeyRequested)
  }

  // MARK: - Signature digest per curve

  func testP256CSRIsSignedWithSHA256() throws {
    try assertSignature(curve: "secp256r1", oid: "1.2.840.10045.4.3.2", verifyWith: .ecdsaSignatureMessageX962SHA256)
  }

  func testP384CSRIsSignedWithSHA384() throws {
    try assertSignature(curve: "secp384r1", oid: "1.2.840.10045.4.3.3", verifyWith: .ecdsaSignatureMessageX962SHA384)
  }

  func testP521CSRIsSignedWithSHA512() throws {
    try assertSignature(curve: "secp521r1", oid: "1.2.840.10045.4.3.4", verifyWith: .ecdsaSignatureMessageX962SHA512)
  }

  func testResultShape() throws {
    let result = try core.generateCSR(params()).toDictionary(appContext: nil)
    XCTAssertEqual(result["privateKeyAlias"] as? String, alias)
    XCTAssertEqual(result["isHardwareBacked"] as? Bool, false)
    XCTAssertEqual(result["useHardwareKey"] as? Bool, false)
    XCTAssertEqual(result["hardwareKeyRequested"] as? Bool, false)
    XCTAssertEqual(result["tlsCompatible"] as? Bool, true)
    XCTAssertNil(result["keystore"], "iOS keys live in the Keychain, not a file")
    XCTAssertTrue((result["csr"] as? String)?.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n") ?? false)
    XCTAssertTrue((result["publicKey"] as? String)?.hasPrefix("-----BEGIN PUBLIC KEY-----\n") ?? false)
  }

  // MARK: - Keychain lifecycle

  func testKeyLifecycle() throws {
    XCTAssertFalse(try core.keyExists(alias))

    let result = try core.generateCSR(params())
    XCTAssertTrue(try core.keyExists(alias))
    XCTAssertEqual(try core.getPublicKey(alias), result.publicKey)

    XCTAssertTrue(core.deleteKey(alias))
    XCTAssertFalse(try core.keyExists(alias))
    XCTAssertThrowsError(try core.getPublicKey(alias)) { error in
      XCTAssertEqual((error as? CSRError)?.code, "KEY_NOT_FOUND")
    }
  }

  func testDeletingMissingKeySucceeds() {
    XCTAssertTrue(core.deleteKey(alias))
  }

  func testRegeneratingReplacesTheKey() throws {
    _ = try core.generateCSR(params { $0.curve = "secp256r1" })
    let second = try core.generateCSR(params { $0.curve = "secp384r1" })

    XCTAssertEqual(try core.getPublicKey(alias), second.publicKey)

    // Exactly one key is left under the alias.
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnRef as String: true,
    ]
    var items: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &items), errSecSuccess)
    XCTAssertEqual((items as? [Any])?.count, 1)
  }

  func testSoftwareKeysAreThisDeviceOnly() throws {
    _ = try core.generateCSR(params())

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecReturnAttributes as String: true,
    ]
    var attributes: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &attributes), errSecSuccess)
    let accessible = (attributes as? [String: Any])?[kSecAttrAccessible as String] as? String
    XCTAssertEqual(accessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
  }

  // MARK: - Helpers

  private func assertRejects(
    _ code: String, _ params: CSRParams, _ context: String = "",
    file: StaticString = #filePath, line: UInt = #line
  ) {
    XCTAssertThrowsError(try core.generateCSR(params), context, file: file, line: line) { error in
      XCTAssertEqual((error as? CSRError)?.code, code, "\(context) \(error)", file: file, line: line)
    }
  }

  private func assertSignature(
    curve: String, oid: String, verifyWith algorithm: SecKeyAlgorithm,
    file: StaticString = #filePath, line: UInt = #line
  ) throws {
    let result = try core.generateCSR(params { $0.curve = curve })
    let csr = try CSR(pem: result.csr)
    XCTAssertEqual(csr.signatureAlgorithmOID, oid, file: file, line: line)

    let publicKey = try publicKey(fromPEM: result.publicKey)
    var error: Unmanaged<CFError>?
    let valid = SecKeyVerifySignature(
      publicKey, algorithm, csr.certificationRequestInfo as CFData, csr.signature as CFData, &error)
    XCTAssertTrue(valid, "Signature does not verify: \(String(describing: error?.takeRetainedValue()))",
                  file: file, line: line)
  }

  private func publicKey(fromPEM pem: String?) throws -> SecKey {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let spki = try DERReader(try pemBody(pem)).sequence()
    var fields = DERReader(spki)
    _ = try fields.element(tag: 0x30)
    let bitString = try fields.element(tag: 0x03)
    let point = bitString.dropFirst()  // unused-bits byte

    var error: Unmanaged<CFError>?
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
    ]
    guard let key = SecKeyCreateWithData(Data(point) as CFData, attributes as CFDictionary, &error) else {
      throw error!.takeRetainedValue()
    }
    return key
  }
}

// MARK: - Minimal DER parsing

private struct TestError: Error, CustomStringConvertible {
  let description: String
}

private func pemBody(_ pem: String?) throws -> Data {
  guard let pem else { throw TestError(description: "No PEM") }
  let base64 = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
  guard let data = Data(base64Encoded: base64) else { throw TestError(description: "Bad base64") }
  return data
}

/// CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature }
private struct CSR {
  let certificationRequestInfo: Data
  let signatureAlgorithmOID: String
  let signature: Data

  init(pem: String?) throws {
    var fields = DERReader(try DERReader(try pemBody(pem)).sequence())
    certificationRequestInfo = try fields.rawElement(tag: 0x30)
    var algorithm = DERReader(try fields.element(tag: 0x30))
    signatureAlgorithmOID = Self.decodeOID(try algorithm.element(tag: 0x06))
    signature = Data(try fields.element(tag: 0x03).dropFirst())  // unused-bits byte
  }

  private static func decodeOID(_ bytes: Data) -> String {
    let bytes = [UInt8](bytes)
    var components = [Int(bytes[0]) / 40, Int(bytes[0]) % 40]
    var value = 0
    for byte in bytes.dropFirst() {
      value = (value << 7) | Int(byte & 0x7F)
      if byte & 0x80 == 0 {
        components.append(value)
        value = 0
      }
    }
    return components.map(String.init).joined(separator: ".")
  }
}

private struct DERReader {
  private let bytes: [UInt8]
  private var offset = 0

  init(_ data: Data) {
    bytes = [UInt8](data)
  }

  /// The content of the single top-level SEQUENCE.
  func sequence() throws -> Data {
    var reader = self
    return try reader.element(tag: 0x30)
  }

  mutating func element(tag: UInt8) throws -> Data {
    let (_, contentStart, end) = try header(tag: tag)
    offset = end
    return Data(bytes[contentStart..<end])
  }

  /// The element including its tag and length, as signed.
  mutating func rawElement(tag: UInt8) throws -> Data {
    let (start, _, end) = try header(tag: tag)
    offset = end
    return Data(bytes[start..<end])
  }

  private func header(tag: UInt8) throws -> (Int, Int, Int) {
    guard offset + 2 <= bytes.count, bytes[offset] == tag else {
      throw TestError(description: "Expected tag \(tag) at \(offset)")
    }
    var cursor = offset + 1
    var length = Int(bytes[cursor])
    cursor += 1
    if length & 0x80 != 0 {
      let count = length & 0x7F
      length = 0
      for _ in 0..<count {
        length = (length << 8) | Int(bytes[cursor])
        cursor += 1
      }
    }
    guard cursor + length <= bytes.count else { throw TestError(description: "Truncated element") }
    return (offset, cursor, cursor + length)
  }
}
