import CryptoKit
import Foundation
import Security

/// A rejection that reaches JS as `error.code` / `error.message`.
///
/// The codes are part of the JS contract (callers match on `error.code`), so treat them as API.
struct CSRError: Error {
  let code: String
  let message: String

  init(_ code: String, _ message: String) {
    self.code = code
    self.message = message
  }

  init(_ code: String, _ error: Error) {
    self.init(code, error.localizedDescription)
  }
}

/// ECC key pair and CSR generation, with no dependency on React Native or Expo.
///
/// The JS-facing module is the Expo module in CSRModule.swift, which only adapts arguments and
/// promises. Everything that decides behaviour - validation, key storage, error codes, response
/// shape - lives here. Every entry point either returns the value to resolve with or throws a
/// `CSRError`.
final class CSRCore {
  // Align defaults with Android (Generac-specific values)
  private static let defaultCountry = "US"
  private static let defaultState = "Wisconsin"
  private static let defaultLocality = "Waukesha"
  private static let defaultOrganization = "Generac Power Systems"
  private static let defaultOrganizationalUnit = "Field Pro"
  private static let defaultIPAddress = "10.10.10.10"
  private static let defaultECCCurve = "secp384r1"

  func generateCSR(_ params: [String: Any]) throws -> [String: Any] {
    // Everything is read up front so that a malformed value is rejected before a key is stored.
    let commonName = try Self.string(params, "commonName") ?? ""
    let serialNumber = try Self.string(params, "serialNumber") ?? ""
    let country = try Self.string(params, "country") ?? Self.defaultCountry
    let state = try Self.string(params, "state") ?? Self.defaultState
    let locality = try Self.string(params, "locality") ?? Self.defaultLocality
    let organization = try Self.string(params, "organization") ?? Self.defaultOrganization
    let organizationalUnit = try Self.string(params, "organizationalUnit") ?? Self.defaultOrganizationalUnit
    let ipAddress = try Self.string(params, "ipAddress") ?? Self.defaultIPAddress
    let dnsName = try Self.string(params, "dnsName")
    let curveName = try Self.string(params, "curve") ?? Self.defaultECCCurve
    let phoneInfo = try Self.string(params, "phoneInfo")
    let privateKeyAlias = try Self.string(params, "privateKeyAlias")

    // Default: false (software keys - matches Android behavior)
    // For P-256: can be set to true to try Secure Enclave
    // For P-384/P-521: always false (Secure Enclave doesn't support them)
    let useHardwareKey = try Self.bool(params, "useHardwareKey") ?? false

    if commonName.isEmpty {
      throw CSRError("INVALID_PARAM", "commonName is required")
    }

    guard let privateKeyAlias, !privateKeyAlias.isEmpty else {
      throw CSRError("INVALID_PARAM", "privateKeyAlias is required")
    }

    let curve = try Curve(name: curveName)

    let trimmedIPAddress = ipAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    if !trimmedIPAddress.isEmpty && Self.ipAddressBytes(trimmedIPAddress) == nil {
      throw CSRError("INVALID_IP", "Invalid IP address format: \(ipAddress)")
    }

    let keyPair: KeyPair
    do {
      keyPair = try generateKeyPair(curve: curve, alias: privateKeyAlias, useHardwareKey: useHardwareKey)
    } catch {
      throw CSRError("KEY_GENERATION_ERROR", error)
    }

    let publicKeyData: Data
    do {
      publicKeyData = try exportPublicKey(keyPair.publicKey)
    } catch {
      throw CSRError("PUBLIC_KEY_ERROR", error)
    }

    let csrData: Data
    do {
      csrData = try buildCSR(
        subject: [
          "CN": commonName,
          "serialNumber": serialNumber,
          "C": country,
          "ST": state,
          "L": locality,
          "O": organization,
          "OU": organizationalUnit,
        ],
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        ipAddress: ipAddress,
        dnsName: dnsName,
        phoneInfo: phoneInfo
      )
    } catch {
      throw CSRError("CSR_GENERATION_ERROR", error)
    }

    return [
      "csr": Self.convertToPEM(csrData, label: "CERTIFICATE REQUEST"),
      "privateKeyAlias": privateKeyAlias,
      "publicKey": Self.convertToPEM(publicKeyData, label: "PUBLIC KEY"),
      "isHardwareBacked": keyPair.isHardwareBacked,
      "useHardwareKey": keyPair.isHardwareBacked,
      "hardwareKeyRequested": useHardwareKey,
      "tlsCompatible": true,  // iOS Secure Enclave always supports TLS
    ]
  }

  /// Resolves true when the key is gone afterwards, including when it never existed. Keychain
  /// failures resolve false rather than rejecting, as they always have.
  func deleteKey(_ privateKeyAlias: String) -> Bool {
    let status = SecItemDelete(Self.keyQuery(privateKeyAlias) as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound
  }

  func keyExists(_ privateKeyAlias: String) -> Bool {
    var query = Self.keyQuery(privateKeyAlias)
    query[kSecReturnRef as String] = true

    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
  }

  func getPublicKey(_ privateKeyAlias: String) throws -> String {
    do {
      var query = Self.keyQuery(privateKeyAlias)
      query[kSecReturnRef as String] = true

      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)

      guard status == errSecSuccess, let item = result, CFGetTypeID(item) == SecKeyGetTypeID() else {
        throw Self.error(code: Int(status), "Key not found")
      }

      // The type ID check above is what makes this cast safe.
      guard let publicKey = SecKeyCopyPublicKey(item as! SecKey) else {
        throw Self.error(code: -1, "Could not extract public key")
      }

      return Self.convertToPEM(try exportPublicKey(publicKey), label: "PUBLIC KEY")
    } catch {
      throw CSRError("GET_PUBLIC_KEY_ERROR", error)
    }
  }

  func getHardwareKeystoreCapabilities() -> [String: Any] {
    // iOS Secure Enclave is always TLS-compatible (no SDK version gating like Android)
    // However, only P-256 is supported; P-384/P-521 fall back to software
    //
    // There is no API to ask whether a Secure Enclave is present. Every device that can run this
    // module's minimum iOS version has one (A7 and later), so report it as available.
    let model = Self.deviceModel()

    return [
      "tlsCompatible": true,  // iOS Secure Enclave always TLS-compatible
      "androidSdkVersion": 0,  // N/A for iOS
      "hasStrongBox": true,  // Secure Enclave is iOS equivalent
      "manufacturer": "Apple",
      "model": model,
      "device": model,
    ]
  }

  // MARK: - Helper Methods

  /// Reads an optional string parameter. Absent and null both mean "not provided". Any other type
  /// is rejected with EXCEPTION - the code the Objective-C implementation produced when it sent a
  /// string message to a non-string value.
  private static func string(_ params: [String: Any], _ key: String) throws -> String? {
    switch params[key] {
    case nil, is NSNull:
      return nil
    case let value as String:
      return value
    default:
      throw CSRError("EXCEPTION", "\(key) must be a string")
    }
  }

  /// Reads an optional boolean parameter, accepting what `-[NSObject boolValue]` accepted.
  private static func bool(_ params: [String: Any], _ key: String) throws -> Bool? {
    switch params[key] {
    case nil, is NSNull:
      return nil
    case let value as Bool:
      return value
    case let value as NSNumber:
      return value.boolValue
    case let value as String:
      return (value as NSString).boolValue
    default:
      throw CSRError("EXCEPTION", "\(key) must be a boolean")
    }
  }

  private static func error(code: Int, _ description: String) -> NSError {
    NSError(domain: "CSRModule", code: code, userInfo: [NSLocalizedDescriptionKey: description])
  }

  private static func keyQuery(_ alias: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
  }

  private static func deviceModel() -> String {
    var systemInfo = utsname()
    uname(&systemInfo)
    return withUnsafeBytes(of: &systemInfo.machine) { bytes in
      String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
    }
  }

  // MARK: - Key Generation

  private struct KeyPair {
    let privateKey: SecKey
    let publicKey: SecKey
    let isHardwareBacked: Bool
  }

  private func generateKeyPair(curve: Curve, alias: String, useHardwareKey: Bool) throws -> KeyPair {
    // The Keychain does not dedupe keys on tag alone, so a key left under this alias would sit
    // beside the new one and a tag lookup could return either - a cert/key mismatch, and a way
    // for a pre-2.0 backup-eligible key to survive regeneration. Refuse rather than risk that.
    let deleteStatus = SecItemDelete(Self.keyQuery(alias) as CFDictionary)
    guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
      throw Self.error(code: Int(deleteStatus), "Failed to delete existing key for alias")
    }

    let privateKeyAttrs: [String: Any] = [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: Data(alias.utf8),
      // Keeps software keys out of encrypted iTunes/Finder backups and device migration.
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]

    var privateKey: SecKey?
    var isHardwareBacked = false

    // Secure Enclave ONLY supports P-256
    // For P-384/P-521: always use software
    // For P-256: respect useHardwareKey parameter

    if curve == .p256 && useHardwareKey {
      let secureEnclaveParams: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: curve.keySize,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: privateKeyAttrs,
      ]

      var enclaveError: Unmanaged<CFError>?
      privateKey = SecKeyCreateRandomKey(secureEnclaveParams as CFDictionary, &enclaveError)

      if privateKey != nil {
        isHardwareBacked = true
        NSLog("✅ P-256 key created in Secure Enclave (hardware-backed)")
      } else {
        let reason = enclaveError.map { String(describing: $0.takeRetainedValue()) } ?? "unknown error"
        NSLog("⚠️ Secure Enclave failed (%@), falling back to software", reason)
      }
    }

    if privateKey == nil {
      let softwareParams: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: curve.keySize,
        kSecPrivateKeyAttrs as String: privateKeyAttrs,
      ]

      var cfError: Unmanaged<CFError>?
      guard let key = SecKeyCreateRandomKey(softwareParams as CFDictionary, &cfError) else {
        throw Self.takeError(cfError, "Key generation failed")
      }
      privateKey = key

      if curve == .p256 {
        NSLog("ℹ️ P-256 key created in software")
      } else {
        NSLog("ℹ️ P-%d key created in software (Secure Enclave unsupported)", curve.keySize)
      }
    }

    guard let privateKey, let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw Self.error(code: -1, "Could not extract public key")
    }

    return KeyPair(privateKey: privateKey, publicKey: publicKey, isHardwareBacked: isHardwareBacked)
  }

  private func exportPublicKey(_ publicKey: SecKey) throws -> Data {
    var cfError: Unmanaged<CFError>?
    guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &cfError) as Data? else {
      throw Self.takeError(cfError, "Public key export failed")
    }

    return Self.wrapPublicKeyInSPKI(keyData, curve: Self.curve(of: publicKey))
  }

  private static func curve(of key: SecKey) -> Curve {
    let attributes = SecKeyCopyAttributes(key) as? [String: Any]
    let keySize = (attributes?[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue
    return Curve(keySize: keySize)
  }

  private static func takeError(_ cfError: Unmanaged<CFError>?, _ fallback: String) -> Error {
    cfError?.takeRetainedValue() ?? error(code: -1, fallback)
  }

  // MARK: - CSR Building

  private func buildCSR(
    subject: [String: String],
    publicKey: SecKey,
    privateKey: SecKey,
    ipAddress: String,
    dnsName: String?,
    phoneInfo: String?
  ) throws -> Data {
    let subjectDN = Self.encodeDN(subject)
    let publicKeyInfo = try exportPublicKey(publicKey)

    let extensions = Self.buildExtensions(ipAddress: ipAddress, dnsName: dnsName, phoneInfo: phoneInfo)
    let attributes = Self.buildAttributes(extensions)

    let certRequestInfo = DER.sequence(DER.integer(0) + subjectDN + publicKeyInfo + attributes)

    let curve = Self.curve(of: publicKey)
    let signature = try Self.sign(certRequestInfo, with: privateKey, curve: curve)

    return DER.sequence(certRequestInfo + Self.encodeSignatureAlgorithm(curve) + DER.bitString(signature))
  }

  // MARK: - DN Encoding

  private static func encodeDN(_ subject: [String: String]) -> Data {
    var dn = Data()

    for key in ["C", "ST", "L", "O", "OU", "CN", "serialNumber"] {
      if let value = subject[key], !value.isEmpty {
        dn += encodeRDN(key, value: value)
      }
    }

    return DER.sequence(dn)
  }

  private static func encodeRDN(_ key: String, value: String) -> Data {
    let stringValue = key == "C" || key == "serialNumber"
      ? DER.printableString(value)
      : DER.utf8String(value)

    return DER.set(DER.sequence(DER.oid(oidForAttribute[key]!) + stringValue))
  }

  private static let oidForAttribute = [
    "C": "2.5.4.6",
    "ST": "2.5.4.8",
    "L": "2.5.4.7",
    "O": "2.5.4.10",
    "OU": "2.5.4.11",
    "CN": "2.5.4.3",
    "serialNumber": "2.5.4.5",
  ]

  // MARK: - Extensions

  private static func buildExtensions(ipAddress: String, dnsName: String?, phoneInfo: String?) -> Data {
    var extensions = buildKeyUsageExtension() + buildExtendedKeyUsageExtension()

    // Checked before trimming, so a whitespace-only dnsName/phoneInfo still produces a SAN
    // extension (possibly empty). Kept as-is: it is what every issued certificate so far has had.
    if !ipAddress.isEmpty || !(dnsName ?? "").isEmpty || !(phoneInfo ?? "").isEmpty {
      extensions += buildSubjectAltNameExtension(ipAddress: ipAddress, dnsName: dnsName, phoneInfo: phoneInfo)
    }

    return DER.sequence(extensions)
  }

  private static func buildKeyUsageExtension() -> Data {
    // BIT STRING, 3 unused bits: digitalSignature | keyAgreement
    buildExtension("2.5.29.15", critical: true, value: Data([0x03, 0x02, 0x03, 0x88]))
  }

  private static func buildExtendedKeyUsageExtension() -> Data {
    buildExtension("2.5.29.37", critical: false, value: DER.sequence(DER.oid("1.3.6.1.5.5.7.3.2")))
  }

  private static func buildSubjectAltNameExtension(ipAddress: String, dnsName: String?, phoneInfo: String?) -> Data {
    var sanData = Data()

    if let dnsName, !dnsName.isEmpty {
      for dns in dnsName.components(separatedBy: ",") {
        let trimmedDns = dns.trimmingCharacters(in: .whitespacesAndNewlines)

        if !trimmedDns.isEmpty {
          sanData += DER.tagged(0x82, Data(trimmedDns.utf8))
        }
      }
    }

    // generateCSR has already rejected a non-empty IP that does not parse.
    if let ipBytes = ipAddressBytes(ipAddress.trimmingCharacters(in: .whitespacesAndNewlines)) {
      sanData += DER.tagged(0x87, ipBytes)
    }

    if let phoneInfo, !phoneInfo.isEmpty {
      let trimmedPhoneInfo = phoneInfo.trimmingCharacters(in: .whitespacesAndNewlines)

      if !trimmedPhoneInfo.isEmpty {
        sanData += DER.tagged(0x86, Data("phone:\(trimmedPhoneInfo)".utf8))
      }
    }

    return buildExtension("2.5.29.17", critical: false, value: DER.sequence(sanData))
  }

  private static func buildExtension(_ oid: String, critical: Bool, value: Data) -> Data {
    var extensionData = DER.oid(oid)

    if critical {
      extensionData += Data([0x01, 0x01, 0xFF])
    }

    extensionData += DER.octetString(value)

    return DER.sequence(extensionData)
  }

  private static func buildAttributes(_ extensions: Data) -> Data {
    let extReqOID = DER.oid("1.2.840.113549.1.9.14")
    return DER.context(0, DER.sequence(extReqOID + DER.set(extensions)))
  }

  // MARK: - Signing

  /// The digest matches the curve's security level: SHA-256 for P-256, SHA-384 for P-384 and
  /// SHA-512 for P-521, the same pairing Android uses.
  private static func sign(_ data: Data, with privateKey: SecKey, curve: Curve) throws -> Data {
    let hash: Data
    let algorithm: SecKeyAlgorithm
    switch curve {
    case .p256:
      hash = Data(SHA256.hash(data: data))
      algorithm = .ecdsaSignatureDigestX962SHA256
    case .p384:
      hash = Data(SHA384.hash(data: data))
      algorithm = .ecdsaSignatureDigestX962SHA384
    case .p521:
      hash = Data(SHA512.hash(data: data))
      algorithm = .ecdsaSignatureDigestX962SHA512
    }

    var cfError: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
      privateKey,
      algorithm,
      hash as CFData,
      &cfError
    ) as Data? else {
      throw takeError(cfError, "Signing failed")
    }

    return signature
  }

  private static func encodeSignatureAlgorithm(_ curve: Curve) -> Data {
    DER.sequence(DER.oid(curve.signatureAlgorithmOID))
  }

  // MARK: - IP Addresses

  /// Network-order bytes of a literal IPv4 or IPv6 address, or nil when `ip` is not one. Hostnames
  /// and out-of-range octets are rejected rather than truncated, matching Android's `INVALID_IP`.
  private static func ipAddressBytes(_ ip: String) -> Data? {
    var ipv4 = in_addr()
    if inet_pton(AF_INET, ip, &ipv4) == 1 {
      return withUnsafeBytes(of: &ipv4) { Data($0) }
    }

    var ipv6 = in6_addr()
    if inet_pton(AF_INET6, ip, &ipv6) == 1 {
      return withUnsafeBytes(of: &ipv6) { Data($0) }
    }

    return nil
  }

  // MARK: - Public Key Info

  private static func wrapPublicKeyInSPKI(_ publicKeyData: Data, curve: Curve) -> Data {
    let algorithm = DER.sequence(DER.oid("1.2.840.10045.2.1") + DER.oid(curve.oid))
    return DER.sequence(algorithm + DER.bitString(publicKeyData))
  }

  // MARK: - PEM Conversion

  private static func convertToPEM(_ data: Data, label: String) -> String {
    let base64 = data.base64EncodedString(options: .lineLength64Characters)
      .replacingOccurrences(of: "\r", with: "")

    return "-----BEGIN \(label)-----\n\(base64)\n-----END \(label)-----"
  }
}

// MARK: - Curves

private enum Curve {
  case p256, p384, p521

  /// Unrecognised names are rejected, matching Android's `INVALID_CURVE`.
  init(name: String) throws {
    switch name {
    case "secp256r1": self = .p256
    case "secp384r1": self = .p384
    case "secp521r1": self = .p521
    default:
      throw CSRError("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1")
    }
  }

  init(keySize: Int?) {
    switch keySize {
    case 256: self = .p256
    case 521: self = .p521
    default: self = .p384
    }
  }

  var keySize: Int {
    switch self {
    case .p256: return 256
    case .p384: return 384
    case .p521: return 521
    }
  }

  var oid: String {
    switch self {
    case .p256: return "1.2.840.10045.3.1.7"
    case .p384: return "1.3.132.0.34"
    case .p521: return "1.3.132.0.35"
    }
  }

  /// ecdsa-with-SHA256 / SHA384 / SHA512, paired with the digest `sign(_:with:curve:)` uses.
  var signatureAlgorithmOID: String {
    switch self {
    case .p256: return "1.2.840.10045.4.3.2"
    case .p384: return "1.2.840.10045.4.3.3"
    case .p521: return "1.2.840.10045.4.3.4"
    }
  }
}

// MARK: - ASN.1 DER Encoding Primitives

enum DER {
  static func integer(_ value: UInt8) -> Data {
    Data([0x02, 0x01, value])
  }

  static func oid(_ oidString: String) -> Data {
    let components = oidString.components(separatedBy: ".").map { Int($0)! }

    var oidData = Data([UInt8(components[0] * 40 + components[1])])
    for value in components.dropFirst(2) {
      oidData += oidComponent(value)
    }

    return tagged(0x06, oidData)
  }

  private static func oidComponent(_ value: Int) -> Data {
    if value < 128 {
      return Data([UInt8(value)])
    }

    var bytes: [UInt8] = []
    var remaining = value
    while remaining > 0 {
      bytes.insert(UInt8(remaining & 0x7F), at: 0)
      remaining >>= 7
    }
    for i in 0..<(bytes.count - 1) {
      bytes[i] |= 0x80
    }

    return Data(bytes)
  }

  /// Non-ASCII input encodes as an empty PrintableString, as it did in Objective-C (where the
  /// ASCII conversion returned nil and appending nil was a no-op).
  static func printableString(_ string: String) -> Data {
    tagged(0x13, string.data(using: .ascii) ?? Data())
  }

  static func utf8String(_ string: String) -> Data {
    tagged(0x0C, Data(string.utf8))
  }

  static func octetString(_ data: Data) -> Data {
    tagged(0x04, data)
  }

  /// BIT STRING with no unused bits.
  static func bitString(_ data: Data) -> Data {
    tagged(0x03, Data([0x00]) + data)
  }

  static func sequence(_ data: Data) -> Data {
    tagged(0x30, data)
  }

  static func set(_ data: Data) -> Data {
    tagged(0x31, data)
  }

  static func context(_ tag: UInt8, _ data: Data) -> Data {
    tagged(0xA0 | tag, data)
  }

  static func tagged(_ tag: UInt8, _ content: Data) -> Data {
    Data([tag]) + length(content.count) + content
  }

  static func length(_ length: Int) -> Data {
    if length < 128 {
      return Data([UInt8(length)])
    }

    var bytes: [UInt8] = []
    var remaining = length
    while remaining > 0 {
      bytes.insert(UInt8(remaining & 0xFF), at: 0)
      remaining >>= 8
    }

    return Data([0x80 | UInt8(bytes.count)] + bytes)
  }
}
