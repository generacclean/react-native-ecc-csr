import ExpoModulesCore

/// The argument of `generateCSR`, mirroring `CSRParams` in src/index.ts.
///
/// Every field is optional and `CSRCore` applies the real defaults. That way an absent property,
/// an `undefined` one and an explicit `null` all mean "not provided", on iOS and Android alike. A
/// wrongly-typed value is rejected by Expo's converter before CSRCore runs.
///
/// `curve` stays a String rather than an Enumerable: Expo would reject an unknown value with its
/// own code before CSRCore runs, and callers match on INVALID_CURVE.
struct CSRParams: Record {
  @Field var country: String?
  @Field var state: String?
  @Field var locality: String?
  @Field var organization: String?
  @Field var organizationalUnit: String?
  @Field var commonName: String?
  @Field var serialNumber: String?
  @Field var ipAddress: String?
  @Field var dnsName: String?
  @Field var curve: String?
  @Field var privateKeyAlias: String?
  @Field var phoneInfo: String?
  @Field var useHardwareKey: Bool?
}

/// What `generateCSR` resolves with, mirroring `CSRResult` in src/index.ts.
struct CSRResult: Record {
  @Field var csr: String = ""
  @Field var privateKeyAlias: String = ""
  @Field var publicKey: String = ""
  @Field var isHardwareBacked: Bool = false
  @Field var useHardwareKey: Bool = false
  @Field var hardwareKeyRequested: Bool = false
  @Field var tlsCompatible: Bool = false
}

/// What `getHardwareKeystoreCapabilities` resolves with, mirroring `HardwareKeystoreCapabilities`
/// in src/index.ts.
struct HardwareKeystoreCapabilities: Record {
  @Field var tlsCompatible: Bool = false
  @Field var androidSdkVersion: Int = 0
  @Field var hasStrongBox: Bool = false
  @Field var manufacturer: String = ""
  @Field var model: String = ""
  @Field var device: String = ""
}
