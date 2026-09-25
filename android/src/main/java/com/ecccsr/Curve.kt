package com.ecccsr

/**
 * The EC curves the module supports, each with its standard name (what JS passes and what
 * ECGenParameterSpec takes) and the signature algorithm for its CSR.
 *
 * The digest matches the curve's security level. Hardware keys are generated with all three
 * digests allowed (see CSRCore.generateHardwareKeyPair), so this holds for both key paths.
 */
internal enum class Curve(val keystoreName: String, val signatureAlgorithm: String) {
  P256("secp256r1", "SHA256withECDSA"),
  P384("secp384r1", "SHA384withECDSA"),
  P521("secp521r1", "SHA512withECDSA");

  companion object {
    /** Null for anything that is not a supported curve name, including null. */
    fun fromName(name: String?): Curve? = entries.firstOrNull { it.keystoreName == name }

    /** For rejection messages: "secp256r1, secp384r1, secp521r1". */
    val names: String = entries.joinToString { it.keystoreName }
  }
}
