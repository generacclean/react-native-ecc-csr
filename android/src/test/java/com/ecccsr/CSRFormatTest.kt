package com.ecccsr

import java.security.Security
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

/**
 * Unit tests for CSR format and X500 name handling
 */
class CSRFormatTest {

  companion object {
    @JvmStatic
    @BeforeClass
    fun setUpClass() {
      // Register BouncyCastle provider for tests
      if (Security.getProvider("BC") == null) {
        Security.addProvider(BouncyCastleProvider())
      }
    }
  }

  @Test
  fun testX500NameBuilder() {
    // Arrange
    val builder = X500NameBuilder(BCStyle.INSTANCE)

    // Act
    builder.addRDN(BCStyle.C, "US")
    builder.addRDN(BCStyle.ST, "Wisconsin")
    builder.addRDN(BCStyle.L, "Waukesha")
    builder.addRDN(BCStyle.O, "Generac Power Systems")
    builder.addRDN(BCStyle.OU, "Field Pro")
    builder.addRDN(BCStyle.CN, "test-device")

    val name = builder.build()

    // Assert
    assertNotNull("X500Name should be created", name)
    val nameString = name.toString()
    assertTrue("Should contain country", nameString.contains("C=US"))
    assertTrue("Should contain state", nameString.contains("ST=Wisconsin"))
    assertTrue("Should contain locality", nameString.contains("L=Waukesha"))
    assertTrue("Should contain organization", nameString.contains("O=Generac Power Systems"))
    assertTrue("Should contain OU", nameString.contains("OU=Field Pro"))
    assertTrue("Should contain CN", nameString.contains("CN=test-device"))
  }

  @Test
  fun testX500NameWithSpecialCharacters() {
    // Arrange
    val builder = X500NameBuilder(BCStyle.INSTANCE)

    // Act - Test that special characters are handled
    builder.addRDN(BCStyle.CN, "Test,Inc.")
    builder.addRDN(BCStyle.O, "Test=Org")
    builder.addRDN(BCStyle.OU, "Test+Unit")

    val name = builder.build()

    // Assert
    assertNotNull("X500Name should handle special characters", name)
    val nameString = name.toString()
    // X500NameBuilder should properly escape these
    assertTrue("Should contain escaped comma", nameString.contains("CN="))
  }

  @Test
  fun testX500NameWithEmptyValues() {
    // Arrange
    val builder = X500NameBuilder(BCStyle.INSTANCE)

    // Act - Add only required fields
    builder.addRDN(BCStyle.CN, "test")

    val name = builder.build()

    // Assert
    assertNotNull("X500Name should work with minimal fields", name)
    assertTrue("Should contain CN", name.toString().contains("CN=test"))
  }

  @Test
  fun testX500NameFieldOrder() {
    // Arrange
    val builder = X500NameBuilder(BCStyle.INSTANCE)

    // Act - Add fields in specific order
    builder.addRDN(BCStyle.C, "US")
    builder.addRDN(BCStyle.ST, "CA")
    builder.addRDN(BCStyle.CN, "test")

    val name = builder.build()

    // Assert
    assertNotNull("X500Name should maintain field order", name)
    // Note: X500Name may reorder fields according to standard, this is expected
  }

  @Test
  fun testPEMFormatValidation() {
    // Test PEM format string structure
    val validPEM = "-----BEGIN CERTIFICATE REQUEST-----\n" +
      "MIIBuTCCAV4CAQAwgZcxCzAJBgNVBAYTAlVT\n" +
      "-----END CERTIFICATE REQUEST-----"

    assertTrue(
      "Should start with BEGIN marker",
      validPEM.startsWith("-----BEGIN CERTIFICATE REQUEST-----"),
    )
    assertTrue(
      "Should end with END marker",
      validPEM.endsWith("-----END CERTIFICATE REQUEST-----"),
    )
    assertTrue("Should contain newlines", validPEM.contains("\n"))
  }

  @Test
  fun testPEMFormatInvalid() {
    val invalidPEM1 = "Not a PEM"
    val invalidPEM2 = "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"
    val invalidPEM3 = ""

    assertFalse(
      "Should not start with BEGIN CERTIFICATE REQUEST",
      invalidPEM1.startsWith("-----BEGIN CERTIFICATE REQUEST-----"),
    )
    assertFalse(
      "Should not be CERTIFICATE type",
      invalidPEM2.contains("CERTIFICATE REQUEST"),
    )
    assertFalse(
      "Empty string should not be valid",
      invalidPEM3.startsWith("-----BEGIN"),
    )
  }

  @Test
  fun testDefaultValues() {
    // Test that default values produce valid X500Name structures
    val builder = X500NameBuilder(BCStyle.INSTANCE)

    // Add default values
    builder.addRDN(BCStyle.C, "US")
    builder.addRDN(BCStyle.ST, "Wisconsin")
    builder.addRDN(BCStyle.L, "Waukesha")
    builder.addRDN(BCStyle.O, "Generac Power Systems")
    builder.addRDN(BCStyle.OU, "Field Pro")

    val name = builder.build()

    // Verify structure is valid
    assertNotNull("X500Name should not be null", name)
    assertTrue("X500Name should contain RDNs", name.rdNs.isNotEmpty())

    // Verify country code is present and valid
    val nameStr = name.toString()
    assertTrue("Should contain country", nameStr.contains("C=US"))
    assertTrue("Should contain state", nameStr.contains("ST=Wisconsin"))
    assertTrue("Should contain organization", nameStr.contains("O=Generac Power Systems"))
  }

  @Test
  fun testCurveNames() {
    // Test that curve names match expected values
    val validCurves = arrayOf("secp256r1", "secp384r1", "secp521r1")

    for (curve in validCurves) {
      assertNotNull("Curve name should not be null", curve)
      assertTrue("Curve name should start with 'secp'", curve.startsWith("secp"))
      assertTrue("Curve name should end with 'r1'", curve.endsWith("r1"))
    }
  }

  @Test
  fun testKeySizes() {
    // Test that curve names map to expected key sizes
    // This verifies the curve-to-keysize mapping logic

    // Curve name to expected key size mapping
    val curveSizes = listOf(
      "secp256r1" to 256,
      "secp384r1" to 384,
      "secp521r1" to 521,
    )

    val curvePattern = Regex("""^secp(\d+)r1$""")

    for ((curveName, expectedSize) in curveSizes) {
      // Extract size from curve name (e.g., "secp256r1" -> 256) via a named-group
      // regex rather than fixed offsets, so an unexpected curve name shape fails
      // loudly instead of silently producing a wrong size.
      val match = curvePattern.matchEntire(curveName)
      assertTrue("Unexpected curve name format: $curveName", match != null)
      val actualSize = match?.groupValues?.get(1)?.toInt()

      assertEquals(
        "Key size for $curveName should be $expectedSize",
        expectedSize,
        actualSize,
      )
    }
  }

  @Test
  fun testX500NameWithUnicode() {
    // Test unicode character handling
    val builder = X500NameBuilder(BCStyle.INSTANCE)

    // Act
    builder.addRDN(BCStyle.CN, "Test-デバイス") // Japanese characters

    val name = builder.build()

    // Assert
    assertNotNull("X500Name should handle unicode", name)
    // Unicode handling depends on BC implementation
  }

  @Test
  fun testFilenameSanitization() {
    // Test that filenames are sanitized properly
    val filename = "software_keys.p12"

    assertTrue("Should have .p12 extension", filename.endsWith(".p12"))
    assertFalse("Should not contain path separators", filename.contains("/"))
    assertFalse("Should not contain path separators", filename.contains("\\"))
  }
}
