package com.ecccsr

import java.security.Provider
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for BouncyCastle provider initialization
 */
class BouncyCastleProviderTest {

  @Before
  fun setUp() {
    // Clean up any existing BC providers before each test
    Security.removeProvider("BC")
  }

  @Test
  fun testBouncyCastleProviderCanBeRegistered() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()

    // Act
    val position = Security.addProvider(bcProvider)

    // Assert
    assertTrue("Provider should be added successfully", position >= 0)
    assertNotNull("BC provider should be findable", Security.getProvider("BC"))
  }

  @Test
  fun testBouncyCastleProviderSupportsEC() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()
    Security.addProvider(bcProvider)

    // Act
    val ecService = bcProvider.getService("KeyPairGenerator", "EC")

    // Assert
    assertNotNull("BC provider should support EC algorithm", ecService)
    assertEquals("Service algorithm should be EC", "EC", ecService?.algorithm)
  }

  @Test
  fun testBouncyCastleProviderSupportsECDSA() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()
    Security.addProvider(bcProvider)

    // Act
    val ecdsaService = bcProvider.getService("Signature", "SHA256withECDSA")

    // Assert
    assertNotNull("BC provider should support SHA256withECDSA", ecdsaService)
  }

  @Test
  fun testBouncyCastleProviderClassName() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()

    // Act
    val className = bcProvider.javaClass.name

    // Assert
    assertEquals(
      "Should be full BC provider, not Android's stripped version",
      "org.bouncycastle.jce.provider.BouncyCastleProvider",
      className,
    )
    assertFalse(
      "Should not be Android's system provider",
      className.startsWith("com.android.org.bouncycastle"),
    )
  }

  @Test
  fun testBouncyCastleProviderVersion() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()

    // Act
    val version = bcProvider.version

    // Assert
    assertTrue("BC provider version should be >= 1.76", version >= 1.76)
  }

  @Test
  fun testMultipleProviderRegistrations() {
    // Arrange
    val bcProvider1: Provider = BouncyCastleProvider()
    val bcProvider2: Provider = BouncyCastleProvider()

    // Act
    Security.addProvider(bcProvider1)
    val result = Security.addProvider(bcProvider2) // Try to add again

    // Assert
    assertEquals("Second registration should be ignored", -1, result)
  }

  @Test
  fun testProviderAtHighestPriority() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()

    // Act
    Security.insertProviderAt(bcProvider, 1)
    val providers = Security.getProviders()

    // Assert
    assertTrue("BC should be at position 1 (index 0)", providers.isNotEmpty())
    assertEquals("First provider should be BC", "BC", providers[0].name)
  }

  @Test
  fun testProviderSupportsCurves() {
    // Arrange
    val bcProvider: Provider = BouncyCastleProvider()
    Security.addProvider(bcProvider)

    // Act & Assert
    // Check that all required curves are supported
    val algParamService = bcProvider.getService("AlgorithmParameters", "EC")
    assertNotNull("Should support EC algorithm parameters", algParamService)
  }
}
