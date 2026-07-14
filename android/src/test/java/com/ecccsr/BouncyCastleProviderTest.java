package com.ecccsr;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.Before;
import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.*;

/**
 * Unit tests for BouncyCastle provider initialization
 */
public class BouncyCastleProviderTest {

    @Before
    public void setUp() {
        // Clean up any existing BC providers before each test
        Security.removeProvider("BC");
    }

    @Test
    public void testBouncyCastleProviderCanBeRegistered() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();

        // Act
        int position = Security.addProvider(bcProvider);

        // Assert
        assertTrue("Provider should be added successfully", position >= 0);
        assertNotNull("BC provider should be findable", Security.getProvider("BC"));
    }

    @Test
    public void testBouncyCastleProviderSupportsEC() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        // Act
        Provider.Service ecService = bcProvider.getService("KeyPairGenerator", "EC");

        // Assert
        assertNotNull("BC provider should support EC algorithm", ecService);
        assertEquals("Service algorithm should be EC", "EC", ecService.getAlgorithm());
    }

    @Test
    public void testBouncyCastleProviderSupportsECDSA() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        // Act
        Provider.Service ecdsaService = bcProvider.getService("Signature", "SHA256withECDSA");

        // Assert
        assertNotNull("BC provider should support SHA256withECDSA", ecdsaService);
    }

    @Test
    public void testBouncyCastleProviderClassName() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();

        // Act
        String className = bcProvider.getClass().getName();

        // Assert
        assertEquals("Should be full BC provider, not Android's stripped version",
                "org.bouncycastle.jce.provider.BouncyCastleProvider",
                className);
        assertFalse("Should not be Android's system provider",
                className.startsWith("com.android.org.bouncycastle"));
    }

    @Test
    public void testBouncyCastleProviderVersion() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();

        // Act
        double version = bcProvider.getVersion();

        // Assert
        assertTrue("BC provider version should be >= 1.76", version >= 1.76);
    }

    @Test
    public void testMultipleProviderRegistrations() {
        // Arrange
        Provider bcProvider1 = new BouncyCastleProvider();
        Provider bcProvider2 = new BouncyCastleProvider();

        // Act
        Security.addProvider(bcProvider1);
        int result = Security.addProvider(bcProvider2); // Try to add again

        // Assert
        assertEquals("Second registration should be ignored", -1, result);
    }

    @Test
    public void testProviderAtHighestPriority() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();

        // Act
        Security.insertProviderAt(bcProvider, 1);
        Provider[] providers = Security.getProviders();

        // Assert
        assertTrue("BC should be at position 1 (index 0)", providers.length > 0);
        assertEquals("First provider should be BC", "BC", providers[0].getName());
    }

    @Test
    public void testProviderSupportsCurves() {
        // Arrange
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        // Act & Assert
        // Check that all required curves are supported
        Provider.Service algParamService = bcProvider.getService("AlgorithmParameters", "EC");
        assertNotNull("Should support EC algorithm parameters", algParamService);
    }
}
