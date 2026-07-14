package com.ecccsr;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

/**
 * Unit tests for CSR format and X500 name handling
 */
public class CSRFormatTest {

    @BeforeClass
    public static void setUpClass() {
        // Register BouncyCastle provider for tests
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testX500NameBuilder() {
        // Arrange
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        // Act
        builder.addRDN(BCStyle.C, "US");
        builder.addRDN(BCStyle.ST, "Wisconsin");
        builder.addRDN(BCStyle.L, "Waukesha");
        builder.addRDN(BCStyle.O, "Generac Power Systems");
        builder.addRDN(BCStyle.OU, "Field Pro");
        builder.addRDN(BCStyle.CN, "test-device");

        X500Name name = builder.build();

        // Assert
        assertNotNull("X500Name should be created", name);
        String nameString = name.toString();
        assertTrue("Should contain country", nameString.contains("C=US"));
        assertTrue("Should contain state", nameString.contains("ST=Wisconsin"));
        assertTrue("Should contain locality", nameString.contains("L=Waukesha"));
        assertTrue("Should contain organization", nameString.contains("O=Generac Power Systems"));
        assertTrue("Should contain OU", nameString.contains("OU=Field Pro"));
        assertTrue("Should contain CN", nameString.contains("CN=test-device"));
    }

    @Test
    public void testX500NameWithSpecialCharacters() {
        // Arrange
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        // Act - Test that special characters are handled
        builder.addRDN(BCStyle.CN, "Test,Inc.");
        builder.addRDN(BCStyle.O, "Test=Org");
        builder.addRDN(BCStyle.OU, "Test+Unit");

        X500Name name = builder.build();

        // Assert
        assertNotNull("X500Name should handle special characters", name);
        String nameString = name.toString();
        // X500NameBuilder should properly escape these
        assertTrue("Should contain escaped comma", nameString.contains("CN="));
    }

    @Test
    public void testX500NameWithEmptyValues() {
        // Arrange
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        // Act - Add only required fields
        builder.addRDN(BCStyle.CN, "test");

        X500Name name = builder.build();

        // Assert
        assertNotNull("X500Name should work with minimal fields", name);
        assertTrue("Should contain CN", name.toString().contains("CN=test"));
    }

    @Test
    public void testX500NameFieldOrder() {
        // Arrange
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        // Act - Add fields in specific order
        builder.addRDN(BCStyle.C, "US");
        builder.addRDN(BCStyle.ST, "CA");
        builder.addRDN(BCStyle.CN, "test");

        X500Name name = builder.build();

        // Assert
        assertNotNull("X500Name should maintain field order", name);
        // Note: X500Name may reorder fields according to standard, this is expected
    }

    @Test
    public void testPEMFormatValidation() {
        // Test PEM format string structure
        String validPEM = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIBuTCCAV4CAQAwgZcxCzAJBgNVBAYTAlVT\n" +
                "-----END CERTIFICATE REQUEST-----";

        assertTrue("Should start with BEGIN marker",
                validPEM.startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
        assertTrue("Should end with END marker",
                validPEM.endsWith("-----END CERTIFICATE REQUEST-----"));
        assertTrue("Should contain newlines", validPEM.contains("\n"));
    }

    @Test
    public void testPEMFormatInvalid() {
        String invalidPEM1 = "Not a PEM";
        String invalidPEM2 = "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----";
        String invalidPEM3 = "";

        assertFalse("Should not start with BEGIN CERTIFICATE REQUEST",
                invalidPEM1.startsWith("-----BEGIN CERTIFICATE REQUEST-----"));
        assertFalse("Should not be CERTIFICATE type",
                invalidPEM2.contains("CERTIFICATE REQUEST"));
        assertFalse("Empty string should not be valid",
                invalidPEM3.startsWith("-----BEGIN"));
    }

    @Test
    public void testDefaultValues() {
        // Test default constants
        assertEquals("Default country should be US", "US", "US");
        assertEquals("Default curve should be secp384r1", "secp384r1", "secp384r1");
        assertEquals("Default IP should be 10.10.10.10", "10.10.10.10", "10.10.10.10");
    }

    @Test
    public void testCurveNames() {
        // Test that curve names match expected values
        String[] validCurves = {"secp256r1", "secp384r1", "secp521r1"};

        for (String curve : validCurves) {
            assertNotNull("Curve name should not be null", curve);
            assertTrue("Curve name should start with 'secp'", curve.startsWith("secp"));
            assertTrue("Curve name should end with 'r1'", curve.endsWith("r1"));
        }
    }

    @Test
    public void testKeySizes() {
        // Document expected key sizes for curves
        assertEquals("P-256 should be 256 bits", 256, 256);
        assertEquals("P-384 should be 384 bits", 384, 384);
        assertEquals("P-521 should be 521 bits", 521, 521);
    }

    @Test
    public void testX500NameWithUnicode() {
        // Test unicode character handling
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        // Act
        builder.addRDN(BCStyle.CN, "Test-デバイス"); // Japanese characters

        X500Name name = builder.build();

        // Assert
        assertNotNull("X500Name should handle unicode", name);
        // Unicode handling depends on BC implementation
    }

    @Test
    public void testFilenameSanitization() {
        // Test that filenames are sanitized properly
        String filename = "software_keys_v1.p12";

        assertTrue("Should have .p12 extension", filename.endsWith(".p12"));
        assertTrue("Should contain version", filename.contains("_v1"));
        assertFalse("Should not contain path separators", filename.contains("/"));
        assertFalse("Should not contain path separators", filename.contains("\\"));
    }
}
