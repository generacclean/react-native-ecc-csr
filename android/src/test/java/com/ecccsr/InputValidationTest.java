package com.ecccsr;

import org.junit.Test;
import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.Assert.*;

/**
 * Unit tests for input validation
 */
public class InputValidationTest {

    private boolean isValidIPAddress(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return false;
        }
        try {
            String trimmed = ip.trim();
            InetAddress addr = InetAddress.getByName(trimmed);

            // Verify input is a literal IP address, not a hostname that resolved
            // For IPv6, strip brackets for comparison
            String resolvedAddr = addr.getHostAddress();
            String inputForComparison = trimmed.replace("[", "").replace("]", "");

            return resolvedAddr.equals(trimmed) || resolvedAddr.equals(inputForComparison);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    @Test
    public void testValidIPv4Addresses() {
        assertTrue("192.168.1.1 should be valid", isValidIPAddress("192.168.1.1"));
        assertTrue("10.0.0.1 should be valid", isValidIPAddress("10.0.0.1"));
        assertTrue("172.16.0.1 should be valid", isValidIPAddress("172.16.0.1"));
        assertTrue("127.0.0.1 should be valid", isValidIPAddress("127.0.0.1"));
        assertTrue("0.0.0.0 should be valid", isValidIPAddress("0.0.0.0"));
        assertTrue("255.255.255.255 should be valid", isValidIPAddress("255.255.255.255"));
    }

    @Test
    public void testInvalidIPv4Addresses() {
        assertFalse("999.999.999.999 should be invalid", isValidIPAddress("999.999.999.999"));
        assertFalse("256.1.1.1 should be invalid", isValidIPAddress("256.1.1.1"));
        assertFalse("1.256.1.1 should be invalid", isValidIPAddress("1.256.1.1"));
        assertFalse("1.1.256.1 should be invalid", isValidIPAddress("1.1.256.1"));
        assertFalse("1.1.1.256 should be invalid", isValidIPAddress("1.1.1.256"));
    }

    @Test
    public void testInvalidIPFormats() {
        assertFalse("not-an-ip should be invalid", isValidIPAddress("not-an-ip"));
        assertFalse("192.168.1 should be invalid", isValidIPAddress("192.168.1"));
        assertFalse("192.168.1.1.1 should be invalid", isValidIPAddress("192.168.1.1.1"));
        assertFalse("192.168.-1.1 should be invalid", isValidIPAddress("192.168.-1.1"));
        assertFalse("192..168.1.1 should be invalid", isValidIPAddress("192..168.1.1"));
    }

    @Test
    public void testNullAndEmptyIP() {
        assertFalse("null should be invalid", isValidIPAddress(null));
        assertFalse("empty string should be invalid", isValidIPAddress(""));
        assertFalse("whitespace should be invalid", isValidIPAddress("   "));
    }

    @Test
    public void testIPWithWhitespace() {
        assertTrue("IP with leading space should be valid after trim",
                isValidIPAddress(" 192.168.1.1"));
        assertTrue("IP with trailing space should be valid after trim",
                isValidIPAddress("192.168.1.1 "));
        assertTrue("IP with surrounding spaces should be valid after trim",
                isValidIPAddress("  192.168.1.1  "));
    }

    @Test
    public void testIPv6Addresses() {
        // IPv6 should also be supported
        assertTrue("IPv6 localhost should be valid",
                isValidIPAddress("::1"));
        assertTrue("IPv6 address should be valid",
                isValidIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assertTrue("IPv6 compressed should be valid",
                isValidIPAddress("2001:db8::1"));
    }

    @Test
    public void testHostnames() {
        // Hostnames should be rejected for IP address field
        // The isValidIPAddress() method verifies that the input is a literal IP address
        // by comparing it to the resolved address, preventing hostname injection
        assertFalse("localhost should be rejected as a non-literal hostname",
                isValidIPAddress("localhost"));
        assertFalse("example.com should be rejected as a hostname",
                isValidIPAddress("example.com"));
        assertFalse("www.google.com should be rejected as a hostname",
                isValidIPAddress("www.google.com"));
    }

    @Test
    public void testCurveValidation() {
        // Test curve name validation
        assertTrue("secp256r1 should be valid", isValidCurve("secp256r1"));
        assertTrue("secp384r1 should be valid", isValidCurve("secp384r1"));
        assertTrue("secp521r1 should be valid", isValidCurve("secp521r1"));

        assertFalse("invalid-curve should be invalid", isValidCurve("invalid-curve"));
        assertFalse("secp256k1 should be invalid", isValidCurve("secp256k1"));
        assertFalse("null should be invalid", isValidCurve(null));
        assertFalse("empty should be invalid", isValidCurve(""));
    }

    private boolean isValidCurve(String curve) {
        if (curve == null || curve.trim().isEmpty()) {
            return false;
        }
        return curve.equals("secp256r1") ||
               curve.equals("secp384r1") ||
               curve.equals("secp521r1");
    }

    @Test
    public void testAliasValidation() {
        // Test key alias validation
        assertTrue("Valid alias should pass", isValidAlias("my-key-123"));
        assertTrue("Alias with underscore should pass", isValidAlias("my_key"));
        assertTrue("Alias with dots should pass", isValidAlias("com.example.key"));

        assertFalse("null alias should fail", isValidAlias(null));
        assertFalse("empty alias should fail", isValidAlias(""));
        assertFalse("whitespace alias should fail", isValidAlias("   "));
    }

    private boolean isValidAlias(String alias) {
        return alias != null && !alias.trim().isEmpty();
    }

    @Test
    public void testDNValueSanitization() {
        // Test DN value sanitization
        assertEquals("Should trim whitespace", "Test", sanitizeDNValue("  Test  "));
        assertEquals("Should handle null", "", sanitizeDNValue(null));
        assertEquals("Should handle empty", "", sanitizeDNValue(""));
        assertEquals("Should preserve special chars", "Test,Inc.", sanitizeDNValue("Test,Inc."));
    }

    private String sanitizeDNValue(String value) {
        if (value == null) {
            return "";
        }
        return value.trim();
    }
}
