package com.ecccsr

import com.ecccsr.testutil.FakeContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

/**
 * Unit tests for input validation. Every assertion delegates to the real CSRCore
 * validator (isValidIPAddress / isValidCurve / isValidAlias / sanitizeDNValue) rather
 * than re-declaring the logic, so these tests fail if production behavior changes.
 */
@RunWith(RobolectricTestRunner::class)
class InputValidationTest {

  private lateinit var module: CSRCore

  @Before
  fun setUp() {
    module = CSRCore(FakeContext(RuntimeEnvironment.getApplication()))
  }

  private fun isValidIPAddress(ip: String?): Boolean = module.isValidIPAddress(ip)

  @Test
  fun testValidIPv4Addresses() {
    assertTrue("192.168.1.1 should be valid", isValidIPAddress("192.168.1.1"))
    assertTrue("10.0.0.1 should be valid", isValidIPAddress("10.0.0.1"))
    assertTrue("172.16.0.1 should be valid", isValidIPAddress("172.16.0.1"))
    assertTrue("127.0.0.1 should be valid", isValidIPAddress("127.0.0.1"))
    assertTrue("0.0.0.0 should be valid", isValidIPAddress("0.0.0.0"))
    assertTrue("255.255.255.255 should be valid", isValidIPAddress("255.255.255.255"))
  }

  @Test
  fun testInvalidIPv4Addresses() {
    assertFalse("999.999.999.999 should be invalid", isValidIPAddress("999.999.999.999"))
    assertFalse("256.1.1.1 should be invalid", isValidIPAddress("256.1.1.1"))
    assertFalse("1.256.1.1 should be invalid", isValidIPAddress("1.256.1.1"))
    assertFalse("1.1.256.1 should be invalid", isValidIPAddress("1.1.256.1"))
    assertFalse("1.1.1.256 should be invalid", isValidIPAddress("1.1.1.256"))
  }

  @Test
  fun testInvalidIPFormats() {
    assertFalse("not-an-ip should be invalid", isValidIPAddress("not-an-ip"))
    assertFalse("192.168.1 should be invalid", isValidIPAddress("192.168.1"))
    assertFalse("192.168.1.1.1 should be invalid", isValidIPAddress("192.168.1.1.1"))
    assertFalse("192.168.-1.1 should be invalid", isValidIPAddress("192.168.-1.1"))
    assertFalse("192..168.1.1 should be invalid", isValidIPAddress("192..168.1.1"))
  }

  @Test
  fun testNullAndEmptyIP() {
    assertFalse("null should be invalid", isValidIPAddress(null))
    assertFalse("empty string should be invalid", isValidIPAddress(""))
    assertFalse("whitespace should be invalid", isValidIPAddress("   "))
  }

  @Test
  fun testIPWithWhitespace() {
    assertTrue(
      "IP with leading space should be valid after trim",
      isValidIPAddress(" 192.168.1.1"),
    )
    assertTrue(
      "IP with trailing space should be valid after trim",
      isValidIPAddress("192.168.1.1 "),
    )
    assertTrue(
      "IP with surrounding spaces should be valid after trim",
      isValidIPAddress("  192.168.1.1  "),
    )
  }

  @Test
  fun testIPv6Addresses() {
    // IPv6 should also be supported
    assertTrue(
      "IPv6 localhost should be valid",
      isValidIPAddress("::1"),
    )
    assertTrue(
      "IPv6 address should be valid",
      isValidIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
    )
    assertTrue(
      "IPv6 compressed should be valid",
      isValidIPAddress("2001:db8::1"),
    )
  }

  @Test
  fun testHostnames() {
    // Hostnames should be rejected for IP address field
    // The isValidIPAddress() method verifies that the input is a literal IP address
    // by comparing it to the resolved address, preventing hostname injection
    assertFalse(
      "localhost should be rejected as a non-literal hostname",
      isValidIPAddress("localhost"),
    )
    assertFalse(
      "example.com should be rejected as a hostname",
      isValidIPAddress("example.com"),
    )
    assertFalse(
      "www.google.com should be rejected as a hostname",
      isValidIPAddress("www.google.com"),
    )
  }

  @Test
  fun testCurveValidation() {
    // Test curve name validation
    assertTrue("secp256r1 should be valid", isValidCurve("secp256r1"))
    assertTrue("secp384r1 should be valid", isValidCurve("secp384r1"))
    assertTrue("secp521r1 should be valid", isValidCurve("secp521r1"))

    assertFalse("invalid-curve should be invalid", isValidCurve("invalid-curve"))
    assertFalse("secp256k1 should be invalid", isValidCurve("secp256k1"))
    assertFalse("null should be invalid", isValidCurve(null))
    assertFalse("empty should be invalid", isValidCurve(""))
  }

  private fun isValidCurve(curve: String?): Boolean = module.isValidCurve(curve)

  @Test
  fun testAliasValidation() {
    // Test key alias validation
    assertTrue("Valid alias should pass", isValidAlias("my-key-123"))
    assertTrue("Alias with underscore should pass", isValidAlias("my_key"))
    assertTrue("Alias with dots should pass", isValidAlias("com.example.key"))

    assertFalse("null alias should fail", isValidAlias(null))
    assertFalse("empty alias should fail", isValidAlias(""))
    assertFalse("whitespace alias should fail", isValidAlias("   "))
  }

  @Test
  fun testTrimmingFollowsJavaStringTrimRules() {
    // CSRCore trims the way java.lang.String#trim does: every char <= U+0020, and nothing else.
    // Kotlin's trim() differs in both directions, and would change which aliases are accepted
    // and the alias an existing key is looked up under.
    assertFalse("control-char-only alias should fail", isValidAlias("\u0000\t"))
    assertTrue("NBSP-only alias is not blank to String#trim", isValidAlias("\u00A0"))
    assertEquals("Should strip control chars", "Test", module.sanitizeDNValue("\u0000Test\u001F"))
    assertEquals("Should keep NBSP", "\u00A0Test\u00A0", module.sanitizeDNValue("\u00A0Test\u00A0"))
  }

  private fun isValidAlias(alias: String?): Boolean = module.isValidAlias(alias)

  @Test
  fun testDNValueSanitization() {
    // Test DN value sanitization against the real production method
    assertEquals("Should trim whitespace", "Test", module.sanitizeDNValue("  Test  "))
    assertEquals("Should handle null", "", module.sanitizeDNValue(null))
    assertEquals("Should handle empty", "", module.sanitizeDNValue(""))
    assertEquals("Should preserve special chars", "Test,Inc.", module.sanitizeDNValue("Test,Inc."))
  }
}
