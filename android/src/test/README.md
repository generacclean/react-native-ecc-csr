# Unit Tests for react-native-ecc-csr

This directory contains unit tests for the Android native module.

## Test Structure

```
android/src/test/java/com/ecccsr/
├── BouncyCastleProviderTest.java  - Tests BC provider initialization
├── InputValidationTest.java       - Tests input validation logic (delegates to CSRModule)
├── CSRFormatTest.java             - Tests CSR format and X500 names
├── CSRModuleTest.java             - Tests CSRModule directly: CSR generation, key lifecycle,
│                                    keystore round-trip, corruption recovery, capabilities
└── testutil/
    ├── FakeReactApplicationContext.java - Minimal ReactApplicationContext for Robolectric tests
    └── RecordingPromise.java            - Captures resolve/reject calls for assertions
```

## Running Tests

### From Command Line

```bash
# Run all tests
cd android
./gradlew test

# Run specific test class
./gradlew test --tests com.ecccsr.BouncyCastleProviderTest

# Run with verbose output
./gradlew test --info

# Generate HTML report
./gradlew test
# Report will be at: android/build/reports/tests/test/index.html
```

### From Android Studio

1. Right-click on `android/src/test/java/com/ecccsr/` folder
2. Select "Run 'Tests in com.ecccsr'"
3. View results in the Run panel

## Test Categories

### BouncyCastleProviderTest
Tests the BouncyCastle cryptographic provider:
- Provider registration
- EC algorithm support
- ECDSA signature support
- Provider class verification
- Version checking
- Priority handling

### InputValidationTest
Tests input validation for:
- IPv4 addresses (valid and invalid)
- IPv6 addresses
- Curve names (secp256r1, secp384r1, secp521r1)
- Key aliases
- DN value sanitization

### CSRFormatTest
Tests CSR format handling:
- X500Name building
- Special character escaping
- PEM format validation
- Default values
- Unicode handling
- Filename sanitization

### CSRModuleTest
Tests `CSRModule` directly via Robolectric, exercising real production code
(the same logic the `@ReactMethod` entry points call, minus the RN bridge's
`WritableMap` serialization step, which needs a native JNI library unavailable
in this JVM-only test environment):
- CSR generation for P-256/P-384/P-521 with a parseable, correctly-signed CSR
- Key lifecycle: create → keyExists → getPublicKey → deleteKey → keyExists
- Software keystore round-trip: write then reload the PKCS12 file
- Corruption handling: corrupt keystore quarantine and `.corrupted` retention cap
- Input validation (IP address, curve, alias) against the real production methods
- Hardware capability detection across SDK versions

## Dependencies

Tests use:
- **JUnit 4.13.2** - Test framework
- **Mockito 5.3.1** - Mocking framework (for future tests)
- **Robolectric 4.10.3** - Android framework simulation, used by `CSRModuleTest`
  and `InputValidationTest` to instantiate `CSRModule` with a fake
  `ReactApplicationContext` (see `testutil/FakeReactApplicationContext.java`)

## What's NOT Tested (Requires Hardware/Emulator)

Key generation, PKCS12 keystore round-trips, and corruption recovery now run
as JVM unit tests via Robolectric (see `CSRModuleTest`). What's still out of
scope for this suite and requires a full Android environment:
- Actual Android Keystore (hardware-backed) key generation and StrongBox
- React Native bridge serialization (`Arguments.createMap()` / `WritableNativeMap`,
  which require a native JNI library not available in a JVM-only test run)
- Concurrent operations under real thread scheduling

For these, see: `/TESTING_GUIDE.md`

## Adding New Tests

### 1. Create a new test file

```java
package com.ecccsr;

import org.junit.Test;
import static org.junit.Assert.*;

public class MyNewTest {
    @Test
    public void testSomething() {
        // Arrange
        int expected = 5;
        
        // Act
        int actual = 2 + 3;
        
        // Assert
        assertEquals("Sum should be 5", expected, actual);
    }
}
```

### 2. Run the test

```bash
./gradlew test --tests com.ecccsr.MyNewTest
```

### 3. Check coverage

```bash
./gradlew jacocoTestReport
# Report at: android/build/reports/jacoco/test/html/index.html
```

## Best Practices

1. **Use AAA Pattern**: Arrange, Act, Assert
2. **One assertion per test** (when possible)
3. **Descriptive test names**: `testMethodName_condition_expectedResult`
4. **Test edge cases**: null, empty, invalid inputs
5. **Clean up**: Use `@Before` and `@After` for setup/teardown
6. **Don't test Android SDK**: Focus on YOUR code logic

## Continuous Integration

These tests are designed to run in CI without requiring:
- Android emulator
- Physical device
- React Native runtime
- Full Android SDK (just JDK needed)

Perfect for GitHub Actions, Jenkins, etc.

## Current Test Coverage

| Component | Coverage | Status |
|-----------|----------|--------|
| BC Provider Init | ~60% | ✅ Good |
| Input Validation | ~80% | ✅ Excellent (delegates to production `CSRModule` methods) |
| CSR Format | ~40% | ⚠️ Basic |
| Key Generation (software) | ✅ Covered | ✅ Good (`CSRModuleTest`, via Robolectric) |
| Key Generation (hardware/StrongBox) | 0% | ❌ Needs real-device/emulator tests |
| Keystore round-trip / corruption recovery | ✅ Covered | ✅ Good (`CSRModuleTest`) |
| Concurrency | 0% | ❌ Needs integration tests |

## Next Steps

1. **Add Mockito tests** for CSRModule methods
2. **Add Robolectric tests** for Android-specific code
3. **Add integration tests** in separate directory
4. **Set up CI pipeline** to run tests automatically

## Troubleshooting

### Tests won't run
```bash
# Make sure you have the gradle wrapper
ls -la android/ | grep gradle

# If missing, regenerate
cd android
gradle wrapper
```

### Dependencies not found
```bash
# Sync gradle
cd android
./gradlew build --refresh-dependencies
```

### JVM version issues
```bash
# Check Java version (needs 8+)
java -version

# Set JAVA_HOME if needed
export JAVA_HOME=/path/to/jdk
```

## Resources

- [JUnit 4 Documentation](https://junit.org/junit4/)
- [Mockito Documentation](https://site.mockito.org/)
- [Robolectric Documentation](http://robolectric.org/)
- [Android Testing Guide](https://developer.android.com/training/testing)
