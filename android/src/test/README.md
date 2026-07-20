# Unit Tests for react-native-ecc-csr

This directory contains unit tests for the Android native module.

## Test Structure

```
android/src/test/java/com/ecccsr/
├── BouncyCastleProviderTest.java  - Tests BC provider initialization
├── InputValidationTest.java       - Tests input validation logic
└── CSRFormatTest.java             - Tests CSR format and X500 names
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

## Dependencies

Tests use:
- **JUnit 4.13.2** - Test framework
- **Mockito 5.3.1** - Mocking framework (for future tests)
- **Robolectric 4.10.3** - Android framework simulation (for future tests)

## What's NOT Tested (Requires Hardware/Emulator)

These require full Android environment and cannot run as unit tests:
- Actual key generation
- Hardware keystore operations
- Android Keystore access
- PKCS12 keystore file operations
- React Native bridge calls
- File I/O with app context
- Concurrent operations

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
| Input Validation | ~80% | ✅ Excellent |
| CSR Format | ~40% | ⚠️ Basic |
| Key Generation | 0% | ❌ Needs hardware tests |
| Encryption | 0% | ❌ Needs hardware tests |
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
