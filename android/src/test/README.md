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
    ├── FakeReactApplicationContext.java - Minimal ReactApplicationContext for Robolectric tests,
    │                                      with hooks to make no-backup storage unavailable or
    │                                      unwritable (see "Simulating storage failures")
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

# Force execution when Gradle considers the task up to date
./gradlew test --rerun-tasks
```

`./gradlew test` prints `BUILD SUCCESSFUL` without running anything when Gradle judges the task
up to date, which is easy to mistake for a passing run — especially when checking that a change
actually breaks a test. Use `--rerun-tasks`, or read the counts out of
`android/build/test-results/testDebugUnitTest/*.xml`.

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
- Backup exclusion: the keystore lives in `getNoBackupFilesDir()`, and legacy copies in
  `getFilesDir()` (keystore, `.tmp`, and quarantined `.corrupted.*` files in both the flat
  and `keystore_forensics/` layouts) are relocated out of backup-eligible storage
- Migration failure modes: when the no-backup directory is unavailable or cannot be written to,
  `keyExists`, `getPublicKey`, `deleteKey` and `generateCSR` all fail loudly instead of reporting
  "no key" (which would shadow an existing key with an empty keystore and trigger a silent
  re-enrolment). Each entry point is asserted separately, because each has its own broad `catch`
  that the location failure has to escape.
- Downgrade then upgrade: a legacy keystore *newer* than the no-backup one wins the migration
  rather than being deleted as stale, and the copy it supersedes is quarantined as
  `.superseded.*`. If that quarantine cannot be performed, the migration fails instead of
  deleting the newer key. Identical modification times are covered separately: the downgrade
  tests put the stamps a minute apart, which only exercises the case where the filesystem's
  mtime resolution can rank the two files at all, so a third test stages an exact tie — the
  pair a one- or two-second-resolution filesystem would report — and asserts both keys survive.
- Corruption handling: corrupt keystore quarantine and `.corrupted` retention cap
- Input validation (IP address, curve, alias) against the real production methods
- Hardware capability detection across SDK versions

#### Simulating storage failures

The two hooks on `FakeReactApplicationContext` are what make the no-backup storage tests
assertions rather than skips:

- `setNoBackupFilesDirUnavailable(true)` — `getNoBackupFilesDir()` returns null, the platform's
  way of saying it has no such directory.
- `setNoBackupFilesDirOverride(dir)` — points the module at another directory. Tests pass a path
  whose parent is a **regular file**, so every create and rename underneath it fails on any
  filesystem and for any user. Do not reach for `File.setWritable(false)` instead: it is a silent
  no-op when the test runs as root, so a permission-based version of these tests passes (or
  `assumeTrue`-skips) on containerised CI runners without ever exercising the failure path — and
  the failure path is the headline behaviour of this change.

Tests that assert a rejection assert on `CSRModule.KeystoreLocationException` specifically, not on
`Exception`. Under Robolectric the hardware keystore is absent, so almost any hardware-path call
throws *something*; only the exception type distinguishes "storage is broken, we stopped" from
"this environment has no AndroidKeyStore".

## Dependencies

Tests use:
- **JUnit 4.13.2** - Test framework
- **Mockito 5.3.1** - Mocking framework, used by `CSRModuleTest` to `mockStatic` the
  RN `Arguments` factory, which otherwise needs a native JNI library
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
3. **Descriptive test names**: `test` + camelCase describing condition and expected result, e.g.
   `testNoBackupDirUnavailableMakesGetPublicKeyRejectInsteadOfReportingKeyNotFound`. No
   underscores — SonarQube rule `java:S100` enforces `^[a-z][a-zA-Z0-9]*$` for method names, so
   the `testMethod_condition_result` convention fails the quality gate.
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
| No-backup storage / legacy keystore migration | ✅ Covered | ✅ Good (`CSRModuleTest`) |
| Concurrency | 0% | ❌ Needs integration tests |

Robolectric tests run at API 33, pinned in `resources/robolectric.properties` and dependent on
`testOptions.unitTests.includeAndroidResources` in `android/build.gradle`. Removing either drops
Robolectric into legacy resources mode and back to its API 16 floor, where it skips or fails
anything using a platform API newer than API 16. `AndroidManifest.xml` in this directory exists only
to override react-android's `minSdkVersion 24` for the test variant; it is not published.

## Next Steps

Mockito and Robolectric coverage of `CSRModule` and a blocking CI pipeline
(`.github/workflows/android-tests.yml`) are in place. What's left:

1. **Add instrumented tests** in a separate directory for the hardware-keystore paths
   listed under "What's NOT Tested" above
2. **Add iOS test coverage** — `ios/CSRModule.m` is verified manually only

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
