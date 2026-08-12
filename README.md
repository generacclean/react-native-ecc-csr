# React Native ECC CSR Module

A React Native module for generating Certificate Signing Requests (CSR) with Elliptic Curve Cryptography (ECC) support.

> **ℹ️ This is the Field Pro variant.** Field Pro (installer-app) consumes this `@generacclean`-scoped module from GitHub Packages — make changes here. A separate [`neurio/react-native-ecc-csr`](https://github.com/neurio/react-native-ecc-csr) exists for **PWRview** (end-of-life, git-SSH) and is not used by Field Pro.

## ⚠️ IMPORTANT SECURITY NOTICE

### Software Keystore Security (useHardwareKey=false)

**Storage:** Software-backed keys are stored in a PKCS12 file in the app's private no-backup directory (`Context.getNoBackupFilesDir()`, i.e. `/data/data/<your.package>/no_backup/software_keys.p12`). The file is protected by Android OS-level security (file permissions 0600, app sandboxing) but **not encrypted at rest**.

**Backup Exclusion (Android):** No configuration required. Android never includes `getNoBackupFilesDir()` in Auto Backup, cloud backup, or device-to-device transfer, so the private key cannot leave the device through backup infrastructure no matter what your app sets for `android:allowBackup`, `android:fullBackupContent`, or `android:dataExtractionRules`.

**iOS is different — do not read the guarantee above as cross-platform.** iOS keys live in the Keychain, not in a file, so none of the directory or manifest discussion applies. `ios/CSRModule.m` adds Keychain items without an explicit `kSecAttrAccessible` value, which means they default to `kSecAttrAccessibleWhenUnlocked` — and an *encrypted* iTunes/Finder backup **does** include items with that accessibility. Only the `…ThisDeviceOnly` variants are excluded. Secure Enclave keys (`useHardwareKey: true`) are non-exportable regardless. Treat a software-backed iOS key as backup-eligible until this module sets `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

Earlier versions shipped `backup_rules.xml` and `data_extraction_rules.xml` for the consuming app to reference from its manifest. Those files have been **removed** — the approach could not be made reliable, because `android:fullBackupContent` and `android:dataExtractionRules` each accept exactly one resource reference and nothing merges them. Any other library that claimed either attribute (`expo-secure-store`, for example) silently deactivated this module's exclusions. If your manifest or config plugin still references `@xml/backup_rules` or `@xml/data_extraction_rules` from this package, remove those references; nothing else is needed in their place.

Keys created with `useHardwareKey=true` live in the Android Keystore and are non-exportable, so they were never backup-eligible.

**Migration:** installs created before this change hold the keystore at `files/software_keys.p12`, plus any quarantined corrupt copies at `files/software_keys.p12.corrupted.<timestamp>` — each of those is a complete copy of a private key. The module moves all of them into `no_backup/` on first keystore access (quarantined copies land in `no_backup/keystore_forensics/`) and deletes the backup-eligible originals, so no action is needed from the app. If your app persists the `keystorePath` returned by `generateCSR`, re-read it rather than trusting a cached value across the upgrade — the directory changes.

**Security Recommendations:**
- ✅ **Production apps:** Use `useHardwareKey=true` on Android 12+ devices whenever possible
- ✅ **Development/Testing:** Software keys are acceptable
- ⚠️ **Older devices (Android 11-):** Software keys are supported but rely on OS-level security only
- ⚠️ **High-security requirements:** Always prefer hardware-backed keys (Android 12+)
- ⚠️ **Compliance (HIPAA/PCI DSS):** Use hardware-backed keys; software keys may not meet requirements

See [Security Considerations](#security-considerations) section below for detailed analysis.

---

## Features

- ✅ Generate CSR with ECC keys (P-256, P-384, P-521)
- ✅ Intelligent hardware vs software keystore selection
- ✅ Hardware-backed keys with TLS compatibility checks
- ✅ SHA256 signature algorithm
- ✅ Subject Alternative Name (SAN) support with IP addresses
- ✅ Full TypeScript support
- ✅ Configurable subject DN fields
- ✅ Key Usage and Extended Key Usage extensions
- ✅ Standards-compliant PKCS#10 format
- ✅ Device capability detection API

## Installation

Add the following to your package.json

```
"react-native-ecc-csr": "git@github.com:generacclean/react-native-ecc-csr.git",

```

## Quick Start

```typescript
import CSRModule from "react-native-ecc-csr";

const params = {
  country: "US",
  state: "Texas",
  locality: "Austin",
  organization: "MyOrganization",
  organizationalUnit: "MyOrganizationalUnit",
  commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
  serialNumber: "APCBPGN2202-AF250300028",
  ipAddress: "10.10.10.10",
  curve: "secp384r1",
  phoneInfo: "apple_iphone17_ios_AYEU377-E8783DE",
};

const result = await CSRModule.generateCSR(params);
console.log(result.csr); // PEM-encoded CSR
console.log(result.privateKeyAlias); // String
console.log(result.publicKey); // Base64-encoded public key
console.log(result.isHardwareBacked); // Boolean
console.log(result.tlsCompatible); // Boolean
```

## Hardware vs Software Keystore

### Intelligent Decision Making

The module **automatically decides** whether to use hardware or software keystore based on device capabilities, even if your app requests hardware keys. This ensures TLS compatibility across all devices.

#### Requirements for Hardware Keys:
- Android 12+ (API 31) for TLS/ECDH support
- Device with hardware keystore (TEE or StrongBox)

#### When Hardware is Overridden:
On Android 11 and below, hardware keys lack `PURPOSE_AGREE_KEY` support needed for TLS ECDH. The module will automatically fall back to software keys and log a warning.

### Checking Device Capabilities

```typescript
// Check if device supports hardware keys for TLS before generating CSR
const capabilities = await CSRModule.getHardwareKeystoreCapabilities();
console.log(capabilities);
// {
//   tlsCompatible: true,        // Can use hardware keys for TLS
//   androidSdkVersion: 31,       // Android 12
//   hasStrongBox: false,         // StrongBox support
//   manufacturer: "Samsung",
//   model: "SM-G991U",
//   device: "o1s"
// }

// Generate CSR with hardware preference (will be overridden if not compatible)
const result = await CSRModule.generateCSR({
  commonName: "device-001",
  privateKeyAlias: "my-key",
  useHardwareKey: true  // Preference - module decides final storage
});

// Check what actually happened
if (result.hardwareKeyRequested && !result.useHardwareKey) {
  console.log("Hardware requested but device doesn't support TLS with hardware keys");
}
```

### Response Fields

`src/index.ts` is the source of truth for these types; the block below is a commented copy of
`CSRResult` for readers browsing the docs.

```typescript
interface CSRResult {
  csr: string;                    // PEM-encoded CSR
  privateKeyAlias: string;        // Key alias
  publicKey: string;              // Base64-encoded public key
  isHardwareBacked: boolean;      // True if key is in hardware keystore
  useHardwareKey: boolean;        // Final decision (software or hardware)
  hardwareKeyRequested: boolean;  // What the app requested
  tlsCompatible: boolean;         // Device supports hardware keys for TLS
  keystore?: {                    // Android only. Present when useHardwareKey is false.
                                   // Always absent on iOS (keys live in the Keychain, not a file).
    path: string;                 // Absolute path to the PKCS12 keystore file
    password?: string;            // Always sent, always ""; optional only for forward
                                   // compatibility (see CSRKeystoreDescriptor in src/index.ts)
    format: 'pkcs12';
  };
}
```

## API Reference

### `generateCSR(params: CSRParams): Promise<CSRResult>`

Generates a Certificate Signing Request with the specified parameters.

#### Parameters

| Parameter            | Type    | Required | Default       | Description                                         |
| -------------------- | ------- | -------- | ------------- | --------------------------------------------------- |
| `commonName`         | string  | Yes      | -             | Common Name (CN) for the certificate                |
| `country`            | string  | No       | "US"          | Country code (C)                                    |
| `state`              | string  | No       | "Colorado"    | State or province (ST)                              |
| `locality`           | string  | No       | "Denver"      | Locality or city (L)                                |
| `organization`       | string  | No       | "MyOrg"       | Organization name (O)                               |
| `organizationalUnit` | string  | No       | "MyOrgUnit"   | Organizational unit (OU)                            |
| `serialNumber`       | string  | No       | ""            | Serial number                                       |
| `ipAddress`          | string  | No       | "10.10.10.10" | IP address for SAN extension                        |
| `curve`              | ECCurve | No       | "secp384r1"   | ECC curve: "secp256r1", "secp384r1", or "secp521r1" |
| `phoneInfo`          | string  | No       | ""            | PhoneInfo                                           |
| `privateKeyAlias`    | string  | Yes      | -             | Unique alias for the key pair                       |
| `useHardwareKey`     | boolean | No       | false         | Request hardware keystore (module decides final)    |

#### Returns

`Promise<CSRResult>` — see [Response Fields](#response-fields) above for the field-by-field
breakdown.

### `getHardwareKeystoreCapabilities(): Promise<HardwareKeystoreCapabilities>`

Checks if the device supports hardware-backed keys for TLS. Call this before requesting hardware keys.

#### Returns

```typescript
{
  tlsCompatible: boolean;        // Can use hardware keys for TLS (Android 12+)
  androidSdkVersion: number;     // Android SDK version
  hasStrongBox: boolean;         // Device has StrongBox secure element
  manufacturer: string;          // Device manufacturer (e.g., "Samsung")
  model: string;                 // Device model (e.g., "SM-G991U")
  device: string;                // Device codename
}
```

### `deleteKey(privateKeyAlias: string): Promise<boolean>`

Deletes a key from both hardware and software keystores.

### `keyExists(privateKeyAlias: string): Promise<boolean>`

Checks if a key exists in either hardware or software keystore.

### `getPublicKey(privateKeyAlias: string): Promise<string>`

Retrieves the public key for a given alias from either keystore.

## Supported Curves

| Curve               | Key Size | Security Level | Best For                          |
| ------------------- | -------- | -------------- | --------------------------------- |
| `secp256r1` (P-256) | 256 bits | ~128-bit       | IoT devices, performance-critical |
| `secp384r1` (P-384) | 384 bits | ~192-bit       | Enterprise, general use (default) |
| `secp521r1` (P-521) | 521 bits | ~256-bit       | Maximum security, long-term       |

See [curveSelectionGuide.md](./docs/curveSelectionGuide.md) for detailed curve comparison.

## Examples

### Minimal CSR (with defaults)

```typescript
const result = await CSRModule.generateCSR({
  commonName: "device-12345",
  serialNumber: "APCBPGN2202-AF250300028",
});
```

### CSR with P-256 curve

```typescript
const result = await CSRModule.generateCSR({
  commonName: "iot-device-001",
  curve: "secp256r1",
  ipAddress: "192.168.1.100",
});
```

### CSR with maximum security (P-521)

```typescript
const result = await CSRModule.generateCSR({
  country: "US",
  organization: "High Security Corp",
  commonName: "secure-device",
  curve: "secp521r1",
});
```

See [example-usage.tsx](./example-usage.tsx) for more examples.

## Verify Generated CSR

```bash
# View CSR details
openssl req -in csr.csr -noout -text

# Check signature algorithm (should be ecdsa-with-SHA256)
openssl req -in csr.csr -noout -text | grep "Signature Algorithm"

# Check curve
openssl req -in csr.csr -noout -text | grep -A 2 "Public-Key"

# Check SAN
openssl req -in csr.csr -noout -text | grep -A 1 "Subject Alternative Name"
```

## Generated CSR Format

The module generates CSRs with the following characteristics:

- **Format:** PKCS#10
- **Signature Algorithm:** ecdsa-with-SHA256
- **Key Usage (critical):** Digital Signature, Key Agreement
- **Extended Key Usage:** TLS Web Client Authentication
- **Subject Alternative Name:** IP Address (configurable)

Example output:

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=US, ST=Texas, L=Austin, O=MyOrganization, OU=MyOrganizationalUnit, CN=5dab25dd-7d0a-4a03-94c3-39f935c0a48a/serialNumber=APCBPGN2202-AF250300028
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Requested Extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                IP Address:10.10.10.10
    Signature Algorithm: ecdsa-with-SHA256
```

## TypeScript Support

Full TypeScript definitions are included:

```typescript
import CSRModule, {
  CSRParams,
  CSRResult,
  ECCurve,
  KeyPairParams,
  KeyPairResult,
} from "react-native-ecc-csr";

const params: CSRParams = {
  commonName: "device-001",
  serialNumber: "abcdedf19839",
};

const result: CSRResult = await CSRModule.generateCSR(params);
```

## Requirements

- React Native >= 0.60
- Android SDK >= 21
- BouncyCastle library (included)

## Dependencies

### Android

- `org.bouncycastle:bcprov-jdk18on:1.76` - Cryptographic provider with EC support
- `org.bouncycastle:bcpkix-jdk18on:1.76` - PKI and certificate utilities

These are automatically included by the module as transitive dependencies.

**React Native compile version:** this module compiles against exactly
`com.facebook.react:react-android:0.76.0` (`compileOnly`), pinned so `./gradlew test` works
standalone outside a consuming app. The app supplies its own React Native version at
runtime, which is fine while the bridge API this module uses (`Promise`,
`ReactApplicationContext`, `ReadableMap`, `WritableMap`) stays stable. Bump the pin in
`android/build.gradle` deliberately - notably for the Turbo Modules migration (IA-5752).

## Testing

Android logic is covered by JVM unit tests (Robolectric) and gated in CI by
`.github/workflows/android-tests.yml`:

```bash
cd android && ./gradlew test
```

See `android/src/test/README.md` for what is and isn't covered.

Robolectric tests run against API 33, pinned in `android/src/test/resources/robolectric.properties`
and backed by `testOptions.unitTests.includeAndroidResources`. Both are required: without the merged
manifest, Robolectric falls back to legacy resources mode, which is unsupported after API 28 and
silently drops every Robolectric test down to its API 16 floor — seven levels below this module's
`minSdk 23`. Platform APIs newer than 16 then fail at runtime with `NoSuchMethodError` despite
compiling cleanly. Tests that need a specific level still override `Build.VERSION.SDK_INT` locally.

**iOS has no automated test coverage.** `ios/CSRModule.m` carries the other half of this
module and is verified manually only, so a CSR-format regression on iOS would not be caught
by CI. Exercise iOS changes against a real device or simulator before release.

## Android Configuration

### ProGuard/R8 Rules

**Good news:** The module automatically applies ProGuard rules via `consumerProguardFiles`, so most apps won't need manual configuration.

**If you experience issues in release builds**, verify these rules are present in your app's `android/app/proguard-rules.pro`:

```proguard
# BouncyCastle - keep EC algorithm implementations
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.asn1.** { *; }

# AndroidX Security
-keep class androidx.security.crypto.** { *; }
```

**Why this matters**: Without these rules, R8 may strip the EC (Elliptic Curve) algorithms from BouncyCastle, causing `NoSuchAlgorithmException: no such algorithm: EC` errors in release builds.

**Debugging:** To verify ProGuard rules are applied:
```bash
# Check if BC classes are kept in release build
unzip -l app-release.apk | grep bouncycastle
```

### System BouncyCastle Provider

Android includes a stripped-down BouncyCastle provider that only supports RSA, DSA, and DH algorithms - **not EC (Elliptic Curve)**. This module automatically:
- Removes the system's stripped BC provider
- Registers its own full BouncyCastle provider with EC support
- Uses the full provider directly to avoid conflicts

See [SYSTEM_BC_PROVIDER_FIX.md](./docs/SYSTEM_BC_PROVIDER_FIX.md) for technical details.

## Security Considerations

Understanding the security implications of different key storage methods is important for making informed decisions.

### Software Keys (Android)

**Storage Details**:
- Stored in PKCS12 format in app's private directory (`software_keys.p12`)
- Password-protected with empty password (PKCS12 standard format)
- **Not encrypted at rest** - relies on OS-level security only
- File permissions explicitly set to mode 0600 (owner read/write only)
- Protected by Android app sandboxing (other apps cannot access)
- Excluded from device backups unconditionally (stored in `getNoBackupFilesDir()`, no manifest configuration required)
- Automatically deleted when app is uninstalled

**Security Level**:
- ✅ **Protected from**: Other apps (sandboxing), normal users, device backups and device-to-device transfer
- ⚠️ **Vulnerable to**: Root access, physical access with USB debugging enabled
- ⚠️ **No encryption at rest**: Keys stored in plain PKCS12 format

**Recommended For**:
- Development and testing
- Older devices (Android 11 and below where hardware TLS not supported)
- Use cases where hardware keys not available and threat model accepts OS-level security
- Short-term key storage

**Security Note**: For production use, prefer hardware-backed keys (`useHardwareKey=true`) on Android 12+ devices.

### Hardware Keys (Android)

**Storage Details**:
- Stored in Android Keystore (TEE or StrongBox)
- Protected by hardware security module
- Private keys **cannot be exported or extracted**
- Survive app reinstall (must explicitly call `deleteKey()` to remove)

**Security Level**:
- ✅ **Protected from**: All software-based attacks, including root access
- ✅ **Hardware-backed**: Cryptographic operations performed in secure hardware
- ✅ **Tamper-resistant**: Even physical access cannot extract key material

**Recommended For**:
- Production environments
- Android 12+ devices (for TLS compatibility)
- High-security requirements
- Long-term key storage

### Best Practices

1. **Use Hardware Keys When Available**
   ```typescript
   const caps = await CSRModule.getHardwareKeystoreCapabilities();
   const result = await CSRModule.generateCSR({
     commonName: "device-001",
     privateKeyAlias: "my-key",
     useHardwareKey: caps.tlsCompatible  // Use HW if device supports it
   });
   ```

2. **Check What Was Actually Used**
   ```typescript
   if (result.hardwareKeyRequested && !result.useHardwareKey) {
     console.warn("Hardware key requested but device doesn't support TLS with hardware keys");
     console.log("Using software keystore instead");
   }
   ```

3. **Implement Key Rotation**
   - Periodically generate new keys and CSRs
   - Delete old keys after successful certificate renewal
   ```typescript
   await CSRModule.deleteKey("old-key-alias");
   ```

4. **Handle Device Backups** — no configuration required

   The software keystore is stored in `Context.getNoBackupFilesDir()`. Android excludes that directory from Auto Backup, cloud backup, and device-to-device transfer unconditionally, so nothing needs to be added to your manifest or Expo config, and no `android:allowBackup` value can override it.

   **If you are upgrading from a version that shipped `backup_rules.xml`:** delete any manifest attribute or config plugin that references `@xml/backup_rules` or `@xml/data_extraction_rules` from this package. Both files have been removed, so a stale reference will fail resource resolution at build time. Do not replace them with anything.

   Those files were removed because the mechanism could not be made to work from inside a library: `android:fullBackupContent` and `android:dataExtractionRules` each accept exactly one resource reference, and nothing merges rule sets across libraries. If any other dependency claimed either attribute — `expo-secure-store` does, via its own config plugin — this module's exclusions were silently inactive, with no build error and no runtime warning. Storing the key outside the backup set removes the coordination problem instead of documenting around it.

   **Migration for existing installs:** the keystore moves from `files/software_keys.p12` to `no_backup/software_keys.p12` on first keystore access, along with any quarantined corrupt copies — `files/software_keys.p12.corrupted.<timestamp>` files written by earlier releases move into `no_backup/keystore_forensics/`, and the retention cap of three is applied there. The backup-eligible originals are deleted, not merely abandoned. If the live keystore cannot be relocated, the call fails rather than returning the new path, so an existing key is never shadowed by an empty keystore. If your app caches the `keystorePath` from a previous `generateCSR` call, re-read it after upgrading.

   **Verification:**
   ```bash
   adb shell run-as <your.package> ls -l no_backup/    # keystore should be here
   adb shell run-as <your.package> ls -l files/        # and absent here
   ```

5. **Monitor Key Storage Type**
   - Log which storage method is being used
   - Alert if production devices fall back to software keys unexpectedly
   ```typescript
   if (!result.isHardwareBacked) {
     analytics.track('software_key_used', {
       device: caps.manufacturer + ' ' + caps.model,
       androidVersion: caps.androidSdkVersion
     });
   }
   ```

### Security Trade-offs

| Aspect | Software Keys | Hardware Keys |
|--------|---------------|---------------|
| **Encryption at Rest** | ❌ No encryption (OS-level protection only) | ✅ Hardware-encrypted |
| **Root Protection** | ❌ Vulnerable to root access | ✅ Fully protected |
| **Backup Exposure** | ✅ Excluded (stored in `no_backup/`) | ✅ Cannot be backed up |
| **Device Compatibility** | ✅ All devices (API 23+) | ⚠️ Android 12+ for TLS |
| **Performance** | ⚠️ Slower (software crypto) | ✅ Faster (hardware acceleration) |
| **Survives Reinstall** | ❌ Deleted with app | ✅ Persists (manual delete required) |
| **Key Extraction** | ⚠️ Possible with root or physical access | ✅ Impossible (hardware-bound) |

**Note:** Software keys rely on Android OS-level security (app sandboxing, file permissions). For production use with sensitive keys, prefer hardware-backed keys.

### Compliance & Regulatory Considerations

- **FIPS 140-2**: 
  - Hardware keys in StrongBox may meet FIPS 140-2 Level 3 (device-dependent, verify specific device certification)
  - Software keys typically do NOT meet FIPS 140-2 requirements (no encryption at rest)
- **PCI DSS**: Hardware-backed keys strongly recommended for payment applications; software keys generally NOT acceptable
- **GDPR**: Both methods comply when proper access controls and backup exclusion are configured
- **HIPAA**: Hardware-backed keys strongly recommended for ePHI; software keys require thorough risk analysis and may not be acceptable
- **SOC 2**: Hardware keys preferred; software keys may require additional compensating controls

**Recommendation:** Always verify compliance requirements with your security/compliance team before deployment.

For maximum security, always prefer hardware-backed keys (`useHardwareKey: true`) on supported devices (Android 12+).
