# React Native ECC CSR Module

A React Native module for generating Certificate Signing Requests (CSR) with Elliptic Curve Cryptography (ECC) support.

## ⚠️ IMPORTANT SECURITY NOTICE

### Software Keystore Security (useHardwareKey=false)

**Encryption at Rest:** As of v1.2.0, software-backed keys are **encrypted at rest** using AndroidX Security's `EncryptedFile` with AES256-GCM encryption. The encryption key is stored in Android Keystore, providing hardware-backed protection for the software keystore.

**Previous versions (< 1.2.0):** Keys were stored unencrypted with an empty password.

**Backup Exclusion:** The keystore file is automatically excluded from device backups (see `backup_rules.xml`). However, **you must ensure your app properly configures backup settings** in `AndroidManifest.xml`:

```xml
<application
    android:allowBackup="false">
    <!-- OR for selective backup: -->
    android:fullBackupContent="@xml/backup_rules">
</application>
```

**Security Recommendations:**
- ✅ **Production apps:** Use `useHardwareKey=true` on Android 12+ devices whenever possible
- ✅ **Development/Testing:** Software keys are acceptable
- ✅ **Older devices (Android 11-):** Software keys with encryption at rest are your best option
- ⚠️ **High-security requirements:** Always prefer hardware-backed keys (Android 12+)
- ⚠️ **Compliance (HIPAA/PCI DSS):** Use hardware-backed keys or verify encrypted software keys meet requirements

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

```typescript
interface CSRResult {
  csr: string;                    // PEM-encoded CSR
  privateKeyAlias: string;        // Key alias
  publicKey: string;              // Base64-encoded public key
  isHardwareBacked: boolean;      // True if key is in hardware keystore
  useHardwareKey: boolean;        // Final decision (software or hardware)
  hardwareKeyRequested: boolean;  // What the app requested
  tlsCompatible: boolean;         // Device supports hardware keys for TLS
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

```typescript
{
  csr: string;                    // PEM-encoded CSR
  privateKeyAlias: string;        // Key alias
  publicKey: string;              // Base64-encoded public key
  isHardwareBacked: boolean;      // True if key is in hardware keystore
  useHardwareKey: boolean;        // Final decision (software or hardware)
  hardwareKeyRequested: boolean;  // What the app requested
  tlsCompatible: boolean;         // Device supports hardware keys for TLS
}
```

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
- `androidx.security:security-crypto:1.1.0` - EncryptedFile for keystore encryption at rest

These are automatically included by the module as transitive dependencies.

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

**🔒 Version 1.2.0+ (Current) - Encrypted at Rest:**

**Storage Details**:
- Stored in PKCS12 format in app's private directory (`software_keys_v1.p12`)
- **Encrypted at rest** using AndroidX Security `EncryptedFile` (AES256-GCM)
- Encryption key stored in Android Keystore (hardware-backed)
- File permissions explicitly set to mode 0600 (owner read/write only)
- Automatically excluded from device backups (via `backup_rules.xml`)
- Automatically deleted when app is uninstalled

**Security Level**:
- ✅ **Protected from**: Other apps, normal users, device backups
- ✅ **Encrypted**: AES256-GCM with hardware-backed encryption key
- ⚠️ **Vulnerable to**: Root access with Android Keystore compromise (extremely difficult)

**Recommended For**:
- Development and testing
- Older devices (Android 11 and below where hardware TLS not supported)
- Use cases where hardware keys not available
- Short-to-medium term key storage

**⚠️ Version < 1.2.0 (Legacy) - Unencrypted:**
- Stored with empty password (no encryption at rest)
- Vulnerable to root access, device backups, physical access with debugging
- **Upgrade to 1.2.0+ for encryption at rest**

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

4. **Handle Device Backups** ⚠️ **CRITICAL - MUST CONFIGURE IN YOUR APP**
   
   The module provides `backup_rules.xml` and `data_extraction_rules.xml`, but **these files do NOT automatically protect your app** unless you wire them into your app's manifest.
   
   **For Native Android Apps (AndroidManifest.xml):**
   ```xml
   <application
       android:allowBackup="true"
       android:fullBackupContent="@xml/backup_rules"
       android:dataExtractionRules="@xml/data_extraction_rules">
       <!-- OR for maximum security: -->
       android:allowBackup="false">
   </application>
   ```
   
   **For Expo/React Native Apps (app.json or app.config.js):**
   
   You **MUST** create a config plugin to merge the backup exclusion rules:
   
   ```javascript
   // app.config.js or plugins/android-backup-exclusion.js
   const { withAndroidManifest } = require('@expo/config-plugins');
   
   module.exports = function withBackupExclusion(config) {
     return withAndroidManifest(config, async (config) => {
       const androidManifest = config.modResults.manifest;
       const application = androidManifest.application[0];
       
       // Reference the backup rules from the library
       application.$['android:fullBackupContent'] = '@xml/backup_rules';
       application.$['android:dataExtractionRules'] = '@xml/data_extraction_rules';
       
       return config;
     });
   };
   
   // Then in app.config.js:
   module.exports = {
     expo: {
       plugins: [
         './plugins/android-backup-exclusion'
       ]
     }
   };
   ```
   
   **Why This Matters:**
   - Without manifest configuration, the library's backup rules are **NOT applied**
   - Your software keystore **WILL be uploaded to Google Drive** and device-to-device transfer
   - This exposes encrypted keys to cloud storage and backup infrastructure
   - Android 12+ requires `data_extraction_rules.xml` (the old `backup_rules.xml` is ignored)
   
   **What the module excludes:**
   - `software_keys.p12` (legacy filename)
   - `software_keys.p12.tmp` (temporary write file)
   - Any files matching the keystore pattern
   
   **Verification:**
   ```bash
   # Check if backup rules are applied in your built APK
   apktool d app-release.apk
   grep -r "backup_rules\|data_extraction_rules" app-release/AndroidManifest.xml
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

| Aspect | Software Keys (v1.2.0+) | Hardware Keys |
|--------|-------------------------|---------------|
| **Encryption at Rest** | ✅ AES256-GCM (hardware-backed key) | ✅ Hardware-encrypted |
| **Root Protection** | ⚠️ Protected (requires Keystore compromise) | ✅ Fully protected |
| **Backup Exposure** | ✅ Excluded (if configured) | ✅ Cannot be backed up |
| **Device Compatibility** | ✅ All devices (API 23+) | ⚠️ Android 12+ for TLS |
| **Performance** | ⚠️ Slower (software crypto) | ✅ Faster (hardware acceleration) |
| **Survives Reinstall** | ❌ Deleted with app | ✅ Persists (manual delete required) |
| **Key Extraction** | ⚠️ Possible with root + Keystore access | ✅ Impossible (hardware-bound) |

**Note:** Software keys in v1.2.0+ are significantly more secure than earlier versions due to encryption at rest.

### Compliance & Regulatory Considerations

- **FIPS 140-2**: 
  - Hardware keys in StrongBox may meet FIPS 140-2 Level 3 (device-dependent, verify specific device certification)
  - Software keys (even encrypted) typically do NOT meet FIPS 140-2 requirements
- **PCI DSS**: Hardware-backed keys strongly recommended for payment applications; encrypted software keys may be acceptable with risk assessment
- **GDPR**: Both methods comply when proper access controls and backup exclusion are configured
- **HIPAA**: Hardware-backed keys recommended for ePHI; encrypted software keys acceptable with documented risk analysis
- **SOC 2**: Hardware keys preferred; software keys with encryption at rest may satisfy Type II requirements

**Recommendation:** Always verify compliance requirements with your security/compliance team before deployment.

For maximum security, always prefer hardware-backed keys (`useHardwareKey: true`) on supported devices (Android 12+).
