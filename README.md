# React Native ECC CSR Module

A React Native module for generating Certificate Signing Requests (CSR) with Elliptic Curve Cryptography (ECC) support.

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

- `org.bouncycastle:bcprov-jdk18on:1.76`
- `org.bouncycastle:bcpkix-jdk18on:1.76`

These are automatically included by the module.

## Android Configuration

### ProGuard/R8 Rules (Important!)

If your app uses ProGuard or R8 (enabled by default in release builds), you **must** add these rules to prevent the BouncyCastle crypto algorithms from being stripped:

```proguard
# BouncyCastle ProGuard/R8 Rules
# Prevent stripping of BouncyCastle cryptographic algorithms

# Keep all BouncyCastle classes
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep EC (Elliptic Curve) algorithm implementations
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }

# Keep Security Provider registration
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }

# Keep cryptographic service classes
-keepclassmembers class * extends java.security.Provider {
    <init>(...);
}

# Prevent optimization of crypto algorithms
-keepnames class org.bouncycastle.jcajce.provider.** { *; }
-keepnames class org.bouncycastle.jce.provider.** { *; }
```

Add these to your app's `android/app/proguard-rules.pro` file.

**Why this is needed**: Without these rules, R8 will strip the EC (Elliptic Curve) algorithms from BouncyCastle, causing `NoSuchAlgorithmException: no such algorithm: EC` errors in release builds.

### System BouncyCastle Provider

Android includes a stripped-down BouncyCastle provider that only supports RSA, DSA, and DH algorithms - **not EC (Elliptic Curve)**. This module automatically:
- Removes the system's stripped BC provider
- Registers its own full BouncyCastle provider with EC support
- Uses the full provider directly to avoid conflicts

See [SYSTEM_BC_PROVIDER_FIX.md](./docs/SYSTEM_BC_PROVIDER_FIX.md) for technical details.
