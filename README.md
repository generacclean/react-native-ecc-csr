# React Native ECC CSR Module

A React Native module for generating Certificate Signing Requests (CSR) with Elliptic Curve Cryptography (ECC) support.

## Features

- ✅ Generate CSR with ECC keys (P-256, P-384, P-521)
- ✅ SHA256 signature algorithm
- ✅ Subject Alternative Name (SAN) support with IP addresses
- ✅ Full TypeScript support
- ✅ Configurable subject DN fields
- ✅ Key Usage and Extended Key Usage extensions
- ✅ Standards-compliant PKCS#10 format

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

#### Returns

```typescript
{
  csr: string; // PEM-encoded CSR
  privateKeyAlias: string; // string
  publicKey: string; // Base64-encoded public key
}
```

## Supported Curves

| Curve               | Key Size | Security Level | Best For                          |
| ------------------- | -------- | -------------- | --------------------------------- |
| `secp256r1` (P-256) | 256 bits | ~128-bit       | IoT devices, performance-critical |
| `secp384r1` (P-384) | 384 bits | ~192-bit       | Enterprise, general use (default) |
| `secp521r1` (P-521) | 521 bits | ~256-bit       | Maximum security, long-term       |

See [CURVE_SELECTION_GUIDE.md](./CURVE_SELECTION_GUIDE.md) for detailed curve comparison.

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

- `org.bouncycastle:bcprov-jdk15on:1.70` (or compatible version)
- `org.bouncycastle:bcpkix-jdk15on:1.70` (or compatible version)
