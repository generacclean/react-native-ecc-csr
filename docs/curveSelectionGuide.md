# ECC Curve Selection Guide

## Supported Curves

The CSR module supports three NIST-standardized elliptic curves:

### 1. secp256r1 (P-256)
- **Key Size:** 256 bits
- **Also Known As:** prime256v1, NIST P-256
- **Security Level:** ~128-bit equivalent security
- **Performance:** Fastest
- **Use Cases:**
  - IoT devices with limited processing power
  - High-frequency operations
  - Mobile devices where battery life matters
  - TLS/SSL connections (widely supported)

**Example:**
```typescript
const params: CSRParams = {
  commonName: "iot-device-001",
  serialNumber: "abc",
  curve: "secp256r1"
};
```

### 2. secp384r1 (P-384) - **DEFAULT**
- **Key Size:** 384 bits
- **Also Known As:** NIST P-384
- **Security Level:** ~192-bit equivalent security
- **Performance:** Moderate
- **Use Cases:**
  - General-purpose enterprise applications
  - Government/military applications (Suite B)
  - Long-term certificate validity (5-10 years)
  - **Your requirement** (Generac PWRview devices)

```

### 3. secp521r1 (P-521)
- **Key Size:** 521 bits (not 512!)
- **Also Known As:** NIST P-521
- **Security Level:** ~256-bit equivalent security
- **Performance:** Slowest
- **Use Cases:**
  - Maximum security requirements
  - Top Secret government communications
  - Long-term (20+ years) security needs
  - Financial institutions with extreme security requirements

**Example:**
```typescript
const params: CSRParams = {
  commonName: "high-security-vault",
  serialNumber: "abc",
  curve: "secp521r1"
};
```

## Comparison Table

| Curve | Key Size | Security Level | Speed | Certificate Size | Signature Size |
|-------|----------|----------------|-------|------------------|----------------|
| P-256 | 256 bits | 128-bit equiv. | Fast  | Smallest (~320 bytes) | Smallest (~64 bytes) |
| P-384 | 384 bits | 192-bit equiv. | Medium | Medium (~384 bytes) | Medium (~96 bytes) |
| P-521 | 521 bits | 256-bit equiv. | Slow | Largest (~521 bytes) | Largest (~132 bytes) |

## Security Recommendations

### Current (2025) Recommendations:
- **P-256**: Secure until ~2030
- **P-384**: Secure until ~2050+ (NSA Suite B approved)
- **P-521**: Secure for foreseeable future (>2050)

### When to Use Each:

**Use P-256 if:**
- You need maximum performance
- Certificate validity is ≤5 years
- Compatibility with older systems is crucial
- IoT/embedded devices with limited resources

**Use P-384 if:** (Recommended for most cases)
- You want a good balance of security and performance
- Certificate validity is 5-10 years
- Government/enterprise compliance requirements
- This is the default and matches your original requirement

**Use P-521 if:**
- Maximum security is paramount
- Certificate validity is >10 years
- Performance is not a critical concern
- Top Secret or classified information handling

## Performance Considerations

Approximate operations per second (on modern mobile processors):

| Operation | P-256 | P-384 | P-521 |
|-----------|-------|-------|-------|
| Key Generation | ~500/sec | ~200/sec | ~100/sec |
| Signing | ~1000/sec | ~400/sec | ~200/sec |
| Verification | ~400/sec | ~150/sec | ~80/sec |

## Compatibility Notes

### Excellent Compatibility (>99% systems):
- P-256: Universal support across all modern systems
- P-384: Excellent support, required for NSA Suite B

### Good Compatibility (~95% systems):
- P-521: Well supported, but some older systems may not support it
