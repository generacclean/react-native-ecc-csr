# StrongBox Curve Limitation Fix

## Issue

Hardware key generation was failing with:
```
java.security.InvalidAlgorithmParameterException: Unsupported StrongBox EC key size: 384 bits. Supported: 256
```

This occurred on devices with StrongBox support when using P-384 (secp384r1) or P-521 (secp521r1) curves.

## Root Cause

**StrongBox hardware secure elements only support P-256 (secp256r1) curve.**

### What is StrongBox?

StrongBox is a dedicated hardware security module (HSM) found on high-end Android devices (Pixel 3+, Samsung flagships). It provides:
- Physical tampering resistance
- Side-channel attack protection
- Higher security guarantees than TEE (Trusted Execution Environment)

However, StrongBox has **hardware limitations** that TEE doesn't:
- **Only P-256 supported**: 256-bit keys only
- **No P-384**: 384-bit keys not supported
- **No P-521**: 521-bit keys not supported

### Android Hardware Keystore Hierarchy

```
Software Keystore (PKCS12)
  ↓ (more secure)
TEE (Trusted Execution Environment)
  ↓ (more secure)
StrongBox (Dedicated Security Chip)
```

**Curve Support:**
- **Software**: All curves (P-256, P-384, P-521)
- **TEE**: All curves (P-256, P-384, P-521)
- **StrongBox**: Only P-256 ❌ P-384, P-521 not supported

## The Code Flow Before Fix

```java
if (hasStrongBox) {
    specBuilder.setIsStrongBoxBacked(true);
    Log.d(MODULE_NAME, "Using StrongBox-backed key generation");
}

keyPairGenerator.initialize(specBuilder.build());
// ☠️ CRASH if curve is P-384 or P-521
```

**What happened:**
1. Device has StrongBox → `hasStrongBox = true`
2. Code sets `setIsStrongBoxBacked(true)`
3. App requests P-384 curve (default)
4. StrongBox can't handle P-384 → **InvalidAlgorithmParameterException**

## The Fix: Intelligent Fallback

### New Logic

```java
boolean hasStrongBox = false;
boolean useStrongBox = false;

if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
    hasStrongBox = getReactApplicationContext().getPackageManager()
            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    Log.d(MODULE_NAME, "Device StrongBox support: " + hasStrongBox);

    // StrongBox only supports P-256 (secp256r1). For other curves, use TEE.
    if (hasStrongBox && !keystoreCurve.equals("secp256r1")) {
        Log.w(MODULE_NAME, "StrongBox only supports P-256. Requested curve: " + 
              keystoreCurve + ". Using TEE instead.");
        useStrongBox = false;
    } else {
        useStrongBox = hasStrongBox;
    }
}

// Only apply StrongBox backing if compatible
if (useStrongBox) {
    specBuilder.setIsStrongBoxBacked(true);
    Log.d(MODULE_NAME, "Using StrongBox-backed key generation (P-256)");
} else if (hasStrongBox) {
    Log.d(MODULE_NAME, "Using hardware-backed (TEE) key generation " +
          "(StrongBox available but curve incompatible)");
} else {
    Log.d(MODULE_NAME, "Using hardware-backed (TEE) key generation");
}
```

### Decision Matrix

| Has StrongBox | Curve | Use StrongBox | Use TEE | Log Message |
|--------------|-------|---------------|---------|-------------|
| ❌ No | P-256 | ❌ | ✅ | "Using hardware-backed (TEE) key generation" |
| ❌ No | P-384 | ❌ | ✅ | "Using hardware-backed (TEE) key generation" |
| ❌ No | P-521 | ❌ | ✅ | "Using hardware-backed (TEE) key generation" |
| ✅ Yes | P-256 | ✅ | ❌ | "Using StrongBox-backed key generation (P-256)" |
| ✅ Yes | P-384 | ❌ | ✅ | "Using hardware-backed (TEE) key generation (StrongBox available but curve incompatible)" |
| ✅ Yes | P-521 | ❌ | ✅ | "Using hardware-backed (TEE) key generation (StrongBox available but curve incompatible)" |

### What This Means

**StrongBox devices (Pixel, high-end Samsung):**
- **P-256 request**: Uses StrongBox (highest security)
- **P-384 request**: Falls back to TEE (still hardware-backed, still secure)
- **P-521 request**: Falls back to TEE (still hardware-backed, still secure)

**Non-StrongBox devices (most devices):**
- **All curves**: Use TEE (hardware-backed, secure)

**Android 11 or below:**
- **All curves**: Fall back to software (TLS compatible)

## Logging Examples

### Pixel 5 with P-256 (StrongBox Used)

```
D CSRModule: Generating hardware-backed key pair
D CSRModule: Device StrongBox support: true
D CSRModule: Using StrongBox-backed key generation (P-256)
D CSRModule: Hardware key pair generated successfully
D CSRModule: Key pair generated: my-key (hardware, secp256r1)
```

### Pixel 5 with P-384 (TEE Fallback)

```
D CSRModule: Generating hardware-backed key pair
D CSRModule: Device StrongBox support: true
W CSRModule: StrongBox only supports P-256. Requested curve: secp384r1. Using TEE instead.
D CSRModule: Using hardware-backed (TEE) key generation (StrongBox available but curve incompatible)
D CSRModule: Hardware key pair generated successfully
D CSRModule: Key pair generated: my-key (hardware, secp384r1)
```

### Samsung Galaxy S21 with P-384 (TEE, No StrongBox)

```
D CSRModule: Generating hardware-backed key pair
D CSRModule: Device StrongBox support: false
D CSRModule: Using hardware-backed (TEE) key generation
D CSRModule: Hardware key pair generated successfully
D CSRModule: Key pair generated: my-key (hardware, secp384r1)
```

## Security Implications

### Is TEE Less Secure Than StrongBox?

**Short answer**: TEE is still very secure for most use cases.

**Long answer**:
- **TEE (Trusted Execution Environment)**: Software-isolated secure world running on main processor
  - Resistant to software attacks
  - Used by banks, government apps, DRM
  - Industry standard for mobile security

- **StrongBox**: Dedicated physical security chip
  - Resistant to physical tampering
  - Resistant to side-channel attacks
  - Higher certification (e.g., Common Criteria)

**For TLS client authentication (our use case):**
- TEE provides excellent security
- Private keys never exposed to main OS
- Hardware-backed cryptographic operations
- StrongBox offers marginal additional security for this use case

### Recommendation

**For most apps:**
- Use the default curve (P-384) → Gets TEE on all devices
- TEE provides sufficient security for TLS

**For maximum security with StrongBox:**
- Use P-256 curve explicitly
- Only works on StrongBox-capable devices
- Fallback to TEE on other devices

## Usage Examples

### Default (P-384) - TEE on All Hardware-Capable Devices

```typescript
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  curve: 'secp384r1',  // Default
  useHardwareKey: true,
});

// On Pixel 5 (has StrongBox):
// - Uses TEE (StrongBox doesn't support P-384)
// - Still hardware-backed ✅
// - Still secure ✅

// On Samsung Galaxy S21 (no StrongBox):
// - Uses TEE
// - Hardware-backed ✅
```

### Explicit P-256 for StrongBox

```typescript
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  curve: 'secp256r1',  // P-256
  useHardwareKey: true,
});

// On Pixel 5 (has StrongBox):
// - Uses StrongBox (highest security) ✅

// On Samsung Galaxy S21 (no StrongBox):
// - Uses TEE (still hardware-backed) ✅
```

### Check Capabilities to Choose Curve

```typescript
const caps = await CSRModule.getHardwareKeystoreCapabilities();

// Choose curve based on device capability
const curve = caps.hasStrongBox ? 'secp256r1' : 'secp384r1';

const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  curve,
  useHardwareKey: true,
});

// Optimizes for StrongBox when available
// Falls back to P-384 on non-StrongBox devices
```

## Testing

### Test on StrongBox Device (Pixel 3+)

```typescript
// Test P-256 (should use StrongBox)
const result256 = await CSRModule.generateCSR({
  commonName: 'test',
  privateKeyAlias: 'test-p256',
  curve: 'secp256r1',
  useHardwareKey: true,
});
// Check logs for: "Using StrongBox-backed key generation (P-256)"

// Test P-384 (should fall back to TEE)
const result384 = await CSRModule.generateCSR({
  commonName: 'test',
  privateKeyAlias: 'test-p384',
  curve: 'secp384r1',
  useHardwareKey: true,
});
// Check logs for: "StrongBox only supports P-256. Requested curve: secp384r1. Using TEE instead."

// Test P-521 (should fall back to TEE)
const result521 = await CSRModule.generateCSR({
  commonName: 'test',
  privateKeyAlias: 'test-p521',
  curve: 'secp521r1',
  useHardwareKey: true,
});
// Check logs for: "StrongBox only supports P-256. Requested curve: secp521r1. Using TEE instead."
```

### Verify Logs

```bash
adb logcat | grep "CSRModule.*StrongBox"
```

Expected output on Pixel with P-384:
```
D CSRModule: Device StrongBox support: true
W CSRModule: StrongBox only supports P-256. Requested curve: secp384r1. Using TEE instead.
D CSRModule: Using hardware-backed (TEE) key generation (StrongBox available but curve incompatible)
```

## Curve Selection Guide

### When to Use Each Curve

| Curve | Key Size | Security | Speed | StrongBox | Recommendation |
|-------|----------|----------|-------|-----------|----------------|
| **secp256r1** (P-256) | 256 bits | ~128-bit | Fast | ✅ Yes | IoT devices, maximum hardware support |
| **secp384r1** (P-384) | 384 bits | ~192-bit | Medium | ❌ No (TEE fallback) | **Default**, enterprise use |
| **secp521r1** (P-521) | 521 bits | ~256-bit | Slow | ❌ No (TEE fallback) | Maximum security, long-term |

### Default Choice: P-384

**Why P-384 is the default:**
1. **Good security**: 192-bit strength is more than sufficient
2. **Works everywhere**: Supported by TEE on all Android devices
3. **Performance**: Reasonable balance of speed and security
4. **Industry standard**: Widely used in enterprise PKI

**Trade-off:**
- Doesn't use StrongBox on Pixel devices
- But TEE is still very secure for TLS use case

### When to Use P-256

**Choose P-256 if:**
1. You want StrongBox support on Pixel devices
2. Performance is critical (faster than P-384)
3. You're targeting IoT devices (lower compute)

**Trade-off:**
- Slightly lower security margin than P-384
- Still exceeds current security requirements

### When to Use P-521

**Choose P-521 if:**
1. Maximum security is required
2. Long-term key storage (10+ years)
3. Compliance requirements specify 256-bit security

**Trade-off:**
- Slower performance
- Doesn't use StrongBox (fallback to TEE)

## Summary

**Problem**: StrongBox only supports P-256, causing crashes with P-384/P-521.

**Solution**: Intelligent fallback to TEE when curve is incompatible with StrongBox.

**Result**: 
- P-256 on StrongBox devices → Uses StrongBox (highest security)
- P-384/P-521 on StrongBox devices → Uses TEE (still very secure)
- All curves on non-StrongBox devices → Uses TEE (hardware-backed)
- All curves on Android 11 → Falls back to software (TLS compatible)

**No more crashes, optimal hardware usage based on device capability.**

## Related Fixes

This fix works in conjunction with:
1. **Intelligent keystore selection**: Validates TLS compatibility (Android 12+)
2. **BouncyCastle provider fix**: Ensures software fallback works reliably
3. **Capability detection API**: Apps can query device capabilities

Together, these fixes ensure CSR generation works reliably on all Android devices with optimal security for each device's capabilities.
