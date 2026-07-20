# Intelligent Hardware/Software Keystore Selection

## Overview

The CSRModule now intelligently decides whether to use hardware or software keystores based on device capabilities and TLS compatibility requirements. Apps can express their preference via the `useHardwareKey` parameter, but **the module makes the final decision** to ensure TLS handshakes will succeed.

## The Problem This Solves

### Before: App Had to Know Device Quirks

```typescript
// ❌ Problematic: App makes the decision
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,  // Will fail on Samsung Android 11!
});

// TLS handshake fails later because hardware keys on Android 11
// don't support PURPOSE_AGREE_KEY needed for ECDH
```

**Problems:**
- App developers had to know about Android version limitations
- Different OEM behaviors (Samsung Knox, Pixel StrongBox, etc.)
- Silent failures during TLS handshake (not at key generation time)
- No way to detect compatibility before failure

### After: Module is the Intelligent Layer

```typescript
// ✅ Correct: Module makes the decision
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,  // Preference - module validates
});

// Check what actually happened
if (result.hardwareKeyRequested && !result.useHardwareKey) {
  console.log('Module overrode hardware request for TLS compatibility');
  console.log('Reason: Device requires Android 12+ for hardware TLS support');
}

// TLS handshake will succeed because module ensured compatibility
```

**Benefits:**
- Module knows device capabilities and OS requirements
- Automatic fallback to software on incompatible devices
- Clear logging and response fields explain decisions
- Apps get transparency without needing device knowledge

## Technical Details

### TLS Compatibility Requirements

Hardware-backed keys require **Android 12+ (API 31)** for TLS:

| Android Version | PURPOSE_SIGN | PURPOSE_VERIFY | PURPOSE_AGREE_KEY | TLS ECDH Support |
|-----------------|--------------|----------------|-------------------|------------------|
| Android 11      | ✓            | ✓              | ✗                 | ✗                |
| Android 12+     | ✓            | ✓              | ✓                 | ✓                |

**Why Android 12 is Required:**
- TLS handshake requires ECDH (Elliptic Curve Diffie-Hellman) for key agreement
- Hardware keystore on Android 11 can only sign/verify, not perform key agreement
- Android 12 (API 31) added `PURPOSE_AGREE_KEY` flag support
- Without this, TLS connection establishment fails even though key generation succeeds

### Implementation

#### 1. Capability Check Method

```java
/**
 * Determines if hardware-backed keys will work for TLS on this device.
 * Hardware keys require Android 12+ (API 31) for PURPOSE_AGREE_KEY support.
 *
 * @return true if device supports hardware keys for TLS, false otherwise
 */
private boolean canUseHardwareKeysForTLS() {
    // Android 12 (API 31) added PURPOSE_AGREE_KEY support for ECDH in hardware keystore
    return android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S;
}
```

#### 2. Intelligent Decision Logic

```java
// App can request hardware, but module decides based on TLS compatibility
boolean requestedHardwareKey = params.getBoolean("useHardwareKey");

// Override app preference if hardware won't work for TLS
boolean useHardwareKey = requestedHardwareKey && canUseHardwareKeysForTLS();

if (requestedHardwareKey && !useHardwareKey) {
    Log.w(MODULE_NAME, "Hardware key requested but not supported for TLS on this device (requires Android 12+). Using software keystore.");
}
```

#### 3. Enhanced Response

```java
response.putBoolean("isHardwareBacked", useHardwareKey && isHardwareBacked(privateKeyAlias));
response.putBoolean("useHardwareKey", useHardwareKey);
response.putBoolean("hardwareKeyRequested", requestedHardwareKey);
response.putBoolean("tlsCompatible", canUseHardwareKeysForTLS());
```

#### 4. Capability Detection API

```java
@ReactMethod
public void getHardwareKeystoreCapabilities(Promise promise) {
    capabilities.putBoolean("tlsCompatible", canUseHardwareKeysForTLS());
    capabilities.putInt("androidSdkVersion", android.os.Build.VERSION.SDK_INT);
    capabilities.putBoolean("hasStrongBox", hasStrongBox);
    capabilities.putString("manufacturer", android.os.Build.MANUFACTURER);
    capabilities.putString("model", android.os.Build.MODEL);
    capabilities.putString("device", android.os.Build.DEVICE);
    // ...
}
```

## Response Fields Explained

### CSRResult Interface

```typescript
interface CSRResult {
  csr: string;                    // PEM-encoded CSR (always present)
  privateKeyAlias: string;        // Key alias (always present)
  publicKey: string;              // Base64-encoded public key (always present)
  
  // Storage location
  isHardwareBacked: boolean;      // True if key is actually in hardware keystore
                                  // Verified by querying the Android KeyStore
  
  // Decision tracking
  useHardwareKey: boolean;        // Final decision made by module
                                  // True = hardware, False = software
  
  hardwareKeyRequested: boolean;  // What the app originally requested
                                  // Allows app to detect overrides
  
  // Device capability
  tlsCompatible: boolean;         // Can this device use hardware keys for TLS?
                                  // True if Android 12+, False otherwise
}
```

### Decision Matrix

| requestedHardwareKey | canUseHardwareKeysForTLS() | useHardwareKey (Final) | isHardwareBacked | Outcome |
|---------------------|---------------------------|----------------------|------------------|---------|
| false | false | false | false | Software (as requested) |
| false | true  | false | false | Software (as requested) |
| true  | false | **false** | false | **Software (overridden)** |
| true  | true  | true  | true  | Hardware (as requested) |

**Key Point:** When `hardwareKeyRequested=true` but `useHardwareKey=false`, the module overrode the request.

## Usage Patterns

### Pattern 1: Trust the Module (Simplest)

```typescript
// Just request your preference, module handles the rest
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,  // Module will validate
});

// CSR will always work for TLS
```

### Pattern 2: Check Capabilities First (Recommended)

```typescript
// Check device capabilities
const caps = await CSRModule.getHardwareKeystoreCapabilities();

if (!caps.tlsCompatible) {
  console.log(`Device ${caps.manufacturer} ${caps.model} on Android ${caps.androidSdkVersion} cannot use hardware keys for TLS`);
}

// Generate CSR with informed preference
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  useHardwareKey: caps.tlsCompatible,
});
```

### Pattern 3: Detect and Log Overrides

```typescript
const result = await CSRModule.generateCSR({
  commonName: 'device-001',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,
});

// Detect if module overrode your request
if (result.hardwareKeyRequested && !result.useHardwareKey) {
  console.warn(
    'CSRModule overrode hardware keystore request. ' +
    `Device is not TLS compatible (requires Android 12+). ` +
    `Using software keystore instead.`
  );
  
  // Report to analytics/monitoring
  analytics.track('keystore_override', {
    requested: 'hardware',
    actual: 'software',
    reason: 'tls_incompatible',
    tlsCompatible: result.tlsCompatible,
  });
}
```

## Device Behavior Examples

### Samsung Galaxy S21 on Android 11

```typescript
const caps = await CSRModule.getHardwareKeystoreCapabilities();
// {
//   tlsCompatible: false,        // Android 11 = no TLS support
//   androidSdkVersion: 30,
//   hasStrongBox: false,
//   manufacturer: "Samsung",
//   model: "SM-G991U",
//   device: "o1s"
// }

const result = await CSRModule.generateCSR({
  commonName: 'samsung-device',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,  // Requesting hardware
});

// Result:
// {
//   ...
//   isHardwareBacked: false,         // In software keystore
//   useHardwareKey: false,           // Module decided software
//   hardwareKeyRequested: true,      // App requested hardware
//   tlsCompatible: false             // Device can't do TLS with hardware
// }

// Module logs: "Hardware key requested but not supported for TLS on this device (requires Android 12+). Using software keystore."
```

### Samsung Galaxy S21 on Android 12

```typescript
const caps = await CSRModule.getHardwareKeystoreCapabilities();
// {
//   tlsCompatible: true,         // Android 12 = TLS supported!
//   androidSdkVersion: 31,
//   hasStrongBox: false,
//   manufacturer: "Samsung",
//   model: "SM-G991U",
//   device: "o1s"
// }

const result = await CSRModule.generateCSR({
  commonName: 'samsung-device',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,  // Requesting hardware
});

// Result:
// {
//   ...
//   isHardwareBacked: true,          // In hardware keystore (TEE)
//   useHardwareKey: true,            // Module approved hardware
//   hardwareKeyRequested: true,      // App requested hardware
//   tlsCompatible: true              // Device supports TLS with hardware
// }

// Module logs: "Hardware key pair generated successfully"
```

### Google Pixel 5 on Android 11

```typescript
const caps = await CSRModule.getHardwareKeystoreCapabilities();
// {
//   tlsCompatible: false,        // Android 11 = no TLS support
//   androidSdkVersion: 30,
//   hasStrongBox: true,          // Has StrongBox hardware
//   manufacturer: "Google",
//   model: "Pixel 5",
//   device: "redfin"
// }

const result = await CSRModule.generateCSR({
  commonName: 'pixel-device',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,
});

// Result: Software keystore even though device has StrongBox
// Reason: Android 11 doesn't support PURPOSE_AGREE_KEY
```

### Google Pixel 5 on Android 12

```typescript
const caps = await CSRModule.getHardwareKeystoreCapabilities();
// {
//   tlsCompatible: true,         // Android 12 = TLS supported
//   androidSdkVersion: 31,
//   hasStrongBox: true,          // Has StrongBox hardware
//   manufacturer: "Google",
//   model: "Pixel 5",
//   device: "redfin"
// }

const result = await CSRModule.generateCSR({
  commonName: 'pixel-device',
  privateKeyAlias: 'my-key',
  useHardwareKey: true,
});

// Result: Hardware keystore with StrongBox backing
// isHardwareBacked: true, useHardwareKey: true
// Module logs: "Using StrongBox-backed key generation"
```

## Why This Architecture is Correct

### Separation of Concerns

```
┌─────────────────────────────────────────────┐
│           React Native App                  │
│  - Business logic                           │
│  - User preferences                         │
│  - Expresses intent (hardware preference)   │
└─────────────────┬───────────────────────────┘
                  │
                  │ useHardwareKey: true
                  │
                  ▼
┌─────────────────────────────────────────────┐
│           CSRModule (Native)                │
│  - Device capability detection              │
│  - OS version checking                      │
│  - OEM quirk handling                       │
│  - TLS compatibility validation             │
│  - MAKES FINAL DECISION                     │
└─────────────────┬───────────────────────────┘
                  │
                  │ Validated decision
                  │
                  ▼
┌─────────────────────────────────────────────┐
│       Android KeyStore / PKCS12             │
│  - Actual key storage                       │
│  - Cryptographic operations                 │
└─────────────────────────────────────────────┘
```

### Benefits

1. **Single Source of Truth**: Module contains all device/OS knowledge
2. **Safe Defaults**: Apps can't accidentally break TLS by requesting hardware
3. **Future-Proof**: New Android versions? Update module, apps work unchanged
4. **Transparency**: Apps get full visibility into decisions via response fields
5. **Testability**: Module behavior is deterministic based on SDK version

## Testing Strategy

### Test Matrix

| Device Type | OS Version | Request | Expected Result | Verify |
|------------|-----------|---------|----------------|--------|
| Any | 11 | HW | Software | `useHardwareKey=false`, `hardwareKeyRequested=true` |
| Any | 12+ | HW | Hardware | `useHardwareKey=true`, `isHardwareBacked=true` |
| Any | Any | SW | Software | `useHardwareKey=false` |
| Pixel | 12+ | HW | StrongBox | Logs show "StrongBox-backed" |
| Samsung | 12+ | HW | TEE | Logs show "hardware-backed (TEE)" |

### Unit Tests

```java
// Test canUseHardwareKeysForTLS()
@Test
public void testCanUseHardwareKeysForTLS_Android11() {
    // Mock Build.VERSION.SDK_INT = 30 (Android 11)
    assertFalse(canUseHardwareKeysForTLS());
}

@Test
public void testCanUseHardwareKeysForTLS_Android12() {
    // Mock Build.VERSION.SDK_INT = 31 (Android 12)
    assertTrue(canUseHardwareKeysForTLS());
}
```

### Integration Tests

```typescript
// Test override behavior
test('CSRModule overrides hardware request on Android 11', async () => {
  // On Android 11 device
  const result = await CSRModule.generateCSR({
    commonName: 'test',
    privateKeyAlias: 'test-key',
    useHardwareKey: true,
  });
  
  expect(result.hardwareKeyRequested).toBe(true);
  expect(result.useHardwareKey).toBe(false);
  expect(result.isHardwareBacked).toBe(false);
  expect(result.tlsCompatible).toBe(false);
});
```

## Migration Guide

### Upgrading from Previous Versions

**Old API:**
```typescript
// Old: Boolean result, unclear meaning
const result = await CSRModule.generateCSR({
  commonName: 'device',
  privateKeyAlias: 'key',
  useHardwareKey: true,
});

// result.isHardwareBacked might be false, but why?
```

**New API:**
```typescript
// New: Rich result with decision tracking
const result = await CSRModule.generateCSR({
  commonName: 'device',
  privateKeyAlias: 'key',
  useHardwareKey: true,
});

// Now you know exactly what happened:
console.log({
  requested: result.hardwareKeyRequested,
  actual: result.useHardwareKey,
  backed: result.isHardwareBacked,
  compatible: result.tlsCompatible,
});
```

### No Breaking Changes

The API is **backward compatible**:
- Old code continues to work
- New fields are additive
- Default behavior (software keys) unchanged

## Logging

Module produces clear logs at key decision points:

```
# Device capability detection
CSRModule: Device StrongBox support: true
CSRModule: Using StrongBox-backed key generation

# Decision override
CSRModule: Hardware key requested but not supported for TLS on this device (requires Android 12+). Using software keystore.

# Success
CSRModule: Hardware key pair generated successfully
CSRModule: Key pair generated: my-key (hardware, secp384r1)
CSRModule: CSR generated successfully (requested: hardware, actual: hardware)

# Or
CSRModule: Key pair generated: my-key (software, secp384r1)
CSRModule: CSR generated successfully (requested: hardware, actual: software)
```

## Summary

### Key Principles

1. **Apps express intent** via `useHardwareKey` parameter
2. **Module makes final decision** based on TLS compatibility
3. **Transparency** via detailed response fields
4. **Safety** via automatic fallback to compatible storage
5. **Simplicity** for app developers - no device quirk knowledge needed

### What Changed

- ✅ Added `canUseHardwareKeysForTLS()` method
- ✅ Automatic override logic when hardware won't work
- ✅ New response fields: `hardwareKeyRequested`, `tlsCompatible`
- ✅ New API: `getHardwareKeystoreCapabilities()`
- ✅ Enhanced logging with decision rationale
- ✅ Updated TypeScript definitions

### What Stayed the Same

- ✅ Backward compatible API
- ✅ Default behavior (software keys) unchanged
- ✅ No breaking changes for existing apps
- ✅ Same CSR format and standards compliance

### The Bottom Line

**Before**: Apps had to be Android experts to avoid TLS failures.  
**After**: Apps express preference, module ensures TLS compatibility.

The module is now the intelligent layer that prevents foot-shooting while providing full transparency.
