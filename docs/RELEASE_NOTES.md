# Release Notes - Hardware Keystore Fix & Software Keystore Implementation

## Version 1.0.3

### 🎉 Major Improvements

This release fixes critical issues with hardware keystore compatibility and implements a robust software keystore fallback for devices that don't support hardware-backed TLS keys.

### ✅ What's Fixed

1. **Software Keystore Working on All Devices**
   - Successfully generates CSRs with software keys using BouncyCastle
   - Full EC algorithm support (secp256r1, secp384r1, secp521r1)
   - PKCS12 keystore for secure key storage
   - Tested and verified on Pixel 8 running Android 15

2. **BouncyCastle Provider Conflicts Resolved**
   - Automatically removes Android's stripped-down BC provider
   - Registers full BouncyCastle provider with EC support
   - Uses direct provider reference to avoid lookup conflicts
   - Comprehensive logging for debugging provider issues

3. **Intelligent Hardware vs Software Selection**
   - Module automatically detects device TLS compatibility
   - Android 12+ required for hardware-backed TLS keys
   - Graceful fallback to software keys on older devices
   - Clear logging of decision-making process

### 📋 Implementation Details

#### BouncyCastle Provider Management
```java
// Keep direct reference to avoid system BC provider
private static final Provider FULL_BC_PROVIDER = new BouncyCastleProvider();

// Remove system's stripped BC provider at startup
ensureBouncyCastleProvider();
```

#### Software Key Generation Flow
1. Generate EC key pair using full BouncyCastle provider
2. Create self-signed certificate for PKCS12 storage
3. Store in software_keys.p12 file in app's private directory
4. Use stored keys for CSR signing

#### Hardware Key Requirements
- **Android 12+ (API 31)**: Required for `PURPOSE_AGREE_KEY` support
- **TEE or StrongBox**: Hardware security module
- **StrongBox Limitation**: Only supports P-256 curve

### 🔧 Changes to API

#### New Response Fields
```typescript
interface CSRResult {
  // ... existing fields
  useHardwareKey: boolean;        // Final decision made by module
  hardwareKeyRequested: boolean;  // What app requested
  tlsCompatible: boolean;         // Device supports HW keys for TLS
}
```

#### New Method
```typescript
getHardwareKeystoreCapabilities(): Promise<{
  tlsCompatible: boolean;
  androidSdkVersion: number;
  hasStrongBox: boolean;
  manufacturer: string;
  model: string;
  device: string;
}>
```

### 🛡️ ProGuard/R8 Configuration

Added comprehensive ProGuard rules to prevent BouncyCastle stripping in release builds:

```proguard
# Keep all BouncyCastle classes
-keep class org.bouncycastle.** { *; }

# Keep EC algorithm implementations  
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }

# Keep Security Provider registration
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }
```

These rules are automatically applied via `consumerProguardFiles` in the module's build.gradle.

### 📊 Test Results

#### Pixel 8 (Android 15) - Software Keystore
```
✅ BouncyCastle v1.76 registered successfully
✅ Software key pair generated (secp384r1)
✅ CSR created with all extensions
✅ Key stored in PKCS12 keystore
```

**Generated CSR:**
- Subject DN: C=US, ST=Wisconsin, L=Waukesha, O=Generac Power Systems, OU=Field Pro, CN=[device-id]
- Public Key: EC secp384r1 (384-bit)
- Extensions: Key Usage (critical), Extended Key Usage, SAN
- Signature: ecdsa-with-SHA256

### 🚀 Migration Guide

#### For Apps Currently Using the Module

No breaking changes! The API remains backward compatible:

```typescript
// Old code still works (defaults to software on older devices)
const result = await CSRModule.generateCSR({
  commonName: "device-001",
  privateKeyAlias: "my-key"
});

// New: Explicitly request hardware (with automatic fallback)
const result = await CSRModule.generateCSR({
  commonName: "device-001", 
  privateKeyAlias: "my-key",
  useHardwareKey: true  // Module decides based on device
});

// New: Check device capabilities first
const caps = await CSRModule.getHardwareKeystoreCapabilities();
if (caps.tlsCompatible) {
  // Safe to request hardware keys
}
```

### 📚 Documentation Updates

- ✅ README.md updated with hardware vs software guidance
- ✅ ProGuard rules documented and included
- ✅ API reference expanded with new fields
- ✅ System BC provider conflict explanation
- ✅ Hardware compatibility requirements

### 🔍 Debugging Enhancements

New log messages help diagnose issues:
```
D/CSRModule: Full BouncyCastle provider already registered
D/CSRModule: BC Provider version: 1.76
D/CSRModule: All registered security providers: [list]
D/CSRModule: EC algorithm IS supported by BouncyCastle
D/CSRModule: Software key pair generated successfully
D/CSRModule: CSR generated successfully (requested: software, actual: software)
```

### 🐛 Known Issues & Limitations

1. **Hardware Keys on Android 11 and Below**: Not supported for TLS due to missing PURPOSE_AGREE_KEY. Module automatically falls back to software keys.

2. **StrongBox Curve Support**: StrongBox only supports P-256 (secp256r1). For P-384 and P-521, module uses TEE instead.

3. **Software Keystore Security**: While secure, software keys are not protected by hardware security modules. Use hardware keys when available and device supports TLS.

### 🔐 Security Considerations

#### Software Keys
- Stored in PKCS12 format in app's private directory
- Protected by Android app sandbox
- Not accessible to other apps
- Deleted when app is uninstalled
- **Recommended for**: Development, testing, older devices

#### Hardware Keys  
- Stored in Android Keystore (TEE or StrongBox)
- Protected by hardware security module
- Cannot be exported or extracted
- Survives app reinstall (can be explicitly deleted)
- **Recommended for**: Production, Android 12+, high-security requirements

### 📦 Dependencies

- **BouncyCastle**: 1.76 (bcprov-jdk18on, bcpkix-jdk18on)
- **React Native**: >= 0.60
- **Android SDK**: >= 21 (minimum), >= 31 (for hardware TLS keys)

### 🙏 Acknowledgments

Thanks to the BouncyCastle team for their comprehensive cryptography library and the React Native community for their support.

---

## Previous Versions

See git history for changes in versions 1.0.0 - 1.0.2.
