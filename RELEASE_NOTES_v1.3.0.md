# Release Notes v1.3.0

**Release Date:** July 20, 2026  
**Branch:** feat/software-keystore-bouncycastle-refactor

---

## 🎯 Overview

Version 1.3.0 is a major refactor that implements a robust software keystore solution using BouncyCastle with intelligent hardware/software keystore selection, improved security practices, and enhanced reliability.

---

## 🚀 Major Features

### 1. Software Keystore with BouncyCastle
- Full BouncyCastle provider (v1.76) with complete EC algorithm support
- PKCS12 keystore for software key storage
- Support for all ECC curves: secp256r1, secp384r1, secp521r1
- Resolves system BouncyCastle provider conflicts on Android

### 2. Intelligent Hardware/Software Keystore Selection
- Automatic device capability detection
- Hardware keys require Android 12+ for TLS/ECDH support (`PURPOSE_AGREE_KEY`)
- Automatic fallback to software keys on older devices or when hardware unavailable
- New API: `getHardwareKeystoreCapabilities()` for runtime capability checking

### 3. Enhanced Security
- **File Permissions**: Explicit mode 0600 (owner read/write only) with atomic setting
- **Backup Exclusion**: Android backup rules prevent cloud/device backup exposure
- **Dual-store Collision Prevention**: Stale keys automatically cleaned from opposite keystore
- **Atomic File Operations**: Temp file + atomic rename prevents data loss
- **Corruption Recovery**: Corrupt keystores renamed to `.corrupted` for forensic analysis
- **IP Address Validation**: Enhanced validation prevents hostname injection attacks

### 4. Improved Reliability
- Thread-safe BouncyCastle provider initialization with double-checked locking
- All file I/O uses try-with-resources pattern
- Synchronized software keystore access prevents race conditions
- Better error handling with context tracking
- StrongBox fallback to TEE when unavailable

### 5. Resource Management
- Proper cleanup of FileInputStream/FileOutputStream resources
- Memory leak fixes in ContentSigner implementation
- FilterOutputStream pattern for incremental signature updates

---

## 📋 API Changes

### New Response Fields in `CSRResult`

```typescript
interface CSRResult {
  csr: string;                    // PEM-encoded CSR (existing)
  privateKeyAlias: string;        // Key alias (existing)
  publicKey: string;              // Base64-encoded public key (existing)
  isHardwareBacked: boolean;      // True if key in hardware keystore (existing)
  
  // NEW in v1.3.0
  useHardwareKey: boolean;        // Final decision made by module
  hardwareKeyRequested: boolean;  // What app requested
  tlsCompatible: boolean;         // Device supports HW keys for TLS
}
```

### New Method: `getHardwareKeystoreCapabilities()`

```typescript
getHardwareKeystoreCapabilities(): Promise<{
  tlsCompatible: boolean;        // Can use hardware keys for TLS (Android 12+)
  androidSdkVersion: number;     // Android SDK version
  hasStrongBox: boolean;         // Device has StrongBox secure element
  manufacturer: string;          // Device manufacturer
  model: string;                 // Device model
  device: string;                // Device codename
}>
```

---

## 🔒 Security Improvements

### File Security
- **Before**: File permissions relied on system defaults
- **After**: 
  - Explicit mode 0600 set using POSIX permissions on API 26+
  - Fallback to `File.setReadable/setWritable` on older APIs
  - Permissions set BEFORE writing data to minimize exposure window

### Keystore Operations
- **Atomic Writes**: Uses temp file + `Files.move(ATOMIC_MOVE)` on API 26+, falls back to `renameTo()`
- **Corruption Handling**: Renames corrupt files to `.corrupted.{timestamp}` instead of deleting
- **Dual-store Safety**: Prevents stale key collisions when switching between hardware/software

### Input Validation
- **IP Address Validation**: Enhanced to detect and reject:
  - Hostnames that resolve via DNS
  - `hostname:port` format (single colon check)
  - Suspicious patterns (spaces, //, @)
  - Handles IPv6 compressed addresses correctly

### Backup Protection
- **Android 6-11**: `backup_rules.xml` with `<full-backup-content>` exclusions
- **Android 12+**: `data_extraction_rules.xml` with `<cloud-backup>` and `<device-transfer>` exclusions
- **Critical**: Apps must reference these in `AndroidManifest.xml`

---

## 🐛 Bug Fixes

### Critical Fixes
1. **Race Condition in File Operations**: Synchronized keystore access prevents corruption
2. **Non-atomic Keystore Writes**: Temp file pattern prevents data loss on crashes
3. **Hostname Injection in IP Validation**: Enhanced validation prevents malformed certificates
4. **Stale Key Collision**: Automatic cleanup prevents getPublicKey() returning wrong key
5. **File Permission Race**: Permissions now set atomically before writing data

### Important Fixes
1. **IPv6 Compressed Address Validation**: Properly handles `2001:db8::1` format
2. **StrongBox Fallback**: Catches `StrongBoxUnavailableException` and retries with TEE
3. **Resource Leaks**: All file operations use try-with-resources
4. **ContentSigner Memory Leak**: Uses FilterOutputStream for incremental updates
5. **Corrupt Keystore Recovery**: Renames to `.corrupted` instead of silently deleting

---

## 🔧 Configuration Changes

### ProGuard/R8 Rules
Rules now automatically applied via `consumerProguardFiles`:

```proguard
# BouncyCastle - keep EC algorithm implementations
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.asn1.** { *; }
-keep class org.bouncycastle.cert.** { *; }
-keep class org.bouncycastle.pkcs.** { *; }
-keep class org.bouncycastle.operator.** { *; }
```

### Gradle Configuration
- **Android Gradle Plugin**: Upgraded to 8.6.0
- **Gradle Wrapper**: 9.0.0
- **compileSdk**: 36
- **minSdk**: 23 (unchanged)
- **targetSdk**: 36

### Dependencies Added
- `org.bouncycastle:bcprov-jdk18on:1.76`
- `org.bouncycastle:bcpkix-jdk18on:1.76`

---

## 📱 Device Compatibility

### Hardware Key Support
| Android Version | Hardware Keys | TLS Support | Recommendation |
|----------------|---------------|-------------|----------------|
| Android 11 and below | Available | ❌ No `PURPOSE_AGREE_KEY` | Use software keys |
| Android 12+ | Available | ✅ Full TLS support | Recommended for production |

### Automatic Behavior
- **Android 11 and below**: Module automatically uses software keys even if `useHardwareKey: true`
- **Android 12+**: Hardware keys work for TLS, used when requested
- **All versions**: Software keys work on all devices as fallback

---

## 🔄 Migration Guide

### From v1.2.x to v1.3.0

**Good News**: API is 100% backward compatible!

**Software Keystore Format Changed**:
- Old keystore files (if any) will need regeneration
- Module handles this automatically on first use
- No manual migration steps required

**What Apps Should Do**:

1. **Update Dependency**:
   ```json
   {
     "dependencies": {
       "@generacclean/react-native-ecc-csr": "1.3.0"
     }
   }
   ```

2. **Configure Backup Exclusion** (CRITICAL):
   ```xml
   <!-- android/app/src/main/AndroidManifest.xml -->
   <application
       android:fullBackupContent="@xml/backup_rules"
       android:dataExtractionRules="@xml/data_extraction_rules">
   ```

3. **Test on Real Devices**:
   - Test on Android 11 device (software keystore)
   - Test on Android 12+ device (hardware keystore option)
   - Verify MQTT mTLS connections work

4. **Optional - Check Capabilities**:
   ```typescript
   const caps = await CSRModule.getHardwareKeystoreCapabilities();
   console.log(`TLS Compatible: ${caps.tlsCompatible}`);
   ```

---

## 🧪 Testing

### Verified On
- ✅ Google Pixel 8 (Android 15) - Software keystore
- ✅ Samsung Galaxy devices (Android 12+) - Hardware keystore with TEE
- ✅ Google Pixel 5+ (Android 12+) - Hardware keystore with StrongBox

### Test Coverage
- Unit tests for BouncyCastle provider initialization
- Unit tests for input validation (IP addresses, curves, DN values)
- Unit tests for CSR format handling
- Manual testing of MQTT mTLS connections
- Verification of ProGuard/R8 in release builds

---

## ⚠️ Important Notes

### Security Considerations

**Software Keystore Storage**:
- Keys stored in PKCS12 format in app-private directory
- File permissions: mode 0600 (owner read/write only)
- Protected by Android app sandbox
- **Important**: Apps MUST configure backup exclusion rules

**Hardware Keystore (Recommended for Production)**:
- Keys stored in Android Keystore (TEE or StrongBox)
- Protected by hardware security module
- Private keys cannot be extracted
- Automatically used on Android 12+ when `useHardwareKey: true`

### Known Limitations

1. **Backup Rules**: Apps must manually reference `backup_rules.xml` in their manifest
2. **Android 11 and below**: Hardware keys don't support TLS ECDH
3. **Gradle Version**: Requires AGP 8.6.0+ and Gradle 9.0.0 (may require project updates)

---

## 📊 Code Quality Improvements

### Architecture
- ✅ Extracted focused methods from monolithic `generateCSR()`
- ✅ Centralized keystore file operations
- ✅ Clear separation of hardware vs software key generation
- ✅ Consistent error handling with context tracking

### Thread Safety
- ✅ Volatile flag with synchronized provider initialization
- ✅ Double-checked locking pattern prevents race conditions
- ✅ `SOFTWARE_KEYSTORE_LOCK` for file access synchronization

### Error Handling
- ✅ Error context tracking through CSR generation steps
- ✅ Escalated failures for critical operations
- ✅ Corruption recovery with forensic preservation

---

## 📖 Documentation

### New Documentation
- `docs/INTELLIGENT_KEYSTORE_SELECTION.md` - Hardware/software selection guide
- `docs/RELEASE_NOTES.md` - Detailed release notes
- `android/src/test/README.md` - Unit testing guide

### Updated Documentation
- `README.md` - Comprehensive security guidance and API documentation
- Inline code comments explaining security rationale
- ProGuard configuration documentation

---

## 🔗 Related Issues

- Fixes software keystore generation failures
- Resolves BouncyCastle provider conflicts on Android
- Addresses TLS compatibility issues on Android 11 and below
- Improves security posture for software key storage

---

## 👥 Contributors

- Ved Yedla (@vedgenerac)
- Code review feedback from automated reviewers and team

---

## 🎉 Summary

Version 1.3.0 represents a significant improvement in reliability, security, and device compatibility:

✅ **Reliability**: Software keystore now works consistently across all Android versions  
✅ **Security**: Enhanced file permissions, atomic operations, corruption recovery  
✅ **Compatibility**: Intelligent hardware/software selection based on device capabilities  
✅ **Code Quality**: Better architecture, thread safety, and error handling  
✅ **Testing**: Comprehensive unit tests and real device verification  

For detailed technical information, see the updated README.md and documentation files.

---

**Upgrade Recommendation**: ✅ Recommended for all users. Test thoroughly before production deployment.
