# System BouncyCastle Provider Conflict Fix

## Issue

The CSR generation was failing with:
```
java.security.NoSuchAlgorithmException: no such algorithm: EC for provider BC
```

Even though BouncyCastle was being registered, the EC algorithm was not available. The logs showed:
```
BC Provider version: 1.77
BC Provider class: com.android.org.bouncycastle.jce.provider.BouncyCastleProvider
Available algorithms in BC:
  - DSA
  - DH
  - RSA
```

Notice **EC (Elliptic Curve) is missing** from the available algorithms!

## Root Cause

Android includes a **stripped-down BouncyCastle provider** as part of the system:
- Package: `com.android.org.bouncycastle.jce.provider.BouncyCastleProvider`
- Name: `BC` (same as our provider!)
- Version: `1.77`
- **Problem**: Only includes DSA, DH, and RSA algorithms - **no EC support**

When our code registered a full BouncyCastle provider and then looked it up by name (`"BC"`), Java's security framework was returning the **system's stripped provider** instead of our full one, because:
1. Android loads the system BC provider at boot
2. Looking up by name (`Security.getProvider("BC")`) returns the **first** provider with that name
3. The system's BC provider was at a higher priority position

## Why This Happens

Android strips down BouncyCastle for size/performance reasons and bundles it as part of the OS. Many cryptographic operations are handled by other providers (AndroidKeyStore, Conscrypt), so Android doesn't need the full BC library for most use cases.

However, for **software-backed EC keys**, we need the full BouncyCastle library with EC support.

## The Fix

Instead of looking up the provider by name (which could return the wrong one), we now:

### 1. Keep a Direct Reference to Our Provider

```java
// Keep a direct reference to our full BouncyCastle provider instance
// to avoid getting the system's stripped-down BC provider
private static final Provider FULL_BC_PROVIDER = new BouncyCastleProvider();
```

This creates **our own instance** of the full BouncyCastle provider from our bundled library (`bcprov-jdk18on:1.76`).

### 2. Remove System BC Provider

```java
// Remove the system's stripped BC provider if it exists
Provider systemBcProvider = Security.getProvider("BC");
if (systemBcProvider != null && systemBcProvider.getClass().getName().startsWith("com.android.org.bouncycastle")) {
    Log.d(MODULE_NAME, "Found Android system BC provider (stripped): " + systemBcProvider.getClass().getName());
    Log.d(MODULE_NAME, "Removing system BC provider to avoid conflicts");
    Security.removeProvider("BC");
}
```

This removes the system's stripped provider so it won't conflict with ours.

### 3. Register Our Provider at Highest Priority

```java
// Register our full BouncyCastle provider at position 1 (highest priority)
Security.insertProviderAt(FULL_BC_PROVIDER, 1);
```

This ensures our provider is checked first for all algorithm lookups.

### 4. Use Provider Instance Directly

**Before:**
```java
KeyPairGenerator.getInstance("EC", "BC")  // Could get system BC!
KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)  // Could get system BC!
```

**After:**
```java
KeyPairGenerator.getInstance("EC", FULL_BC_PROVIDER)  // Always gets our full BC!
```

By passing the **provider instance** instead of a name, we guarantee we're using our full BouncyCastle provider with EC support.

### Changed in All These Locations:

1. **Software key pair generation** (line ~306):
   ```java
   KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", FULL_BC_PROVIDER);
   ```

2. **Self-signed certificate creation** (lines ~153-158):
   ```java
   ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
           .setProvider(FULL_BC_PROVIDER)
           .build(keyPair.getPrivate());

   return new JcaX509CertificateConverter()
           .setProvider(FULL_BC_PROVIDER)
           .getCertificate(certBuilder.build(signer));
   ```

3. **CSR signing for software keys** (line ~388):
   ```java
   ContentSigner signer = useHardwareKey
           ? new AndroidKeystoreContentSigner(privateKey, "SHA256withECDSA")
           : new JcaContentSignerBuilder("SHA256withECDSA").setProvider(FULL_BC_PROVIDER).build(privateKey);
   ```

## Verification

After this fix, you should see in the logs:

```
D CSRModule: Found Android system BC provider (stripped): com.android.org.bouncycastle.jce.provider.BouncyCastleProvider
D CSRModule: Removing system BC provider to avoid conflicts
D CSRModule: Registering full BouncyCastle provider at highest priority
D CSRModule: Full BouncyCastle provider registered successfully
D CSRModule: BC Provider version: 1.76
D CSRModule: BC Provider class: org.bouncycastle.jce.provider.BouncyCastleProvider
D CSRModule: All registered security providers:
  - BC v1.76 (org.bouncycastle.jce.provider.BouncyCastleProvider)  <-- Our full provider at position 1
  - AndroidNSSP v1.0 (...)
  - AndroidOpenSSL v1.0 (...)
  ...
D CSRModule: Checking EC algorithm support in full BouncyCastle...
D CSRModule: EC algorithm IS supported by BouncyCastle: BC
D CSRModule: Software key pair generated successfully
```

Notice:
- System BC provider is **removed**
- Our BC provider is at **position 1** (highest priority)
- Provider class is `org.bouncycastle...` (ours) not `com.android.org.bouncycastle...` (system)
- **EC algorithm is supported**

## Why This Fix Works

1. **No Name Conflicts**: By removing the system BC provider, there's only one provider named "BC"
2. **Highest Priority**: Our provider is checked first for all lookups
3. **Direct Reference**: Using `FULL_BC_PROVIDER` instance bypasses name lookup entirely
4. **Full Algorithm Support**: Our bundled BouncyCastle (v1.76) includes EC, ECDSA, and all crypto algorithms we need

## ProGuard/R8 Rules

The `proguard-rules.pro` file ensures our BouncyCastle library isn't stripped during release builds:

```proguard
# Keep all BouncyCastle classes
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep EC (Elliptic Curve) algorithm implementations
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
```

Make sure the **consuming app** also includes these ProGuard rules in their `proguard-rules.pro`.

## Testing

Test software key generation:
```typescript
const result = await CSRModule.generateCSR({
  commonName: 'test-device',
  privateKeyAlias: 'test-software-key',
  useHardwareKey: false,  // Force software keys
});

console.log('Software key generated:', !result.isHardwareBacked);
```

Check the logs for "EC algorithm IS supported" and "Software key pair generated successfully".

## Summary

**Problem**: System's stripped BC provider was being used instead of our full BC provider, causing EC algorithm to be unavailable.

**Solution**: 
- Remove system BC provider to avoid conflicts
- Keep direct reference to our full BC provider instance
- Register our provider at highest priority
- Use provider instance directly instead of name lookup

**Result**: Software-backed EC keys now generate successfully, enabling proper fallback from hardware keys on devices where hardware keys don't support TLS (Android < 12).
