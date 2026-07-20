# BouncyCastle ProGuard/R8 Rules
# Prevent stripping of BouncyCastle cryptographic algorithms

# Keep public API classes (more specific than keeping everything)
-keep public class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }

# Keep EC (Elliptic Curve) algorithm implementations - critical for this library
-keep class org.bouncycastle.jcajce.provider.asymmetric.ec.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }

# Keep crypto primitives and ASN.1 structures
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.asn1.** { *; }

# Keep certificate and PKCS classes (for CSR generation)
-keep class org.bouncycastle.cert.** { *; }
-keep class org.bouncycastle.pkcs.** { *; }
-keep class org.bouncycastle.operator.** { *; }
-keep class org.bouncycastle.openssl.** { *; }

# Keep Security Provider registration (used via reflection)
-keepclassmembers class * extends java.security.Provider {
    <init>(...);
}

# Prevent optimization of crypto algorithms
-keepnames class org.bouncycastle.jcajce.provider.** { *; }
-keepnames class org.bouncycastle.jce.provider.** { *; }

# Suppress warnings for optional dependencies
-dontwarn org.bouncycastle.**

# AndroidX Security Library (for EncryptedFile)
-keep class androidx.security.crypto.** { *; }
-keepclassmembers class androidx.security.crypto.** { *; }
