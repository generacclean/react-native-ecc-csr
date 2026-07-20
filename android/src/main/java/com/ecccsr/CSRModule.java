package com.ecccsr;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.MasterKey;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CSRModule extends ReactContextBaseJavaModule {

    private static final String MODULE_NAME = "CSRModule";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    private static final String SOFTWARE_KEYSTORE_FILE = "software_keys.p12";

    // Align defaults with documentation (Generac-specific values)
    private static final String DEFAULT_COUNTRY = "US";
    private static final String DEFAULT_STATE = "Wisconsin";
    private static final String DEFAULT_LOCALITY = "Waukesha";
    private static final String DEFAULT_ORGANIZATION = "Generac Power Systems";
    private static final String DEFAULT_ORGANIZATIONAL_UNIT = "Field Pro";
    private static final String DEFAULT_IP_ADDRESS = "10.10.10.10";
    private static final String DEFAULT_ECC_CURVE = "secp384r1";

    // Keep a direct reference to our full BouncyCastle provider instance
    // to avoid getting the system's stripped-down BC provider
    private static final Provider FULL_BC_PROVIDER = new BouncyCastleProvider();

    // Thread-safe provider initialization
    private static volatile boolean providerInitialized = false;
    private static final Object providerLock = new Object();

    // Race condition protection for software keystore file access
    private static final Object SOFTWARE_KEYSTORE_LOCK = new Object();

    // Cached master key to prevent "No matching key found" errors
    // Issue: Creating new MasterKey instances can lead to key mismatches
    // MUST be static to survive across CSRModule instance recreations (hot reload, bridge restarts)
    // MUST be cleared when decryption fails (master key invalidated by OS/app reinstall)
    private static volatile MasterKey cachedMasterKey = null;
    private static final Object MASTER_KEY_LOCK = new Object();

    /**
     * Invalidate cached master key when decryption fails.
     *
     * This happens when:
     * - App data is cleared
     * - App is reinstalled
     * - OS invalidates the master key (rare but possible)
     * - Keystore file was encrypted with a different master key
     *
     * Clearing the cache AND the Tink keyset allows getEncryptedKeystoreFile() to create
     * a fresh master key and keyset on the next call, which can then decrypt/encrypt successfully.
     *
     * CRITICAL: Must also clear the Tink keyset from SharedPreferences.
     * When the master key in Android Keystore is deleted (e.g., on app reinstall),
     * the keyset still references the old key. Creating a new master key with the same alias
     * results in "No matching key found for the ciphertext in the stream" because the keyset
     * was encrypted with the old key. Deleting the keyset forces Tink to generate a fresh one.
     */
    private void invalidateCachedMasterKey() {
        synchronized (MASTER_KEY_LOCK) {
            if (cachedMasterKey != null) {
                Log.i(MODULE_NAME, "Invalidating cached master key due to decryption failure");
                cachedMasterKey = null;

                // Clear the Tink keyset from SharedPreferences
                // This is necessary because the keyset is bound to the old master key that no longer exists.
                // When a new MasterKey is created, Tink will generate a fresh keyset for it.
                try {
                    Context context = getReactApplicationContext();
                    SharedPreferences prefs = context.getSharedPreferences(
                        "__androidx_security_crypto_encrypted_file_pref__",
                        Context.MODE_PRIVATE
                    );

                    // Only clear if the keyset exists (defensive check)
                    if (prefs.contains("__androidx_security_crypto_encrypted_file_keyset__")) {
                        SharedPreferences.Editor editor = prefs.edit();
                        editor.remove("__androidx_security_crypto_encrypted_file_keyset__");
                        editor.apply();
                        Log.i(MODULE_NAME, "Cleared stale Tink keyset from SharedPreferences");
                    }
                } catch (Exception e) {
                    Log.w(MODULE_NAME, "Failed to clear Tink keyset (will retry on next attempt): " + e.getMessage());
                }
            }
        }
    }

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
        ensureBouncyCastleProvider();
    }

    // Simplified BC provider initialization logic
    private void ensureBouncyCastleProvider() {
        // Fast path - if already initialized, return immediately
        if (providerInitialized) {
            return;
        }

        // Slow path - synchronize and initialize
        synchronized (providerLock) {
            // Double-check after acquiring lock
            if (providerInitialized) {
                return;
            }

            /*
             * IMPORTANT: Process-wide security provider modification
             *
             * Security.removeProvider("BC") removes the system BouncyCastle provider
             * from the ENTIRE JVM process, not just this module. This affects all
             * code in the host application that uses cryptographic operations.
             *
             * WHY THIS IS NECESSARY:
             * - Android includes a stripped-down BouncyCastle provider that only supports
             *   RSA, DSA, and DH algorithms - NOT Elliptic Curve (EC)
             * - If we don't remove it, algorithm lookups by name "BC" will find the
             *   system provider first and fail with NoSuchAlgorithmException for EC
             * - This module always passes FULL_BC_PROVIDER directly (not by name) to
             *   avoid depending on provider ordering, but removal prevents accidental
             *   usage of the system BC by other code
             *
             * IMPACT ON OTHER LIBRARIES:
             * - Other crypto libraries in the app will use our full BC provider instead
             *   of the system's stripped version
             * - This is generally BENEFICIAL (more algorithms available) but could
             *   theoretically cause compatibility issues if other code depends on
             *   specific system BC behavior
             * - If this causes conflicts, consider NOT removing the system provider
             *   and only using FULL_BC_PROVIDER explicitly throughout this module
             */
            Security.removeProvider("BC");

            // Insert our full provider at position 1 (highest priority)
            Security.insertProviderAt(FULL_BC_PROVIDER, 1);

            providerInitialized = true;

            // Only log details in debug builds
            if (BuildConfig.DEBUG) {
                Log.d(MODULE_NAME, "BouncyCastle provider registered successfully");
                Log.d(MODULE_NAME, "BC Provider version: " + FULL_BC_PROVIDER.getVersion());
                Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.getClass().getName());

                Log.d(MODULE_NAME, "All registered security providers:");
                for (Provider provider : Security.getProviders()) {
                    Log.d(MODULE_NAME, "  - " + provider.getName() + " v" + provider.getVersion() +
                          " (" + provider.getClass().getName() + ")");
                }
            } else {
                Log.i(MODULE_NAME, "BouncyCastle provider registered (v" + FULL_BC_PROVIDER.getVersion() + ")");
            }
        }
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    /**
     * ContentSigner implementation for Android Keystore.
     *
     * Uses a FilterOutputStream to feed signature.update() incrementally during writes
     * rather than buffering the full payload. This is architecturally safer than buffering
     * the entire TBS (to-be-signed) data in a ByteArrayOutputStream and feeding it to the
     * Signature object only in getSignature().
     */
    private static class AndroidKeystoreContentSigner implements ContentSigner {
        private final AlgorithmIdentifier sigAlgId;
        private final Signature signature;
        private final OutputStream outputStream;

        public AndroidKeystoreContentSigner(PrivateKey privateKey, String algorithm) throws Exception {
            this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            this.signature = Signature.getInstance(algorithm);
            this.signature.initSign(privateKey);

            // Wrap a FilterOutputStream that feeds signature.update() on each write
            this.outputStream = new FilterOutputStream(new ByteArrayOutputStream()) {
                @Override
                public void write(int b) throws IOException {
                    try {
                        signature.update((byte) b);
                    } catch (SignatureException e) {
                        throw new IOException("Signature update failed", e);
                    }
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    try {
                        signature.update(b, off, len);
                    } catch (SignatureException e) {
                        throw new IOException("Signature update failed", e);
                    }
                }
            };
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return sigAlgId;
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public byte[] getSignature() {
            try {
                // Signature already updated incrementally via outputStream writes
                return signature.sign();
            } catch (Exception e) {
                throw new RuntimeException("Failed to sign", e);
            } finally {
                try {
                    outputStream.close();
                } catch (IOException ignored) {
                    // FilterOutputStream close - safe to ignore
                }
            }
        }
    }

    private X509Certificate createSelfSignedCertificate(KeyPair keyPair, String subjectDN) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000);

        X500Name subject = new X500Name(subjectDN);
        BigInteger serialNumber = BigInteger.valueOf(now);
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject, serialNumber, startDate, endDate, subject, publicKeyInfo);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(FULL_BC_PROVIDER)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(FULL_BC_PROVIDER)
                .getCertificate(certBuilder.build(signer));
    }

    private boolean canUseHardwareKeysForTLS() {
        // Android 12 (API 31) added PURPOSE_AGREE_KEY support for ECDH in hardware keystore
        return android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S;
    }

    /**
     * IP address validation - accepts only literal IP addresses, not hostnames.
     *
     * InetAddress.getByName() accepts hostnames that resolve via DNS, so we must
     * verify the input is a literal address by comparing the input to the resolved
     * address string. This prevents hostname injection into SAN iPAddress extensions,
     * which would produce malformed certificates.
     */
    private boolean isValidIPAddress(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return false;
        }
        try {
            String trimmed = ip.trim();
            InetAddress addr = InetAddress.getByName(trimmed);

            // Verify input is a literal IP address, not a hostname that resolved
            // For IPv6: normalize both sides by parsing and re-stringifying
            // This handles compressed forms (2001:db8::1) vs uncompressed (2001:db8:0:0:0:0:0:1)
            String resolvedAddr = addr.getHostAddress();
            String inputForComparison = trimmed.replace("[", "").replace("]", "");

            // Try direct comparison first (handles IPv4 and exact IPv6 matches)
            if (resolvedAddr.equals(inputForComparison)) {
                return true;
            }

            // For IPv6 compressed addresses, normalize both sides by re-parsing
            // Only do this for inputs that look like IPv6 (contain ':')
            // to avoid accepting hostnames that resolve to the same IP
            if (inputForComparison.contains(":")) {
                // If input is a valid IPv6 literal, parsing it should yield the same InetAddress
                try {
                    InetAddress inputAddr = InetAddress.getByName(inputForComparison);
                    return inputAddr.equals(addr);
                } catch (UnknownHostException e) {
                    // Input couldn't be re-parsed, likely invalid
                    return false;
                }
            }

            // Not IPv4 match, not IPv6 literal - reject as hostname
            return false;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    // Encryption at rest using AndroidX EncryptedFile
    private EncryptedFile getEncryptedKeystoreFile(Context context) throws Exception {
        // Use cached master key to prevent "No matching key found" errors
        synchronized (MASTER_KEY_LOCK) {
            if (cachedMasterKey == null) {
                Log.d(MODULE_NAME, "Creating new MasterKey instance (first use)");
                cachedMasterKey = new MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();
            }
        }

        File file = new File(context.getFilesDir(), SOFTWARE_KEYSTORE_FILE);

        // Set explicit file permissions (mode 0600)
        if (file.exists()) {
            setSecureFilePermissions(file);
        }

        return new EncryptedFile.Builder(
            context,
            file,
            cachedMasterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
            .build();
    }

    // Explicitly set file permissions
    private void setSecureFilePermissions(File file) {
        try {
            // Set mode 0600 (owner read/write only)
            file.setReadable(false, false);   // No one can read
            file.setReadable(true, true);     // Owner can read
            file.setWritable(false, false);   // No one can write
            file.setWritable(true, true);     // Owner can write
            file.setExecutable(false, false); // No execution

            // For API 26+, use NIO for POSIX permissions (more explicit)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(file.toPath(), perms);
            }
        } catch (Exception e) {
            Log.w(MODULE_NAME, "Could not set file permissions explicitly (may not be supported): " + e.getMessage());
        }
    }

    // Sanitize DN values (already handled by X500NameBuilder, but add explicit method)
    private String sanitizeDNValue(String value) {
        if (value == null) {
            return "";
        }
        // X500NameBuilder already handles escaping, but trim whitespace
        return value.trim();
    }

    @ReactMethod
    public void generateCSR(ReadableMap params, Promise promise) {
        KeyPair keyPair = null;
        PKCS10CertificationRequest csr = null;
        String currentStep = "initialization";

        try {
            // Extract and validate parameters
            currentStep = "parameter extraction";
            String country = sanitizeDNValue(params.hasKey("country") ? params.getString("country") : DEFAULT_COUNTRY);
            String state = sanitizeDNValue(params.hasKey("state") ? params.getString("state") : DEFAULT_STATE);
            String locality = sanitizeDNValue(params.hasKey("locality") ? params.getString("locality") : DEFAULT_LOCALITY);
            String organization = sanitizeDNValue(params.hasKey("organization") ? params.getString("organization") : DEFAULT_ORGANIZATION);
            String organizationalUnit = sanitizeDNValue(params.hasKey("organizationalUnit") ? params.getString("organizationalUnit") : DEFAULT_ORGANIZATIONAL_UNIT);
            String commonName = sanitizeDNValue(params.hasKey("commonName") ? params.getString("commonName") : "");
            String serialNumber = sanitizeDNValue(params.hasKey("serialNumber") ? params.getString("serialNumber") : "");
            String ipAddress = params.hasKey("ipAddress") ? params.getString("ipAddress") : DEFAULT_IP_ADDRESS;
            String dnsName = params.hasKey("dnsName") ? params.getString("dnsName") : null;
            String curve = params.hasKey("curve") ? params.getString("curve") : DEFAULT_ECC_CURVE;
            String phoneInfo = params.hasKey("phoneInfo") ? params.getString("phoneInfo") : null;
            String privateKeyAlias = params.hasKey("privateKeyAlias") ? params.getString("privateKeyAlias") : null;

            // Validate required parameters
            if (privateKeyAlias == null || privateKeyAlias.trim().isEmpty()) {
                promise.reject("MISSING_ALIAS", "privateKeyAlias is required");
                return;
            }
            privateKeyAlias = privateKeyAlias.trim();

            if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
                promise.reject("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
                return;
            }

            // Validate IP address
            if (ipAddress != null && !ipAddress.trim().isEmpty() && !isValidIPAddress(ipAddress)) {
                promise.reject("INVALID_IP", "Invalid IP address format: " + ipAddress);
                return;
            }

            // Keys are always allowed to be overwritten for simplicity.
            // If a key with the same alias exists, it will be replaced.

            // App can request hardware, but module decides based on TLS compatibility
            boolean requestedHardwareKey = params.hasKey("useHardwareKey") ? params.getBoolean("useHardwareKey") : false;

            // Override app preference if hardware won't work for TLS
            boolean useHardwareKey = requestedHardwareKey && canUseHardwareKeysForTLS();

            if (requestedHardwareKey && !useHardwareKey) {
                Log.w(MODULE_NAME, "Hardware key requested but not supported for TLS on this device (requires Android 12+). Using software keystore.");
            }

            Log.d(MODULE_NAME, "Starting CSR generation - alias: " + privateKeyAlias +
                  ", curve: " + curve + ", hardware: " + useHardwareKey);

            String keystoreCurve = curve;

            // Delete any existing key with the same alias from the OPPOSITE keystore
            // to prevent dual-store collision where getPublicKey returns stale key
            currentStep = "removing stale keys";
            try {
                if (useHardwareKey) {
                    // About to use hardware, delete any software key with same alias
                    deleteSoftwareKeyIfExists(privateKeyAlias);
                } else {
                    // About to use software, delete any hardware key with same alias
                    deleteHardwareKeyIfExists(privateKeyAlias);
                }
            } catch (Exception e) {
                Log.w(MODULE_NAME, "Failed to delete stale key from opposite keystore: " + e.getMessage());
            }

            // Generate key pair
            currentStep = "key generation";
            if (useHardwareKey) {
                keyPair = generateHardwareKeyPair(privateKeyAlias, keystoreCurve);
            } else {
                keyPair = generateSoftwareKeyPair(privateKeyAlias, keystoreCurve);
            }

            if (keyPair == null) {
                throw new Exception("Key pair generation returned null");
            }

            currentStep = "CSR building";
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            Log.d(MODULE_NAME, "Key pair generated: " + privateKeyAlias +
                  " (" + (useHardwareKey ? "hardware" : "software") + ", " + keystoreCurve + ")");

            // Build subject DN using X500NameBuilder (handles escaping)
            X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            subjectBuilder.addRDN(BCStyle.C, country);
            subjectBuilder.addRDN(BCStyle.ST, state);
            subjectBuilder.addRDN(BCStyle.L, locality);
            subjectBuilder.addRDN(BCStyle.O, organization);
            subjectBuilder.addRDN(BCStyle.OU, organizationalUnit);
            subjectBuilder.addRDN(BCStyle.CN, commonName);
            if (!serialNumber.isEmpty()) {
                subjectBuilder.addRDN(BCStyle.SERIALNUMBER, serialNumber);
            }
            X500Name subject = subjectBuilder.build();

            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

            // Add extensions
            ExtensionsGenerator extGen = new ExtensionsGenerator();

            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            extGen.addExtension(Extension.keyUsage, true, keyUsage);

            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
            extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

            List<GeneralName> sanList = new ArrayList<>();
            if (ipAddress != null && !ipAddress.trim().isEmpty()) {
                sanList.add(new GeneralName(GeneralName.iPAddress, ipAddress.trim()));
            }

            if (dnsName != null && !dnsName.trim().isEmpty()) {
                for (String dns : dnsName.split(",")) {
                    String trimmedDns = dns.trim();
                    if (!trimmedDns.isEmpty()) {
                        sanList.add(new GeneralName(GeneralName.dNSName, trimmedDns));
                    }
                }
            }

            if (phoneInfo != null && !phoneInfo.trim().isEmpty()) {
                sanList.add(new GeneralName(GeneralName.uniformResourceIdentifier, "phone:" + phoneInfo.trim()));
            }

            if (!sanList.isEmpty()) {
                GeneralNames subjectAltNames = new GeneralNames(sanList.toArray(new GeneralName[0]));
                extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
            }

            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

            currentStep = "CSR signing";
            ContentSigner signer = useHardwareKey
                    ? new AndroidKeystoreContentSigner(privateKey, "SHA256withECDSA")
                    : new JcaContentSignerBuilder("SHA256withECDSA").setProvider(FULL_BC_PROVIDER).build(privateKey);

            csr = csrBuilder.build(signer);

            currentStep = "result serialization";
            StringWriter csrWriter = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(csrWriter)) {
                pemWriter.writeObject(csr);
            }

            com.facebook.react.bridge.WritableMap response = com.facebook.react.bridge.Arguments.createMap();
            response.putString("csr", csrWriter.toString());
            response.putString("privateKeyAlias", privateKeyAlias);
            response.putString("publicKey", Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));
            response.putBoolean("isHardwareBacked", useHardwareKey && isHardwareBacked(privateKeyAlias));
            response.putBoolean("useHardwareKey", useHardwareKey);
            response.putBoolean("hardwareKeyRequested", requestedHardwareKey);
            response.putBoolean("tlsCompatible", canUseHardwareKeysForTLS());

            Log.d(MODULE_NAME, "CSR generated successfully (requested: " +
                  (requestedHardwareKey ? "hardware" : "software") +
                  ", actual: " + (useHardwareKey ? "hardware" : "software") + ")");
            promise.resolve(response);

        } catch (Exception e) {
            // Provide better error context
            String errorContext = "CSR generation failed at step: " + currentStep;
            if (keyPair == null) {
                errorContext += " (key generation failed)";
            } else if (csr == null) {
                errorContext += " (CSR signing failed)";
            }

            Log.e(MODULE_NAME, errorContext, e);
            promise.reject("CSR_GENERATION_ERROR", errorContext + ": " + e.getMessage(), e);
        }
    }

    private KeyPair generateHardwareKeyPair(String privateKeyAlias, String keystoreCurve) throws Exception {
        Log.d(MODULE_NAME, "Generating hardware-backed key pair");

        boolean hasStrongBox = false;
        boolean useStrongBox = false;

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            hasStrongBox = getReactApplicationContext().getPackageManager()
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);

            if (BuildConfig.DEBUG) {
                Log.d(MODULE_NAME, "Device StrongBox support: " + hasStrongBox);
            }
        }

        // Decide whether to use StrongBox or TEE
        if (hasStrongBox) {
            if (keystoreCurve.equals("secp256r1")) {
                useStrongBox = true;
                Log.d(MODULE_NAME, "Using StrongBox-backed key generation (P-256)");
            } else {
                Log.w(MODULE_NAME, "StrongBox only supports P-256. Requested curve: " + keystoreCurve + ". Using TEE instead.");
            }
        } else {
            Log.d(MODULE_NAME, "Using hardware-backed (TEE) key generation");
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);

        // Add clarifying comment about purpose flags
        // Note: canUseHardwareKeysForTLS() guarantees Android 12+, but we check again
        // for defense-in-depth in case this method is called directly
        int purposes = KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            purposes |= KeyProperties.PURPOSE_AGREE_KEY;
        }

        KeyGenParameterSpec.Builder specBuilder = new KeyGenParameterSpec.Builder(privateKeyAlias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(keystoreCurve))
                .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                .setUserAuthenticationRequired(false);

        if (useStrongBox) {
            specBuilder.setIsStrongBoxBacked(true);
        }

        keyPairGenerator.initialize(specBuilder.build());

        try {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Log.d(MODULE_NAME, "Hardware key pair generated successfully" + (useStrongBox ? " (StrongBox)" : " (TEE)"));
            return keyPair;
        } catch (android.security.keystore.StrongBoxUnavailableException e) {
            // StrongBox advertised but transiently unavailable - fall back to TEE once
            if (useStrongBox) {
                Log.w(MODULE_NAME, "StrongBox unavailable, falling back to TEE: " + e.getMessage());
                specBuilder.setIsStrongBoxBacked(false);
                keyPairGenerator.initialize(specBuilder.build());
                try {
                    KeyPair keyPair = keyPairGenerator.generateKeyPair();
                    Log.d(MODULE_NAME, "Hardware key pair generated successfully (TEE fallback)");
                    return keyPair;
                } catch (Exception retryException) {
                    Log.e(MODULE_NAME, "TEE fallback also failed: " + retryException.getMessage());
                    throw new Exception("Hardware key generation failed in both StrongBox and TEE. Error: " + retryException.getMessage(), retryException);
                }
            } else {
                // Not using StrongBox originally, so don't retry
                throw new Exception("Hardware key generation failed: " + e.getMessage(), e);
            }
        } catch (Exception e) {
            Log.e(MODULE_NAME, "Hardware key generation failed: " + e.getMessage());
            throw new Exception("Hardware key generation failed. Device may not support hardware-backed keys for curve " +
                              keystoreCurve + ". Error: " + e.getMessage(), e);
        }
    }

    private KeyPair generateSoftwareKeyPair(String privateKeyAlias, String keystoreCurve) throws Exception {
        Log.d(MODULE_NAME, "Generating software key pair");

        ensureBouncyCastleProvider();

        if (BuildConfig.DEBUG) {
            Log.d(MODULE_NAME, "Using full BouncyCastle provider version: " + FULL_BC_PROVIDER.getVersion());
            Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.getClass().getName());
        }

        // Generate EC key pair
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", FULL_BC_PROVIDER);
            if (BuildConfig.DEBUG) {
                Log.d(MODULE_NAME, "EC algorithm supported, provider: " + keyPairGenerator.getProvider().getName());
            }
        } catch (NoSuchAlgorithmException e) {
            Log.e(MODULE_NAME, "EC algorithm NOT supported by BouncyCastle provider!", e);
            if (BuildConfig.DEBUG) {
                Log.e(MODULE_NAME, "BC Provider info: " + FULL_BC_PROVIDER.getInfo());
                Log.e(MODULE_NAME, "Available algorithms in BC:");
                for (Provider.Service service : FULL_BC_PROVIDER.getServices()) {
                    if (service.getType().equals("KeyPairGenerator")) {
                        Log.e(MODULE_NAME, "  - " + service.getAlgorithm());
                    }
                }
            }
            throw new Exception("BouncyCastle provider does not support EC algorithm. Provider may be corrupted or stripped by ProGuard/R8.", e);
        }

        ECGenParameterSpec ecSpec = new ECGenParameterSpec(keystoreCurve);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Log.d(MODULE_NAME, "Software key pair generated successfully");

        // Synchronize all software keystore file operations
        synchronized (SOFTWARE_KEYSTORE_LOCK) {
            storeSoftwareKey(privateKeyAlias, keyPair);
        }

        return keyPair;
    }

    private void storeSoftwareKey(String privateKeyAlias, KeyPair keyPair) throws Exception {
        File keystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);
        EncryptedFile encFile = null;
        KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

        // Try to get EncryptedFile - may fail if master key/keyset is corrupt
        try {
            encFile = getEncryptedKeystoreFile(getReactApplicationContext());
        } catch (Exception e) {
            // Master key or Tink keyset is corrupt (AEADBadTagException)
            Log.w(MODULE_NAME, "EncryptedFile creation failed, invalidating cache: " + e.getMessage());
            invalidateCachedMasterKey();  // Clear stale master key cache AND delete Tink keyset

            // Retry with fresh master key
            try {
                encFile = getEncryptedKeystoreFile(getReactApplicationContext());
            } catch (Exception retryE) {
                Log.e(MODULE_NAME, "EncryptedFile retry also failed: " + retryE.getMessage());
                throw new Exception("Failed to create EncryptedFile after master key reset: " + retryE.getMessage(), retryE);
            }
        }

        // Try to load existing keystore, create new if doesn't exist or is corrupt
        try (FileInputStream fis = encFile.openFileInput()) {
            softwareKeyStore.load(fis, "".toCharArray());
        } catch (FileNotFoundException e) {
            // Keystore doesn't exist yet, create a new one
            softwareKeyStore.load(null, null);
        } catch (IOException | GeneralSecurityException e) {
            // Keystore is corrupt, undecryptable, or from incompatible version
            // (e.g., master key invalidated, OS upgrade, pre-1.2.0 plaintext file)
            // Delete the corrupt file and start fresh
            Log.w(MODULE_NAME, "Software keystore corrupt/undecryptable, reinitializing: " + e.getMessage());
            if (keystoreFile.exists() && !keystoreFile.delete()) {
                Log.e(MODULE_NAME, "Failed to delete corrupt keystore file");
            }
            softwareKeyStore.load(null, null);
        }

        String tempSubject = "CN=Temp-" + privateKeyAlias;
        X509Certificate selfSignedCert = createSelfSignedCertificate(keyPair, tempSubject);

        softwareKeyStore.setKeyEntry(
            privateKeyAlias,
            keyPair.getPrivate(),
            "".toCharArray(), // See security note below
            new java.security.cert.Certificate[] { selfSignedCert }
        );

        // Save keystore to encrypted file (atomic rewrite via temp file)
        // Write to .tmp file first, then rename to prevent data loss on write failure
        File tempKeystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE + ".tmp");

        // Delete any existing temp file
        if (tempKeystoreFile.exists() && !tempKeystoreFile.delete()) {
            throw new IOException("Failed to delete existing temp keystore file");
        }

        // Build EncryptedFile for temp path using cached master key
        synchronized (MASTER_KEY_LOCK) {
            if (cachedMasterKey == null) {
                Log.d(MODULE_NAME, "Creating new MasterKey instance for temp file (first use)");
                cachedMasterKey = new MasterKey.Builder(getReactApplicationContext())
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();
            }
        }
        EncryptedFile tempEncFile = new EncryptedFile.Builder(
            getReactApplicationContext(),
            tempKeystoreFile,
            cachedMasterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
            .build();

        // Write to temp file
        try (FileOutputStream fos = tempEncFile.openFileOutput()) {
            softwareKeyStore.store(fos, "".toCharArray()); // See security note below
        }

        // Atomic rename: only delete the real file after successful write to temp
        if (keystoreFile.exists() && !keystoreFile.delete()) {
            throw new IOException("Failed to delete existing keystore file before atomic rename");
        }

        if (!tempKeystoreFile.renameTo(keystoreFile)) {
            throw new IOException("Failed to atomically rename temp keystore to final path");
        }

        // Ensure file permissions are set after creation
        setSecureFilePermissions(keystoreFile);

        /*
         * SECURITY NOTE: Empty PKCS12 password rationale
         *
         * The PKCS12 keystore uses an empty password ("".toCharArray()) for both
         * KeyStore.load() and KeyStore.store(). This is acceptable because:
         *
         * 1. The containing EncryptedFile provides AES256-GCM encryption at rest
         * 2. The encryption key is hardware-backed in Android Keystore
         * 3. The file is protected by Android app sandbox (mode 0600)
         * 4. Backup exclusion rules prevent cloud/backup exposure
         *
         * The PKCS12 container structure remains (providing key/cert bundling),
         * but the encryption layer is handled by EncryptedFile instead of PKCS12's
         * password-based encryption. This design prioritizes hardware-backed
         * encryption over password-based encryption.
         *
         * Defense-in-depth alternative: Derive a device-unique PKCS12 password from
         * a separate Android Keystore AES key. This adds a second encryption layer
         * but increases complexity and may not significantly improve security given
         * the EncryptedFile layer already uses hardware-backed keys.
         */
    }

    @ReactMethod
    public void deleteKey(String privateKeyAlias, Promise promise) {
        try {
            boolean deleted = false;

            // Try hardware keystore first
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);
                if (keyStore.containsAlias(privateKeyAlias)) {
                    keyStore.deleteEntry(privateKeyAlias);
                    deleted = true;
                    Log.d(MODULE_NAME, "Deleted hardware key: " + privateKeyAlias);
                }
            } catch (Exception e) {
                // Continue to software keystore
            }

            // Synchronize software keystore access
            synchronized (SOFTWARE_KEYSTORE_LOCK) {
                try {
                    EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
                    KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
                    File keystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);

                    try (FileInputStream fis = encFile.openFileInput()) {
                        softwareKeyStore.load(fis, "".toCharArray());
                    } catch (FileNotFoundException e) {
                        // No software keystore exists
                        softwareKeyStore.load(null, null);
                    } catch (IOException | GeneralSecurityException e) {
                        // Keystore is corrupt/undecryptable - delete and start fresh
                        Log.w(MODULE_NAME, "Software keystore corrupt during delete, reinitializing: " + e.getMessage());
                        invalidateCachedMasterKey();  // Clear stale master key cache
                        if (keystoreFile.exists() && !keystoreFile.delete()) {
                            Log.e(MODULE_NAME, "Failed to delete corrupt keystore file");
                        }
                        softwareKeyStore.load(null, null);
                    }

                    if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                        softwareKeyStore.deleteEntry(privateKeyAlias);

                        // Atomic rewrite via temp file to prevent data loss
                        File tempKeystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE + ".tmp");

                        if (tempKeystoreFile.exists() && !tempKeystoreFile.delete()) {
                            throw new IOException("Failed to delete existing temp keystore file");
                        }

                        // Use cached master key
                        synchronized (MASTER_KEY_LOCK) {
                            if (cachedMasterKey == null) {
                                Log.d(MODULE_NAME, "Creating new MasterKey instance (hasSoftwareKey path)");
                                cachedMasterKey = new MasterKey.Builder(getReactApplicationContext())
                                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                                    .build();
                            }
                        }
                        EncryptedFile tempEncFile = new EncryptedFile.Builder(
                            getReactApplicationContext(),
                            tempKeystoreFile,
                            cachedMasterKey,
                            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
                            .build();

                        try (FileOutputStream fos = tempEncFile.openFileOutput()) {
                            softwareKeyStore.store(fos, "".toCharArray());
                        }

                        if (keystoreFile.exists() && !keystoreFile.delete()) {
                            throw new IOException("Failed to delete existing keystore file before atomic rename");
                        }

                        if (!tempKeystoreFile.renameTo(keystoreFile)) {
                            throw new IOException("Failed to atomically rename temp keystore to final path");
                        }

                        // Restore file permissions after rewrite
                        setSecureFilePermissions(keystoreFile);

                        deleted = true;
                        Log.d(MODULE_NAME, "Deleted software key: " + privateKeyAlias);
                    }
                } catch (FileNotFoundException e) {
                    // Keystore file doesn't exist, nothing to delete
                } catch (Exception e) {
                    Log.w(MODULE_NAME, "Error accessing software keystore: " + e.getMessage());
                }
            }

            promise.resolve(deleted);
        } catch (Exception e) {
            Log.e(MODULE_NAME, "Failed to delete key", e);
            promise.reject("DELETE_KEY_ERROR", "Failed to delete key: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void getHardwareKeystoreCapabilities(Promise promise) {
        try {
            com.facebook.react.bridge.WritableMap capabilities = com.facebook.react.bridge.Arguments.createMap();

            boolean tlsCompatible = canUseHardwareKeysForTLS();
            capabilities.putBoolean("tlsCompatible", tlsCompatible);
            capabilities.putInt("androidSdkVersion", android.os.Build.VERSION.SDK_INT);

            boolean hasStrongBox = false;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                hasStrongBox = getReactApplicationContext().getPackageManager()
                        .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
            }
            capabilities.putBoolean("hasStrongBox", hasStrongBox);

            capabilities.putString("manufacturer", android.os.Build.MANUFACTURER);
            capabilities.putString("model", android.os.Build.MODEL);
            capabilities.putString("device", android.os.Build.DEVICE);

            promise.resolve(capabilities);
        } catch (Exception e) {
            promise.reject("CAPABILITY_CHECK_ERROR", "Failed to check capabilities: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void keyExists(String privateKeyAlias, Promise promise) {
        try {
            // Check hardware keystore
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);
                if (keyStore.containsAlias(privateKeyAlias)) {
                    promise.resolve(true);
                    return;
                }
            } catch (Exception e) {
                // Continue to software keystore
            }

            // Synchronize software keystore access
            synchronized (SOFTWARE_KEYSTORE_LOCK) {
                File keystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);

                // First attempt
                try {
                    EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
                    KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

                    try (FileInputStream fis = encFile.openFileInput()) {
                        softwareKeyStore.load(fis, "".toCharArray());
                        promise.resolve(softwareKeyStore.containsAlias(privateKeyAlias));
                        return;
                    }
                } catch (FileNotFoundException e) {
                    promise.resolve(false);
                    return;
                } catch (Exception e) {
                    // Keystore is corrupt, undecryptable, or from incompatible version
                    // (e.g., master key invalidated after app reinstall, OS upgrade, pre-encrypted file)
                    Log.w(MODULE_NAME, "Software keystore corrupt/undecryptable in keyExists(), attempting recovery: " + e.getMessage());
                    invalidateCachedMasterKey();  // Clear stale master key cache

                    if (keystoreFile.exists()) {
                        Log.w(MODULE_NAME, "Deleting corrupt keystore file: " + keystoreFile.getAbsolutePath());
                        if (!keystoreFile.delete()) {
                            Log.e(MODULE_NAME, "Failed to delete corrupt keystore file");
                            promise.resolve(false);
                            return;
                        } else {
                            Log.i(MODULE_NAME, "Corrupt keystore deleted successfully");
                        }
                    }

                    // Retry with fresh master key
                    try {
                        // File was deleted, so this should return FileNotFoundException and resolve(false)
                        EncryptedFile encFileRetry = getEncryptedKeystoreFile(getReactApplicationContext());
                        KeyStore softwareKeyStoreRetry = KeyStore.getInstance("PKCS12");

                        try (FileInputStream fisRetry = encFileRetry.openFileInput()) {
                            softwareKeyStoreRetry.load(fisRetry, "".toCharArray());
                            promise.resolve(softwareKeyStoreRetry.containsAlias(privateKeyAlias));
                            return;
                        }
                    } catch (FileNotFoundException retryE) {
                        Log.i(MODULE_NAME, "Retry confirmed file deleted - fresh certificate generation will be triggered");
                        promise.resolve(false);
                        return;
                    } catch (Exception retryE) {
                        Log.e(MODULE_NAME, "Retry also failed: " + retryE.getMessage());
                        promise.resolve(false);
                        return;
                    }
                }
            }
        } catch (Exception e) {
            promise.reject("KEY_EXISTS_ERROR", "Failed to check key existence: " + e.getMessage(), e);
        }
    }

    @ReactMethod
    public void getPublicKey(String privateKeyAlias, Promise promise) {
        try {
            // Try hardware keystore first
            try {
                KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
                keyStore.load(null);

                if (keyStore.containsAlias(privateKeyAlias)) {
                    KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
                    if (entry instanceof KeyStore.PrivateKeyEntry) {
                        PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
                        promise.resolve(Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));
                        return;
                    }
                }
            } catch (Exception e) {
                // Continue to software keystore
            }

            // Synchronize software keystore access
            synchronized (SOFTWARE_KEYSTORE_LOCK) {
                File keystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);

                // Check file exists before trying to open it
                if (!keystoreFile.exists()) {
                    promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found");
                    return;
                }

                EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

                try (FileInputStream fis = encFile.openFileInput()) {
                    softwareKeyStore.load(fis, "".toCharArray());
                } catch (FileNotFoundException e) {
                    promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found");
                    return;
                } catch (IOException | GeneralSecurityException e) {
                    // Keystore is corrupt/undecryptable - delete and report key not found
                    Log.w(MODULE_NAME, "Software keystore corrupt during getPublicKey, reinitializing: " + e.getMessage());
                    invalidateCachedMasterKey();  // Clear stale master key cache
                    if (keystoreFile.exists() && !keystoreFile.delete()) {
                        Log.e(MODULE_NAME, "Failed to delete corrupt keystore file");
                    }
                    promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found (keystore was corrupt)");
                    return;
                }

                if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                    KeyStore.Entry entry = softwareKeyStore.getEntry(
                        privateKeyAlias,
                        new KeyStore.PasswordProtection("".toCharArray())
                    );
                    if (entry instanceof KeyStore.PrivateKeyEntry) {
                        PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
                        promise.resolve(Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));
                        return;
                    }
                }
            }

            promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found");

        } catch (Exception e) {
            promise.reject("GET_PUBLIC_KEY_ERROR", "Failed to get public key: " + e.getMessage(), e);
        }
    }

    private boolean isHardwareBacked(String privateKeyAlias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);

            KeyStore.Entry entry = keyStore.getEntry(privateKeyAlias, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    KeyFactory factory = KeyFactory.getInstance(
                            ((KeyStore.PrivateKeyEntry) entry).getPrivateKey().getAlgorithm(),
                            ANDROID_KEYSTORE);
                    KeyInfo keyInfo = factory.getKeySpec(
                            ((KeyStore.PrivateKeyEntry) entry).getPrivateKey(),
                            KeyInfo.class);
                    return keyInfo.isInsideSecureHardware();
                }
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    // Helper method to delete hardware key if it exists
    private void deleteHardwareKeyIfExists(String privateKeyAlias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(privateKeyAlias)) {
            keyStore.deleteEntry(privateKeyAlias);
            Log.d(MODULE_NAME, "Deleted stale hardware key: " + privateKeyAlias);
        }
    }

    // Helper method to delete software key if it exists
    private void deleteSoftwareKeyIfExists(String privateKeyAlias) throws Exception {
        synchronized (SOFTWARE_KEYSTORE_LOCK) {
            File keystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);
            if (!keystoreFile.exists()) {
                return;
            }

            EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
            KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

            try (FileInputStream fis = encFile.openFileInput()) {
                softwareKeyStore.load(fis, "".toCharArray());
            } catch (FileNotFoundException e) {
                return;
            } catch (IOException | GeneralSecurityException e) {
                // Keystore is corrupt - delete and return
                Log.w(MODULE_NAME, "Software keystore corrupt during stale key deletion: " + e.getMessage());
                invalidateCachedMasterKey();  // Clear stale master key cache
                if (keystoreFile.exists() && !keystoreFile.delete()) {
                    Log.e(MODULE_NAME, "Failed to delete corrupt keystore file");
                }
                return;
            }

            if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                softwareKeyStore.deleteEntry(privateKeyAlias);

                // Atomic rewrite via temp file
                File tempKeystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE + ".tmp");

                if (tempKeystoreFile.exists() && !tempKeystoreFile.delete()) {
                    throw new IOException("Failed to delete existing temp keystore file");
                }

                // Use cached master key
                synchronized (MASTER_KEY_LOCK) {
                    if (cachedMasterKey == null) {
                        Log.d(MODULE_NAME, "Creating new MasterKey instance (getPublicKey path)");
                        cachedMasterKey = new MasterKey.Builder(getReactApplicationContext())
                            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                            .build();
                    }
                }
                EncryptedFile tempEncFile = new EncryptedFile.Builder(
                    getReactApplicationContext(),
                    tempKeystoreFile,
                    cachedMasterKey,
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
                    .build();

                try (FileOutputStream fos = tempEncFile.openFileOutput()) {
                    softwareKeyStore.store(fos, "".toCharArray());
                }

                if (keystoreFile.exists() && !keystoreFile.delete()) {
                    throw new IOException("Failed to delete existing keystore file before atomic rename");
                }

                if (!tempKeystoreFile.renameTo(keystoreFile)) {
                    throw new IOException("Failed to atomically rename temp keystore to final path");
                }

                setSecureFilePermissions(keystoreFile);
                Log.d(MODULE_NAME, "Deleted stale software key: " + privateKeyAlias);
            }
        }
    }
}
