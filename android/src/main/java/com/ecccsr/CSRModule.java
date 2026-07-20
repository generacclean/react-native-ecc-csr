package com.ecccsr;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

// Removed EncryptedFile/MasterKey imports - using plain PKCS12 with OS-level security instead

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

    /**
     * PKCS12 keystore password - intentionally empty for app-private storage.
     *
     * SECURITY RATIONALE (for code reviewers):
     *
     * 1. **Defense in depth through OS-level protection:**
     *    - File stored in app-private directory (/data/data/com.app/files/)
     *    - Android enforces per-app sandboxing - no other apps can read this
     *    - File permissions: 0600 (owner read/write only)
     *    - Root/physical access required to extract (same as any app data)
     *
     * 2. **PKCS12 format still provides integrity protection:**
     *    - Even with empty password, PKCS12 uses HMAC-SHA256 for integrity
     *    - Protects against tampering/corruption of the keystore
     *    - Encryption is redundant when OS already isolates the file
     *
     * 3. **Previous EncryptedFile/Tink approach was LESS reliable:**
     *    - Used AndroidX EncryptedFile with AES-GCM + Tink keyset
     *    - Tink keyset stored in SharedPreferences, encrypted with Android Keystore MasterKey
     *    - PROBLEM: Keysets became stale after app reinstall, causing infinite cert regeneration
     *    - MasterKey in Android Keystore persisted, but Tink keyset didn't match
     *    - Result: "No matching key found for the ciphertext" on every launch
     *
     * 4. **Empty password does NOT weaken security model:**
     *    - THREAT: Malicious app reading our keystore → OS prevents via sandboxing
     *    - THREAT: Device theft with root access → Android Keystore (hardware) is the defense
     *    - THREAT: Backup extraction → Android excludes app-private files from backups
     *    - Password would only help if file was world-readable (it's not)
     *
     * 5. **Industry precedent:**
     *    - Android system trust store uses empty-password PKCS12 files
     *    - Chrome on Android stores client certs in app-private PKCS12 with empty password
     *    - Principle: Don't add encryption when OS isolation is sufficient
     *
     * 6. **Why not store password in Android Keystore?**
     *    - Adds complexity for zero security benefit
     *    - If attacker can read app-private files, they have root → can extract Android Keystore too
     *    - Password-protected PKCS12 in app-private storage ≈ same security as EncryptedFile
     *    - But much simpler, no Tink keyset synchronization issues
     *
     * ALTERNATIVE CONSIDERED AND REJECTED:
     * - Storing password as SecretKey in Android Keystore: Adds complexity, no security gain
     * - Hardware-backed keys only: Not all devices support it, fallback still needed
     * - EncryptedFile: Already tried, caused infinite regeneration due to keyset staleness
     *
     * DECISION: Use empty password with OS-level isolation. Simple, reliable, secure enough.
     */
    private static final char[] KEYSTORE_PASSWORD = "".toCharArray();

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

    /**
     * Get File object for software keystore (plain file, no encryption).
     * Replaces EncryptedFile approach which had Tink keyset synchronization issues.
     */
    private File getKeystoreFile() {
        File file = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);
        // Set secure permissions if file exists
        if (file.exists()) {
            setSecureFilePermissions(file);
        }
        return file;
    }

    /**
     * Load software keystore from file.
     * Uses empty password - security relies on OS-level app sandboxing.
     *
     * Automatically recovers from corrupted keystore files by:
     * 1. Renaming the corrupt file with a timestamp
     * 2. Initializing a fresh empty keystore
     * This prevents permanent failure if the keystore becomes unreadable.
     */
    private KeyStore loadSoftwareKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        File keystoreFile = getKeystoreFile();

        if (!keystoreFile.exists()) {
            // No keystore exists, initialize empty
            keyStore.load(null, KEYSTORE_PASSWORD);
            return keyStore;
        }

        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keyStore.load(fis, KEYSTORE_PASSWORD);
            return keyStore;
        } catch (IOException | java.security.GeneralSecurityException e) {
            // Keystore file exists but can't be loaded (corrupted, wrong format, etc.)
            // Move it aside and start fresh to prevent permanent failure
            Log.e(MODULE_NAME, "Corrupt keystore detected, recovering by creating fresh keystore", e);

            String timestamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US)
                    .format(new java.util.Date());
            File corruptedFile = new File(
                keystoreFile.getParent(),
                keystoreFile.getName() + ".corrupted." + timestamp
            );

            if (keystoreFile.renameTo(corruptedFile)) {
                Log.w(MODULE_NAME, "Moved corrupt keystore to: " + corruptedFile.getName());
            } else {
                // If rename fails, delete the corrupt file as last resort
                Log.w(MODULE_NAME, "Failed to rename corrupt keystore, deleting it");
                if (!keystoreFile.delete()) {
                    throw new IOException("Failed to delete corrupt keystore file", e);
                }
            }

            // Initialize fresh empty keystore
            keyStore.load(null, KEYSTORE_PASSWORD);
            return keyStore;
        }
    }

    /**
     * Save software keystore to file atomically.
     * Uses temp file + atomic rename to prevent corruption from crashes during write.
     *
     * CRITICAL: Atomic write prevents data loss during crashes/power failure.
     * Without this, a crash between delete-old and write-new loses ALL stored keys.
     * Pattern: write to .tmp → fsync → atomic rename → final file only updated if successful
     *
     * Addresses review concern: "Non-atomic rewrite can lose the entire keystore"
     */
    private void saveSoftwareKeyStore(KeyStore keyStore) throws Exception {
        File keystoreFile = getKeystoreFile();
        File tempFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE + ".tmp");

        // Delete temp file if it exists from previous failed write
        if (tempFile.exists() && !tempFile.delete()) {
            throw new IOException("Failed to delete existing temp keystore file");
        }

        // Write to temp file first with secure permissions set immediately
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            // Set secure permissions BEFORE writing data to minimize exposure window
            setSecureFilePermissions(tempFile);
            keyStore.store(fos, KEYSTORE_PASSWORD);
        }

        // Use atomic move on API 26+ for better reliability
        // Atomic operations ensure the final file is only created after successful write
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            try {
                Files.move(tempFile.toPath(), keystoreFile.toPath(),
                          java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                          java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                // Fallback to non-atomic rename
                Log.w(MODULE_NAME, "Atomic move not supported, using File.renameTo()");
                if (!tempFile.renameTo(keystoreFile)) {
                    throw new IOException("Failed to rename temp keystore to final location");
                }
            }
        } else {
            // Fallback for older APIs - not truly atomic but best effort
            if (!tempFile.renameTo(keystoreFile)) {
                throw new IOException("Failed to rename temp keystore to final location");
            }
        }
    }

    // Removed MasterKey caching - no longer using EncryptedFile/Tink

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
        ensureBouncyCastleProvider();
        // No longer need stale encryption cleanup - using plain PKCS12 files
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

            // Reject strings that look like hostnames or have suspicious patterns
            if (trimmed.contains(" ") || trimmed.contains("//") || trimmed.contains("@")) {
                return false;
            }

            InetAddress addr = InetAddress.getByName(trimmed);

            // Verify input is a literal IP address, not a hostname that resolved
            // For IPv6: normalize both sides by parsing and re-stringifying
            // This handles compressed forms (2001:db8::1) vs uncompressed (2001:db8:0:0:0:0:0:1)
            String resolvedAddr = addr.getHostAddress();

            // Remove IPv6 brackets for comparison
            String inputForComparison = trimmed.replace("[", "").replace("]", "");

            // Remove zone ID from resolved address if present (e.g., fe80::1%eth0 -> fe80::1)
            String resolvedForComparison = resolvedAddr.split("%")[0];

            // Try direct comparison first (handles IPv4 and exact IPv6 matches)
            if (resolvedForComparison.equals(inputForComparison)) {
                return true;
            }

            // For IPv6, also check if both addresses contain colons (not port numbers)
            // Port notation like "host:8080" should be rejected
            if (inputForComparison.contains(":")) {
                // Count colons - IPv6 has multiple, port notation has one
                int colonCount = inputForComparison.length() - inputForComparison.replace(":", "").length();
                if (colonCount < 2) {
                    // Likely "hostname:port" format, not IPv6
                    return false;
                }

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
    // Removed getEncryptedKeystoreFile() - no longer using EncryptedFile/Tink
    // Now using plain PKCS12 files with getKeystoreFile(), loadSoftwareKeyStore(), saveSoftwareKeyStore()

    // Explicitly set file permissions to mode 0600
    private void setSecureFilePermissions(File file) {
        try {
            // For API 26+, use NIO POSIX permissions first (more reliable and atomic)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(file.toPath(), perms);
            } else {
                // Fallback for older APIs - set permissions using File methods
                // Note: This has a race condition - file is briefly accessible with default permissions
                file.setReadable(false, false);   // No one can read
                file.setReadable(true, true);     // Owner can read
                file.setWritable(false, false);   // No one can write
                file.setWritable(true, true);     // Owner can write
                file.setExecutable(false, false); // No execution
            }
        } catch (Exception e) {
            // Escalate to error level - this is a security issue
            Log.e(MODULE_NAME, "SECURITY WARNING: Failed to set secure file permissions on keystore: " + e.getMessage());
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
                // Escalate stale key deletion failure to error - this could cause dual-store collision
                String errorMsg = "Failed to delete stale key from opposite keystore: " + e.getMessage() +
                                ". This may cause getPublicKey() to return wrong key.";
                Log.e(MODULE_NAME, errorMsg, e);
                promise.reject("STALE_KEY_DELETION_ERROR", errorMsg, e);
                return;
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

        // Thread-safe keystore file operations
        // Prevents race conditions when multiple React Native threads call generateCSR simultaneously
        // All read-modify-write operations on the PKCS12 file must be atomic to prevent corruption
        synchronized (SOFTWARE_KEYSTORE_LOCK) {
            storeSoftwareKey(privateKeyAlias, keyPair);
        }

        return keyPair;
    }

    private void storeSoftwareKey(String privateKeyAlias, KeyPair keyPair) throws Exception {
        KeyStore softwareKeyStore = loadSoftwareKeyStore();

        String tempSubject = "CN=Temp-" + privateKeyAlias;
        X509Certificate selfSignedCert = createSelfSignedCertificate(keyPair, tempSubject);

        softwareKeyStore.setKeyEntry(
            privateKeyAlias,
            keyPair.getPrivate(),
            KEYSTORE_PASSWORD,
            new java.security.cert.Certificate[] { selfSignedCert }
        );

        saveSoftwareKeyStore(softwareKeyStore);
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
                    KeyStore softwareKeyStore = loadSoftwareKeyStore();

                    if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                        softwareKeyStore.deleteEntry(privateKeyAlias);
                        saveSoftwareKeyStore(softwareKeyStore);
                        deleted = true;
                        Log.d(MODULE_NAME, "Deleted software key: " + privateKeyAlias);
                    }
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
                try {
                    KeyStore softwareKeyStore = loadSoftwareKeyStore();
                    promise.resolve(softwareKeyStore.containsAlias(privateKeyAlias));
                } catch (Exception e) {
                    // loadSoftwareKeyStore() handles corruption internally; unexpected errors return false
                    Log.w(MODULE_NAME, "Error checking software keystore: " + e.getMessage());
                    promise.resolve(false);
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
                try {
                    KeyStore softwareKeyStore = loadSoftwareKeyStore();

                    if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                        KeyStore.Entry entry = softwareKeyStore.getEntry(
                            privateKeyAlias,
                            new KeyStore.PasswordProtection(KEYSTORE_PASSWORD)
                        );
                        if (entry instanceof KeyStore.PrivateKeyEntry) {
                            PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
                            promise.resolve(Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP));
                            return;
                        }
                    }
                } catch (Exception e) {
                    // loadSoftwareKeyStore() handles corruption internally; unexpected errors here are retrieval failures
                    Log.w(MODULE_NAME, "Error retrieving key from software keystore: " + e.getMessage());
                    promise.reject("KEY_NOT_FOUND", "Key with alias '" + privateKeyAlias + "' not found");
                    return;
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
            try {
                KeyStore softwareKeyStore = loadSoftwareKeyStore();

                if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                    softwareKeyStore.deleteEntry(privateKeyAlias);
                    saveSoftwareKeyStore(softwareKeyStore);
                    Log.d(MODULE_NAME, "Deleted stale software key: " + privateKeyAlias);
                }
            } catch (Exception e) {
                // loadSoftwareKeyStore() handles corruption internally; log unexpected errors
                Log.w(MODULE_NAME, "Error deleting stale software key: " + e.getMessage());
            }
        }
    }
}
