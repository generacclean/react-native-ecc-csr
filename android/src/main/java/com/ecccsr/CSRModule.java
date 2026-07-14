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

    // Add versioning to keystore filename for future migrations
    private static final String SOFTWARE_KEYSTORE_FILE = "software_keys_v1.p12";

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

            // Remove ALL existing BC providers to avoid conflicts
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

    // Close ByteArrayOutputStream properly
    private static class AndroidKeystoreContentSigner implements ContentSigner {
        private final ByteArrayOutputStream outputStream;
        private final AlgorithmIdentifier sigAlgId;
        private final Signature signature;

        public AndroidKeystoreContentSigner(PrivateKey privateKey, String algorithm) throws Exception {
            this.outputStream = new ByteArrayOutputStream();
            this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            this.signature = Signature.getInstance(algorithm);
            this.signature.initSign(privateKey);
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
                signature.update(outputStream.toByteArray());
                return signature.sign();
            } catch (Exception e) {
                throw new RuntimeException("Failed to sign", e);
            } finally {
                try {
                    outputStream.close();
                } catch (IOException ignored) {
                    // ByteArrayOutputStream close is a no-op, but good practice
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

    // IP address validation
    private boolean isValidIPAddress(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return false;
        }
        try {
            InetAddress.getByName(ip.trim());
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    // Encryption at rest using AndroidX EncryptedFile
    private EncryptedFile getEncryptedKeystoreFile(Context context) throws Exception {
        MasterKey masterKey = new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();

        File file = new File(context.getFilesDir(), SOFTWARE_KEYSTORE_FILE);

        // Set explicit file permissions (mode 0600)
        if (file.exists()) {
            setSecureFilePermissions(file);
        }

        return new EncryptedFile.Builder(
            context,
            file,
            masterKey,
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

    // Check if key exists before generation
    private boolean keyExistsSynchronous(String privateKeyAlias) {
        try {
            // Check hardware keystore
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (keyStore.containsAlias(privateKeyAlias)) {
                return true;
            }
        } catch (Exception e) {
            // Continue to software keystore check
        }

        try {
            // Check software keystore (must be synchronized)
            synchronized (SOFTWARE_KEYSTORE_LOCK) {
                EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

                try (FileInputStream fis = encFile.openFileInput()) {
                    softwareKeyStore.load(fis, "".toCharArray());
                    return softwareKeyStore.containsAlias(privateKeyAlias);
                } catch (FileNotFoundException e) {
                    return false;
                }
            }
        } catch (Exception e) {
            return false;
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
            boolean allowOverwrite = params.hasKey("allowOverwrite") ? params.getBoolean("allowOverwrite") : false;

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

            // Check for key collision
            if (!allowOverwrite && keyExistsSynchronous(privateKeyAlias)) {
                promise.reject("KEY_EXISTS",
                    "Key with alias '" + privateKeyAlias + "' already exists. " +
                    "Delete it first with deleteKey() or set allowOverwrite=true.");
                return;
            }

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
            JcaPEMWriter pemWriter = new JcaPEMWriter(csrWriter);
            pemWriter.writeObject(csr);
            pemWriter.close();

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
            Log.d(MODULE_NAME, "Hardware key pair generated successfully");
            return keyPair;
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
        // Use EncryptedFile for encryption at rest
        EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
        KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

        // Try to load existing keystore, create new if doesn't exist
        try (FileInputStream fis = encFile.openFileInput()) {
            softwareKeyStore.load(fis, "".toCharArray());
        } catch (FileNotFoundException e) {
            // Keystore doesn't exist yet, create a new one
            softwareKeyStore.load(null, null);
        }

        String tempSubject = "CN=Temp-" + privateKeyAlias;
        X509Certificate selfSignedCert = createSelfSignedCertificate(keyPair, tempSubject);

        softwareKeyStore.setKeyEntry(
            privateKeyAlias,
            keyPair.getPrivate(),
            "".toCharArray(),
            new java.security.cert.Certificate[] { selfSignedCert }
        );

        // Save keystore to encrypted file
        try (FileOutputStream fos = encFile.openFileOutput()) {
            softwareKeyStore.store(fos, "".toCharArray());
        }

        // Ensure file permissions are set after creation
        File keystoreFile = new File(getReactApplicationContext().getFilesDir(), SOFTWARE_KEYSTORE_FILE);
        setSecureFilePermissions(keystoreFile);
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

                    try (FileInputStream fis = encFile.openFileInput()) {
                        softwareKeyStore.load(fis, "".toCharArray());
                    }

                    if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                        softwareKeyStore.deleteEntry(privateKeyAlias);

                        try (FileOutputStream fos = encFile.openFileOutput()) {
                            softwareKeyStore.store(fos, "".toCharArray());
                        }

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
                    Log.w(MODULE_NAME, "Error checking software keystore: " + e.getMessage());
                    promise.resolve(false);
                    return;
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
                EncryptedFile encFile = getEncryptedKeystoreFile(getReactApplicationContext());
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");

                try (FileInputStream fis = encFile.openFileInput()) {
                    softwareKeyStore.load(fis, "".toCharArray());
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
}
