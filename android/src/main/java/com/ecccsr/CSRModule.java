package com.ecccsr;

import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
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
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CSRModule extends ReactContextBaseJavaModule {

    private static final String MODULE_NAME = "CSRModule";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String SOFTWARE_KEYSTORE_FILE = "software_keys.p12";
    private static final String DEFAULT_COUNTRY = "US";
    private static final String DEFAULT_STATE = "Colorado";
    private static final String DEFAULT_LOCALITY = "Denver";
    private static final String DEFAULT_ORGANIZATION = "MyOrg";
    private static final String DEFAULT_ORGANIZATIONAL_UNIT = "MyOrgUnit";
    private static final String DEFAULT_IP_ADDRESS = "10.10.10.10";
    private static final String DEFAULT_ECC_CURVE = "secp384r1";

    // Keep a direct reference to our full BouncyCastle provider instance
    // to avoid getting the system's stripped-down BC provider
    private static final Provider FULL_BC_PROVIDER = new BouncyCastleProvider();

    public CSRModule(ReactApplicationContext reactContext) {
        super(reactContext);
        ensureBouncyCastleProvider();
    }

    private void ensureBouncyCastleProvider() {
        // Remove the system's stripped BC provider if it exists
        Provider systemBcProvider = Security.getProvider("BC");
        if (systemBcProvider != null && systemBcProvider.getClass().getName().startsWith("com.android.org.bouncycastle")) {
            Log.d(MODULE_NAME, "Found Android system BC provider (stripped): " + systemBcProvider.getClass().getName());
            Log.d(MODULE_NAME, "Removing system BC provider to avoid conflicts");
            Security.removeProvider("BC");
        }

        // Register our full BouncyCastle provider at position 1 (highest priority)
        Provider existingProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (existingProvider == null || !existingProvider.getClass().getName().equals(FULL_BC_PROVIDER.getClass().getName())) {
            Log.d(MODULE_NAME, "Registering full BouncyCastle provider at highest priority");
            try {
                Security.insertProviderAt(FULL_BC_PROVIDER, 1);
                Log.d(MODULE_NAME, "Full BouncyCastle provider registered successfully");
                Log.d(MODULE_NAME, "BC Provider version: " + FULL_BC_PROVIDER.getVersion());
                Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.getClass().getName());
            } catch (Exception e) {
                Log.e(MODULE_NAME, "Failed to register BouncyCastle provider: " + e.getMessage(), e);
            }
        } else {
            Log.d(MODULE_NAME, "Full BouncyCastle provider already registered");
            Log.d(MODULE_NAME, "BC Provider version: " + FULL_BC_PROVIDER.getVersion());
            Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.getClass().getName());
        }

        // List all registered security providers for debugging
        Log.d(MODULE_NAME, "All registered security providers:");
        for (Provider provider : Security.getProviders()) {
            Log.d(MODULE_NAME, "  - " + provider.getName() + " v" + provider.getVersion() +
                  " (" + provider.getClass().getName() + ")");
        }
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

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

    /**
     * Generates a Certificate Signing Request (CSR) with ECC key pair.
     * The module intelligently decides hardware vs software backing based on device capabilities.
     *
     * @param params CSR parameters including privateKeyAlias and optional useHardwareKey flag
     * @param promise Promise resolving to CSR, key alias, public key, and hardware status
     */
    @ReactMethod
    public void generateCSR(ReadableMap params, Promise promise) {
        try {
            String country = params.hasKey("country") ? params.getString("country") : DEFAULT_COUNTRY;
            String state = params.hasKey("state") ? params.getString("state") : DEFAULT_STATE;
            String locality = params.hasKey("locality") ? params.getString("locality") : DEFAULT_LOCALITY;
            String organization = params.hasKey("organization") ? params.getString("organization") : DEFAULT_ORGANIZATION;
            String organizationalUnit = params.hasKey("organizationalUnit") ? params.getString("organizationalUnit") : DEFAULT_ORGANIZATIONAL_UNIT;
            String commonName = params.hasKey("commonName") ? params.getString("commonName") : "";
            String serialNumber = params.hasKey("serialNumber") ? params.getString("serialNumber") : "";
            String ipAddress = params.hasKey("ipAddress") ? params.getString("ipAddress") : DEFAULT_IP_ADDRESS;
            String dnsName = params.hasKey("dnsName") ? params.getString("dnsName") : null;
            String curve = params.hasKey("curve") ? params.getString("curve") : DEFAULT_ECC_CURVE;
            String phoneInfo = params.hasKey("phoneInfo") ? params.getString("phoneInfo") : null;
            String privateKeyAlias = params.hasKey("privateKeyAlias") ? params.getString("privateKeyAlias") : null;

            // App can request hardware, but module decides based on TLS compatibility
            boolean requestedHardwareKey = params.hasKey("useHardwareKey") ? params.getBoolean("useHardwareKey") : false;

            // Override app preference if hardware won't work for TLS
            boolean useHardwareKey = requestedHardwareKey && canUseHardwareKeysForTLS();

            if (requestedHardwareKey && !useHardwareKey) {
                Log.w(MODULE_NAME, "Hardware key requested but not supported for TLS on this device (requires Android 12+). Using software keystore.");
            }

            if (privateKeyAlias == null || privateKeyAlias.isEmpty()) {
                promise.reject("MISSING_ALIAS", "privateKeyAlias is required");
                return;
            }

            if (!curve.equals("secp256r1") && !curve.equals("secp384r1") && !curve.equals("secp521r1")) {
                promise.reject("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
                return;
            }

            String keystoreCurve = curve;
            KeyPair keyPair;

            if (useHardwareKey) {
                Log.d(MODULE_NAME, "Generating hardware-backed key pair");

                // Check if the device actually supports StrongBox before setting the builder flag
                boolean hasStrongBox = false;
                boolean useStrongBox = false;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    hasStrongBox = getReactApplicationContext().getPackageManager()
                            .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
                    Log.d(MODULE_NAME, "Device StrongBox support: " + hasStrongBox);

                    // StrongBox only supports P-256 (secp256r1). For other curves, use TEE.
                    if (hasStrongBox && !keystoreCurve.equals("secp256r1")) {
                        Log.w(MODULE_NAME, "StrongBox only supports P-256. Requested curve: " + keystoreCurve + ". Using TEE instead.");
                        useStrongBox = false;
                    } else {
                        useStrongBox = hasStrongBox;
                    }
                }

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);

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

                // Only apply StrongBox backing if compatible
                if (useStrongBox) {
                    specBuilder.setIsStrongBoxBacked(true);
                    Log.d(MODULE_NAME, "Using StrongBox-backed key generation (P-256)");
                } else if (hasStrongBox) {
                    Log.d(MODULE_NAME, "Using hardware-backed (TEE) key generation (StrongBox available but curve incompatible)");
                } else {
                    Log.d(MODULE_NAME, "Using hardware-backed (TEE) key generation");
                }

                keyPairGenerator.initialize(specBuilder.build());

                try {
                    keyPair = keyPairGenerator.generateKeyPair();
                    Log.d(MODULE_NAME, "Hardware key pair generated successfully");
                } catch (Exception e) {
                    Log.e(MODULE_NAME, "Hardware key generation failed: " + e.getMessage());
                    // On failure, provide clear error message about the device capability issue
                    throw new Exception("Hardware key generation failed. Device may not support hardware-backed keys for this curve (" + keystoreCurve + "). Error: " + e.getMessage());
                }

            } else {
                Log.d(MODULE_NAME, "Generating software key pair");

                // Ensure BouncyCastle provider is available
                ensureBouncyCastleProvider();

                // Use our full BC provider directly instead of looking it up by name
                Log.d(MODULE_NAME, "Using full BouncyCastle provider version: " + FULL_BC_PROVIDER.getVersion());
                Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.getClass().getName());

                // Check if our BC provider supports EC algorithm
                try {
                    Log.d(MODULE_NAME, "Checking EC algorithm support in full BouncyCastle...");
                    KeyPairGenerator testKpg = KeyPairGenerator.getInstance("EC", FULL_BC_PROVIDER);
                    Log.d(MODULE_NAME, "EC algorithm IS supported by BouncyCastle: " + testKpg.getProvider().getName());
                } catch (Exception e) {
                    Log.e(MODULE_NAME, "EC algorithm NOT supported by BouncyCastle provider!", e);
                    Log.e(MODULE_NAME, "BC Provider info: " + FULL_BC_PROVIDER.getInfo());
                    Log.e(MODULE_NAME, "Available algorithms in BC:");
                    for (Provider.Service service : FULL_BC_PROVIDER.getServices()) {
                        if (service.getType().equals("KeyPairGenerator")) {
                            Log.e(MODULE_NAME, "  - " + service.getAlgorithm());
                        }
                    }
                    throw new Exception("BouncyCastle provider does not support EC algorithm. Provider may be corrupted or stripped by ProGuard/R8.");
                }

                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", FULL_BC_PROVIDER);
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(keystoreCurve);
                keyPairGenerator.initialize(ecSpec, new SecureRandom());
                keyPair = keyPairGenerator.generateKeyPair();
                Log.d(MODULE_NAME, "Software key pair generated successfully");
                
                KeyStore softwareKeyStore;
                String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
                
                try {
                    FileInputStream fis = new FileInputStream(keystorePath);
                    softwareKeyStore = KeyStore.getInstance("PKCS12");
                    softwareKeyStore.load(fis, "".toCharArray());
                    fis.close();
                } catch (Exception e) {
                    softwareKeyStore = KeyStore.getInstance("PKCS12");
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
                
                FileOutputStream fos = new FileOutputStream(keystorePath);
                softwareKeyStore.store(fos, "".toCharArray());
                fos.close();
            }

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            Log.d(MODULE_NAME, "Key pair generated: " + privateKeyAlias + 
                  " (" + (useHardwareKey ? "hardware" : "software") + ", " + keystoreCurve + ")");

            StringBuilder subjectBuilder = new StringBuilder();
            subjectBuilder.append("C=").append(country);
            subjectBuilder.append(", ST=").append(state);
            subjectBuilder.append(", L=").append(locality);
            subjectBuilder.append(", O=").append(organization);
            subjectBuilder.append(", OU=").append(organizationalUnit);
            subjectBuilder.append(", CN=").append(commonName);
            if (!serialNumber.isEmpty()) {
                subjectBuilder.append(", serialNumber=").append(serialNumber);
            }

            X500Name subject = new X500Name(subjectBuilder.toString());
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

            ExtensionsGenerator extGen = new ExtensionsGenerator();
            
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
            extGen.addExtension(Extension.keyUsage, true, keyUsage);

            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
            extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

            List<GeneralName> sanList = new ArrayList<>();
            sanList.add(new GeneralName(GeneralName.iPAddress, ipAddress));

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

            GeneralNames subjectAltNames = new GeneralNames(sanList.toArray(new GeneralName[0]));
            extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

            ContentSigner signer = useHardwareKey
                    ? new AndroidKeystoreContentSigner(privateKey, "SHA256withECDSA")
                    : new JcaContentSignerBuilder("SHA256withECDSA").setProvider(FULL_BC_PROVIDER).build(privateKey);

            PKCS10CertificationRequest csr = csrBuilder.build(signer);

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
            Log.e(MODULE_NAME, "CSR generation failed", e);
            promise.reject("CSR_GENERATION_ERROR", "Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes a key from both hardware and software keystores
     */
    @ReactMethod
    public void deleteKey(String privateKeyAlias, Promise promise) {
        try {
            boolean deleted = false;
            
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
            
            try {
                String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
                FileInputStream fis = new FileInputStream(keystorePath);
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
                softwareKeyStore.load(fis, "".toCharArray());
                fis.close();
                
                if (softwareKeyStore.containsAlias(privateKeyAlias)) {
                    softwareKeyStore.deleteEntry(privateKeyAlias);
                    
                    FileOutputStream fos = new FileOutputStream(keystorePath);
                    softwareKeyStore.store(fos, "".toCharArray());
                    fos.close();
                    
                    deleted = true;
                    Log.d(MODULE_NAME, "Deleted software key: " + privateKeyAlias);
                }
            } catch (Exception e) {
                // Continue
            }
            
            promise.resolve(deleted);
        } catch (Exception e) {
            Log.e(MODULE_NAME, "Failed to delete key", e);
            promise.reject("DELETE_KEY_ERROR", "Failed to delete key: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if the device supports hardware-backed keys for TLS.
     * Apps can call this before requesting hardware keys.
     *
     * @param promise Promise resolving to capability information
     */
    @ReactMethod
    public void getHardwareKeystoreCapabilities(Promise promise) {
        try {
            com.facebook.react.bridge.WritableMap capabilities = com.facebook.react.bridge.Arguments.createMap();

            // Check if device supports hardware keys for TLS (Android 12+)
            boolean tlsCompatible = canUseHardwareKeysForTLS();
            capabilities.putBoolean("tlsCompatible", tlsCompatible);
            capabilities.putInt("androidSdkVersion", android.os.Build.VERSION.SDK_INT);

            // Check StrongBox support
            boolean hasStrongBox = false;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                hasStrongBox = getReactApplicationContext().getPackageManager()
                        .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
            }
            capabilities.putBoolean("hasStrongBox", hasStrongBox);

            // Device info
            capabilities.putString("manufacturer", android.os.Build.MANUFACTURER);
            capabilities.putString("model", android.os.Build.MODEL);
            capabilities.putString("device", android.os.Build.DEVICE);

            promise.resolve(capabilities);
        } catch (Exception e) {
            promise.reject("CAPABILITY_CHECK_ERROR", "Failed to check capabilities: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if a key exists in either hardware or software keystore
     */
    @ReactMethod
    public void keyExists(String privateKeyAlias, Promise promise) {
        try {
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
            
            try {
                String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
                FileInputStream fis = new FileInputStream(keystorePath);
                KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
                softwareKeyStore.load(fis, "".toCharArray());
                fis.close();
                
                promise.resolve(softwareKeyStore.containsAlias(privateKeyAlias));
            } catch (Exception e) {
                promise.resolve(false);
            }
        } catch (Exception e) {
            promise.reject("KEY_EXISTS_ERROR", "Failed to check key existence: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves the public key for a given alias from either keystore
     */
    @ReactMethod
    public void getPublicKey(String privateKeyAlias, Promise promise) {
        try {
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
            
            String keystorePath = getReactApplicationContext().getFilesDir() + "/" + SOFTWARE_KEYSTORE_FILE;
            FileInputStream fis = new FileInputStream(keystorePath);
            KeyStore softwareKeyStore = KeyStore.getInstance("PKCS12");
            softwareKeyStore.load(fis, "".toCharArray());
            fis.close();
            
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