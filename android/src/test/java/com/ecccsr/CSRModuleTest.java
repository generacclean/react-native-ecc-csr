package com.ecccsr;

import com.ecccsr.testutil.FakeReactApplicationContext;
import com.ecccsr.testutil.RecordingPromise;
import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.util.ReflectionHelpers;

import java.io.File;
import java.io.StringReader;
import java.security.KeyStore;
import java.util.Base64;

import static org.junit.Assert.*;

/**
 * Unit tests for CSRModule that exercise the real production code (via generateCSRInternal /
 * getHardwareKeystoreCapabilitiesInternal, which are the same logic the @ReactMethod entry points
 * call, minus the RN bridge's WritableMap serialization step that requires a native JNI library
 * unavailable in this JVM-only test environment).
 */
@RunWith(RobolectricTestRunner.class)
public class CSRModuleTest {

    private CSRModule module;
    private final int originalSdkInt = android.os.Build.VERSION.SDK_INT;

    @Before
    public void setUp() {
        FakeReactApplicationContext context =
                new FakeReactApplicationContext(RuntimeEnvironment.getApplication());
        module = new CSRModule(context);
    }

    @After
    public void restoreSdkInt() {
        ReflectionHelpers.setStaticField(android.os.Build.VERSION.class, "SDK_INT", originalSdkInt);
    }

    private JavaOnlyMap paramsFor(String alias, String curve) {
        JavaOnlyMap params = new JavaOnlyMap();
        params.putString("commonName", "test-device");
        params.putString("privateKeyAlias", alias);
        if (curve != null) {
            params.putString("curve", curve);
        }
        return params;
    }

    // ---- CSR generation: valid, parseable CSR with the expected DN, per curve ----

    @Test
    public void generateCSR_p256_producesParseableCSRWithExpectedDN() throws Exception {
        JavaOnlyMap params = paramsFor("alias-p256", "secp256r1");
        params.putString("country", "US");
        params.putString("organization", "Generac Power Systems");

        CSRModule.CSRGenerationResult result = module.generateCSRInternal(params);

        PKCS10CertificationRequest csr = parseCSR(result.csr);
        String subject = csr.getSubject().toString();
        assertTrue(subject.contains("CN=test-device"));
        assertTrue(subject.contains("C=US"));
        assertTrue(subject.contains("O=Generac Power Systems"));
        assertEquals("alias-p256", result.privateKeyAlias);
        assertFalse(result.useHardwareKey);
    }

    @Test
    public void generateCSR_p384_producesParseableCSR() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("alias-p384", "secp384r1"));
        PKCS10CertificationRequest csr = parseCSR(result.csr);
        assertTrue(csr.getSubject().toString().contains("CN=test-device"));
    }

    @Test
    public void generateCSR_p521_producesParseableCSR() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("alias-p521", "secp521r1"));
        PKCS10CertificationRequest csr = parseCSR(result.csr);
        assertTrue(csr.getSubject().toString().contains("CN=test-device"));
    }

    @Test
    public void generateCSR_signatureVerifiesAgainstPublicKey() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("alias-verify", "secp256r1"));
        PKCS10CertificationRequest csr = parseCSR(result.csr);

        org.bouncycastle.jce.provider.BouncyCastleProvider bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        java.security.PublicKey embeddedPublicKey = new JcaPKCS10CertificationRequest(csr).setProvider(bc).getPublicKey();
        boolean isValid = csr.isSignatureValid(
                new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .setProvider(bc)
                        .build(embeddedPublicKey));
        assertTrue("CSR signature should verify against its own embedded public key", isValid);
    }

    private PKCS10CertificationRequest parseCSR(String pem) throws Exception {
        PemReader pemReader = new PemReader(new StringReader(pem));
        PemObject pemObject = pemReader.readPemObject();
        assertNotNull("PEM should parse", pemObject);
        return new PKCS10CertificationRequest(pemObject.getContent());
    }

    // ---- Key lifecycle: create -> keyExists -> getPublicKey -> deleteKey -> keyExists ----

    @Test
    public void keyLifecycle_softwareKey_createThenExistsThenDeleteThenGone() throws Exception {
        String alias = "lifecycle-alias-" + System.identityHashCode(this);
        module.generateCSRInternal(paramsFor(alias, "secp256r1"));

        RecordingPromise existsAfterCreate = new RecordingPromise();
        module.keyExists(alias, existsAfterCreate);
        assertTrue(existsAfterCreate.resolved);
        assertEquals(Boolean.TRUE, existsAfterCreate.resolvedValue);

        RecordingPromise getPublicKey = new RecordingPromise();
        module.getPublicKey(alias, getPublicKey);
        assertTrue(getPublicKey.resolved);
        assertNotNull(getPublicKey.resolvedValue);
        // Must be valid base64
        Base64.getDecoder().decode((String) getPublicKey.resolvedValue);

        RecordingPromise delete = new RecordingPromise();
        module.deleteKey(alias, delete);
        assertTrue(delete.resolved);
        assertEquals(Boolean.TRUE, delete.resolvedValue);

        RecordingPromise existsAfterDelete = new RecordingPromise();
        module.keyExists(alias, existsAfterDelete);
        assertTrue(existsAfterDelete.resolved);
        assertEquals(Boolean.FALSE, existsAfterDelete.resolvedValue);
    }

    @Test
    public void keyExists_unknownAlias_resolvesFalse() {
        RecordingPromise promise = new RecordingPromise();
        module.keyExists("never-created-alias", promise);
        assertTrue(promise.resolved);
        assertEquals(Boolean.FALSE, promise.resolvedValue);
    }

    @Test
    public void getPublicKey_unknownAlias_rejects() {
        RecordingPromise promise = new RecordingPromise();
        module.getPublicKey("never-created-alias", promise);
        assertTrue(promise.rejected);
        assertEquals("KEY_NOT_FOUND", promise.rejectedCode);
    }

    @Test
    public void deleteKey_unknownAlias_resolvesFalse() {
        RecordingPromise promise = new RecordingPromise();
        module.deleteKey("never-created-alias", promise);
        assertTrue(promise.resolved);
        assertEquals(Boolean.FALSE, promise.resolvedValue);
    }

    // ---- Software keystore round-trip: write then load back ----

    @Test
    public void softwareKeystore_writeThenReload_roundTrips() throws Exception {
        String alias = "roundtrip-alias";
        module.generateCSRInternal(paramsFor(alias, "secp256r1"));

        File keystoreFile = module.getKeystoreFile();
        assertTrue("keystore file should exist after key generation", keystoreFile.exists());

        KeyStore reloaded = KeyStore.getInstance("PKCS12");
        try (java.io.FileInputStream fis = new java.io.FileInputStream(keystoreFile)) {
            reloaded.load(fis, "".toCharArray());
        }
        assertTrue("reloaded keystore should contain the alias written by generateCSR",
                reloaded.containsAlias(alias));
    }

    @Test
    public void generateCSR_result_includesKeystoreDescriptorForSoftwareKey() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("descriptor-alias", "secp256r1"));

        assertNotNull("software-backed keys must expose a keystore descriptor", result.keystorePath);
        assertTrue(result.keystorePath.endsWith("software_keys.p12"));
    }

    // ---- Corruption handling: corrupt keystore is quarantined, regeneration proceeds ----

    @Test
    public void corruptKeystore_isQuarantinedAndRegenerationSucceeds() throws Exception {
        // Establish a real keystore file first so getKeystoreFile() points at a live path.
        module.generateCSRInternal(paramsFor("pre-corruption-alias", "secp256r1"));
        File keystoreFile = module.getKeystoreFile();

        // Corrupt it.
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(keystoreFile)) {
            fos.write("not a valid pkcs12 file".getBytes());
        }

        // Regeneration must not throw and must succeed despite the corrupt file on disk.
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("post-corruption-alias", "secp256r1"));
        assertNotNull(result.csr);

        // Quarantined files live in a keystore_forensics/ subdirectory (not alongside the live
        // keystore file) so a single backup-exclusion entry can cover all timestamped filenames.
        File forensicsDir = new File(keystoreFile.getParentFile(), "keystore_forensics");
        File[] corrupted = forensicsDir.listFiles((dir, name) -> name.startsWith(keystoreFile.getName() + ".corrupted."));
        assertNotNull(corrupted);
        assertTrue("corrupt file should have been quarantined with a .corrupted. suffix", corrupted.length >= 1);
    }

    @Test
    public void corruptedFileRetention_cappedAtThreeMostRecent() throws Exception {
        module.generateCSRInternal(paramsFor("retention-seed-alias", "secp256r1"));
        File keystoreFile = module.getKeystoreFile();
        File forensicsDir = new File(keystoreFile.getParentFile(), "keystore_forensics");

        // Simulate 5 prior corruption cycles by corrupting + regenerating 5 times.
        for (int i = 0; i < 5; i++) {
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(keystoreFile)) {
                fos.write(("corrupt-" + i).getBytes());
            }
            module.generateCSRInternal(paramsFor("retention-alias-" + i, "secp256r1"));
        }

        File[] corrupted = forensicsDir.listFiles((dir, name) -> name.startsWith(keystoreFile.getName() + ".corrupted."));
        assertNotNull(corrupted);
        assertEquals("exactly 3 .corrupted files should be retained after 5 corruption cycles",
                3, corrupted.length);
    }

    // ---- Input validation: exercise the real production isValidIPAddress ----

    @Test
    public void isValidIPAddress_acceptsLiteralIPv4() {
        assertTrue(module.isValidIPAddress("192.168.1.1"));
        assertTrue(module.isValidIPAddress("10.0.0.1"));
    }

    @Test
    public void isValidIPAddress_acceptsLiteralIPv6() {
        assertTrue(module.isValidIPAddress("::1"));
        assertTrue(module.isValidIPAddress("2001:db8::1"));
    }

    @Test
    public void isValidIPAddress_rejectsHostnames() {
        assertFalse(module.isValidIPAddress("localhost"));
        assertFalse(module.isValidIPAddress("example.com"));
    }

    @Test
    public void isValidIPAddress_rejectsHostnamePortInjection() {
        // The ":"-gated hostname-injection case: "host:8080" has exactly one colon,
        // which must not be mistaken for a compressed IPv6 literal.
        assertFalse(module.isValidIPAddress("example.com:8080"));
        assertFalse(module.isValidIPAddress("evil-host:1"));
    }

    @Test
    public void isValidIPAddress_rejectsNullAndEmpty() {
        assertFalse(module.isValidIPAddress(null));
        assertFalse(module.isValidIPAddress(""));
        assertFalse(module.isValidIPAddress("   "));
    }

    @Test
    public void generateCSR_invalidIPAddress_isRejected() {
        JavaOnlyMap params = paramsFor("bad-ip-alias", "secp256r1");
        params.putString("ipAddress", "not-a-hostname-or-ip!!");

        RecordingPromise promise = new RecordingPromise();
        module.generateCSR(params, promise);

        assertTrue(promise.rejected);
        assertEquals("INVALID_IP", promise.rejectedCode);
    }

    @Test
    public void generateCSR_missingAlias_isRejected() {
        JavaOnlyMap params = new JavaOnlyMap();
        params.putString("commonName", "test-device");

        RecordingPromise promise = new RecordingPromise();
        module.generateCSR(params, promise);

        assertTrue(promise.rejected);
        assertEquals("MISSING_ALIAS", promise.rejectedCode);
    }

    @Test
    public void generateCSR_invalidCurve_isRejected() {
        JavaOnlyMap params = paramsFor("bad-curve-alias", "secp256k1");

        RecordingPromise promise = new RecordingPromise();
        module.generateCSR(params, promise);

        assertTrue(promise.rejected);
        assertEquals("INVALID_CURVE", promise.rejectedCode);
    }

    @Test
    public void generateCSR_bridgeResult_includesKeystoreMapForSoftwareKey() {
        // Arguments.createMap() needs the native RN JNI library, which isn't available in
        // this JVM-only Robolectric environment (see generateCSRInternal's Javadoc for why
        // the bridge wrapper is split from the core logic in the first place). Mock the static
        // factory so this test can still assert on the actual WritableMap the bridge builds,
        // not just the plain-Java CSRGenerationResult the other tests exercise.
        try (org.mockito.MockedStatic<com.facebook.react.bridge.Arguments> arguments =
                org.mockito.Mockito.mockStatic(com.facebook.react.bridge.Arguments.class)) {
            arguments.when(com.facebook.react.bridge.Arguments::createMap)
                    .thenAnswer(invocation -> new JavaOnlyMap());

            JavaOnlyMap params = paramsFor("bridge-descriptor-alias", "secp256r1");

            RecordingPromise promise = new RecordingPromise();
            module.generateCSR(params, promise);

            assertTrue(promise.resolved);
            WritableMap response = promise.resolvedMap();
            assertTrue("bridge response must include a keystore map for a software-backed key",
                    response.hasKey("keystore"));

            ReadableMap keystore = response.getMap("keystore");
            assertNotNull(keystore);
            assertTrue(keystore.getString("path").endsWith("software_keys.p12"));
            assertEquals("", keystore.getString("password"));
            assertEquals("pkcs12", keystore.getString("format"));
        }
    }

    // ---- getHardwareKeystoreCapabilities / TLS-compatibility detection ----

    @Test
    public void hardwareCapabilities_belowApi31_notTlsCompatible() {
        // Android 11 (API 30) - below the API 31 PURPOSE_AGREE_KEY requirement.
        // Build.VERSION.SDK_INT is set directly (rather than via @Config(sdk=)) because
        // @Config triggers Robolectric's binary-resource loading path, which this module's
        // minSdk (23) is incompatible with under react-android 0.76's manifest (minSdk 24).
        ReflectionHelpers.setStaticField(android.os.Build.VERSION.class, "SDK_INT", 30);
        CSRModule.HardwareCapabilities caps = module.getHardwareKeystoreCapabilitiesInternal();
        assertFalse(caps.tlsCompatible);
        assertEquals(30, caps.androidSdkVersion);
    }

    @Test
    public void hardwareCapabilities_api31Plus_tlsCompatible() {
        // Android 12 (API 31) - PURPOSE_AGREE_KEY support added.
        ReflectionHelpers.setStaticField(android.os.Build.VERSION.class, "SDK_INT", 31);
        CSRModule.HardwareCapabilities caps = module.getHardwareKeystoreCapabilitiesInternal();
        assertTrue(caps.tlsCompatible);
        assertEquals(31, caps.androidSdkVersion);
    }

    @Test
    public void hardwareCapabilities_returnsDocumentedShape() {
        CSRModule.HardwareCapabilities caps = module.getHardwareKeystoreCapabilitiesInternal();
        assertNotNull(caps.manufacturer);
        assertNotNull(caps.model);
        assertNotNull(caps.device);
    }

    @Test
    public void generateCSR_hardwareRequestedButUnsupported_fallsBackToSoftware() throws Exception {
        // Set SDK explicitly rather than relying on Robolectric's ambient default (which is
        // derived from build.gradle's targetSdk/compileSdk 36, not a low fallback value) -
        // canUseHardwareKeysForTLS() requires API 31+, so API 30 forces software fallback.
        ReflectionHelpers.setStaticField(android.os.Build.VERSION.class, "SDK_INT", 30);
        JavaOnlyMap params = paramsFor("hw-fallback-alias", "secp256r1");
        params.putBoolean("useHardwareKey", true);

        CSRModule.CSRGenerationResult result = module.generateCSRInternal(params);

        assertTrue(result.hardwareKeyRequested);
        assertFalse("device isn't TLS-compatible for hardware keys, must fall back to software",
                result.useHardwareKey);
        assertNotNull("fallback to software must still produce a keystore descriptor",
                result.keystorePath);
    }
}
