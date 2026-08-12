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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Unit tests for CSRModule that exercise the real production code (via generateCSRInternal /
 * getHardwareKeystoreCapabilitiesInternal, which are the same logic the @ReactMethod entry points
 * call, minus the RN bridge's WritableMap serialization step that requires a native JNI library
 * unavailable in this JVM-only test environment).
 */
@RunWith(RobolectricTestRunner.class)
public class CSRModuleTest {

    private static final String KEYSTORE_NAME = "software_keys.p12";

    private CSRModule module;
    private FakeReactApplicationContext context;
    private final int originalSdkInt = android.os.Build.VERSION.SDK_INT;

    @Before
    public void setUp() {
        context = new FakeReactApplicationContext(RuntimeEnvironment.getApplication());
        module = new CSRModule(context);

        // Robolectric may hand out the same app directories to more than one test method, so a
        // leftover keystore or quarantined file would let the corruption tests below pass on
        // another test's artifacts. Start every test from a known-empty state, in both the live
        // no-backup location and the legacy backup-eligible one the migration tests populate.
        for (File dir : new File[] {context.getNoBackupFilesDir(), context.getFilesDir()}) {
            new File(dir, KEYSTORE_NAME).delete();
            new File(dir, KEYSTORE_NAME + ".tmp").delete();
            File[] leftovers = new File(dir, "keystore_forensics").listFiles();
            if (leftovers != null) {
                for (File leftover : leftovers) {
                    leftover.delete();
                }
            }
            // Pre-subdirectory releases quarantined corrupt keystores flat in the files dir, and
            // the migration test below stages one there.
            File[] flatQuarantined = dir.listFiles(
                    (unused, name) -> name.startsWith(KEYSTORE_NAME + ".corrupted."));
            if (flatQuarantined != null) {
                for (File leftover : flatQuarantined) {
                    leftover.delete();
                }
            }
        }
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
        assertTrue(result.keystorePath.endsWith(KEYSTORE_NAME));
    }

    // ---- Backup exclusion: the key lives outside the backup set, and legacy copies are moved ----

    @Test
    public void keystore_livesInNoBackupDirectory() throws Exception {
        File keystoreFile = module.getKeystoreFile();

        // getNoBackupFilesDir() is excluded from Auto Backup, cloud backup and device transfer
        // unconditionally. That is what lets this module drop backup_rules.xml /
        // data_extraction_rules.xml and the manifest wiring the consuming app previously had to get
        // right - and it cannot be defeated by another library claiming the manifest attributes.
        assertEquals(context.getNoBackupFilesDir(), keystoreFile.getParentFile());
        assertNotEquals("keystore must not sit in the backup-eligible files dir",
                context.getFilesDir(), keystoreFile.getParentFile());
    }

    @Test
    public void legacyKeystore_isMovedOutOfBackupEligibleStorageWithKeysIntact() throws Exception {
        // Produce a real keystore through production code, then stage it where installs created
        // before the no-backup change kept it.
        String alias = "legacy-migration-alias";
        module.generateCSRInternal(paramsFor(alias, "secp256r1"));
        File current = new File(context.getNoBackupFilesDir(), KEYSTORE_NAME);
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        assertTrue("staging requires the generated keystore to start in no-backup storage",
                current.renameTo(legacy));

        // Any keystore access must relocate the file and leave the key usable.
        RecordingPromise promise = new RecordingPromise();
        module.keyExists(alias, promise);

        assertEquals("migrated keystore must still contain the key", Boolean.TRUE, promise.resolvedValue);
        assertTrue("keystore should have been migrated into no-backup storage", current.exists());
        assertFalse("legacy backup-eligible copy must not survive migration", legacy.exists());
    }

    @Test
    public void legacyKeystore_supersededByCurrentLocation_isDeleted() throws Exception {
        module.generateCSRInternal(paramsFor("current-alias", "secp256r1"));
        File current = new File(context.getNoBackupFilesDir(), KEYSTORE_NAME);
        long currentLength = current.length();

        // A stale pre-migration file next to a populated no-backup keystore still holds a private
        // key in backup-eligible storage, so it has to be removed rather than ignored - and it must
        // not clobber the live keystore on its way out.
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacy)) {
            fos.write("stale pre-migration keystore".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("stale legacy keystore must be deleted", legacy.exists());
        assertEquals("live keystore must not be overwritten by the stale copy",
                currentLength, current.length());
    }

    @Test
    public void legacyTempKeystore_isDeleted() throws Exception {
        // An interrupted atomic write leaves a .tmp that is a complete copy of the keystore.
        File legacyTemp = new File(context.getFilesDir(), KEYSTORE_NAME + ".tmp");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacyTemp)) {
            fos.write("interrupted write holding a full keystore copy".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("leftover .tmp copies must not stay backup-eligible", legacyTemp.exists());
    }

    @Test
    public void noBackupDirUnavailable_failsInsteadOfWritingToAnUnprotectedPath() {
        context.setNoBackupFilesDirUnavailable(true);

        // new File((File) null, "software_keys.p12") is legal Java and yields a bare relative path
        // resolved against the process working directory - no backup exclusion, no 0600. Refusing
        // is the only safe outcome, and it has to be loud rather than logged.
        assertThrows(java.io.IOException.class, () -> module.getKeystoreFile());
    }

    @Test
    public void noBackupDirUnavailable_keyExistsRejectsInsteadOfAnsweringFalse() {
        context.setNoBackupFilesDirUnavailable(true);

        RecordingPromise promise = new RecordingPromise();
        module.keyExists("some-alias", promise);

        // The software-keystore branch normally swallows failures and resolves false. Doing that
        // when storage itself is unreachable would tell the app its key is gone, and the app would
        // re-enrol with a new key while its issued certificate silently stopped matching.
        assertTrue("unreachable keystore storage must reject, not resolve false", promise.rejected);
        assertEquals("KEY_EXISTS_ERROR", promise.rejectedCode);
    }

    @Test
    public void legacyKeystoreMigrationFailure_failsLoudlyInsteadOfShadowingTheKey() throws Exception {
        // Stage a real keystore where pre-migration installs kept it, then make the destination
        // directory unwritable so renameTo cannot succeed.
        String alias = "migration-failure-alias";
        module.generateCSRInternal(paramsFor(alias, "secp256r1"));
        File noBackupDir = context.getNoBackupFilesDir();
        File current = new File(noBackupDir, KEYSTORE_NAME);
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        assertTrue(current.renameTo(legacy));

        // setWritable() must be inside the try: as root it "succeeds" without actually revoking
        // write access, and skipping the test at that point would leave the directory unwritable
        // for every test that runs after this one.
        boolean unwritable = noBackupDir.setWritable(false) && !noBackupDir.canWrite();
        try {
            assumeTrue("requires a filesystem where the destination dir can be made unwritable",
                    unwritable);

            // Returning the no-backup path here would make loadSoftwareKeyStore() see no file and
            // build an empty keystore, so the device would re-enrol with a new key while its issued
            // certificate silently stopped matching - and the old key would stay backup-eligible.
            assertThrows(java.io.IOException.class, () -> module.getKeystoreFile());
            assertTrue("the only copy of the key must be left intact for the next attempt",
                    legacy.exists());
        } finally {
            noBackupDir.setWritable(true);
        }
    }

    @Test
    public void legacyFlatQuarantinedFiles_areMovedIntoNoBackupStorage() throws Exception {
        // This is the layout an already-installed device actually holds: every release before the
        // keystore_forensics/ subdirectory existed wrote quarantined copies flat into the files dir
        // next to the live keystore. Each one is a complete copy of a private key, so a migration
        // that only swept the subdirectory would leave them backup-eligible forever.
        File legacyQuarantined =
                new File(context.getFilesDir(), KEYSTORE_NAME + ".corrupted.20250101_000000");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacyQuarantined)) {
            fos.write("quarantined key material".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("flat quarantined copies must not stay in backup-eligible storage",
                legacyQuarantined.exists());
        assertTrue("flat quarantined copies should be relocated for forensics, not discarded",
                new File(new File(context.getNoBackupFilesDir(), "keystore_forensics"),
                        legacyQuarantined.getName()).exists());
    }

    @Test
    public void legacyQuarantinedFiles_areMovedIntoNoBackupStorage() throws Exception {
        File legacyForensicsDir = new File(context.getFilesDir(), "keystore_forensics");
        assertTrue(legacyForensicsDir.isDirectory() || legacyForensicsDir.mkdirs());
        File legacyQuarantined =
                new File(legacyForensicsDir, KEYSTORE_NAME + ".corrupted.20250101_000000000");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacyQuarantined)) {
            fos.write("quarantined key material".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("quarantined copies must not stay in backup-eligible storage",
                legacyQuarantined.exists());
        assertTrue("quarantined copies should be relocated for forensics, not discarded",
                new File(new File(context.getNoBackupFilesDir(), "keystore_forensics"),
                        legacyQuarantined.getName()).exists());
        assertFalse("emptied legacy forensics directory should be removed", legacyForensicsDir.exists());
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
        // setUp() empties that directory, so an exact count proves this corruption produced the
        // file rather than an earlier test leaving one behind.
        List<String> corrupted = quarantinedNames(keystoreFile);
        assertEquals("this corruption should have quarantined exactly one .corrupted. file",
                1, corrupted.size());
    }

    @Test
    public void corruptedFileRetention_cappedAtThreeMostRecent() throws Exception {
        module.generateCSRInternal(paramsFor("retention-seed-alias", "secp256r1"));
        File keystoreFile = module.getKeystoreFile();

        // Simulate 5 corruption cycles, recording the quarantine filename each one produces so
        // the retention *order* can be asserted, not just the surviving count.
        List<String> quarantinedInOrder = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(keystoreFile)) {
                fos.write(("corrupt-" + i).getBytes());
            }
            // The quarantine filename carries a millisecond timestamp, and cleanupCorruptedFiles()
            // ranks on that name rather than on lastModified() - so this sleep only has to outrun
            // the millisecond clock, not the host filesystem's timestamp resolution. Without it two
            // cycles could land in the same millisecond, producing an identical filename that
            // renameTo would silently overwrite.
            Thread.sleep(10);
            module.generateCSRInternal(paramsFor("retention-alias-" + i, "secp256r1"));

            for (String name : quarantinedNames(keystoreFile)) {
                if (!quarantinedInOrder.contains(name)) {
                    quarantinedInOrder.add(name);
                }
            }
        }

        assertEquals("each of the 5 corruption cycles should quarantine a distinctly-named file",
                5, quarantinedInOrder.size());

        List<String> survivors = quarantinedNames(keystoreFile);
        assertEquals("exactly 3 .corrupted files should be retained after 5 corruption cycles",
                3, survivors.size());

        // Pin *which* 3 survive: the 3 most recently quarantined, i.e. the last 3 created.
        List<String> expected = new ArrayList<>(quarantinedInOrder.subList(2, 5));
        Collections.sort(expected);
        Collections.sort(survivors);
        assertEquals("retention must keep the 3 most recent quarantined files and drop the oldest 2",
                expected, survivors);
    }

    private File forensicsDir(File keystoreFile) {
        return new File(keystoreFile.getParentFile(), "keystore_forensics");
    }

    private List<String> quarantinedNames(File keystoreFile) {
        File[] files = forensicsDir(keystoreFile).listFiles(
                (dir, name) -> name.startsWith(keystoreFile.getName() + ".corrupted."));
        List<String> names = new ArrayList<>();
        if (files != null) {
            for (File file : files) {
                names.add(file.getName());
            }
        }
        return names;
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
        // "host:port" strings are rejected by InetAddress.getByName() itself - a single
        // colon is not valid syntax for a hostname or an IP literal, so this fails via the
        // outer UnknownHostException catch rather than the colon-counting IPv6 guard below it.
        assertFalse(module.isValidIPAddress("example.com:8080"));
        assertFalse(module.isValidIPAddress("evil-host:1"));
    }

    @Test
    public void isValidIPAddress_acceptsBracketedIPv6() {
        // Covers the bracket-stripping normalization, which no other test input reaches: a
        // bracketed literal only compares equal to getHostAddress()'s unbracketed expanded form
        // after the brackets are removed. Like bare "::1", it then decides in the colon branch
        // via the re-parse comparison (the "host:port" cases above never get that far).
        assertTrue(module.isValidIPAddress("[::1]"));
        assertTrue(module.isValidIPAddress("[2001:db8::1]"));
    }

    @Test
    public void isValidIPAddress_rejectsHostnamesWithoutRelyingOnDNS() {
        // ".invalid" is reserved by RFC 2606 and must never resolve, so this rejection is a
        // real hostname rejection on any runner - unlike "example.com", which passes via the
        // literal-comparison path when DNS resolves and via UnknownHostException when it
        // doesn't, and so would pass vacuously on a CI runner with no resolver.
        assertFalse(module.isValidIPAddress("not-a-real-host.invalid"));
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
        assertFalse("software fallback key can't be hardware-backed", result.isHardwareBacked);
        assertFalse("API 30 device must report TLS-incompatible", result.tlsCompatible);
        assertNotNull("fallback to software must still produce a keystore descriptor",
                result.keystorePath);
    }
}
