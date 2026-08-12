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

/**
 * Unit tests for CSRModule that exercise the real production code (via generateCSRInternal /
 * getHardwareKeystoreCapabilitiesInternal, which are the same logic the @ReactMethod entry points
 * call, minus the RN bridge's WritableMap serialization step that requires a native JNI library
 * unavailable in this JVM-only test environment).
 */
@RunWith(RobolectricTestRunner.class)
public class CSRModuleTest {

    // Read from production rather than copied, so a rename on either side breaks the build instead
    // of quietly leaving these tests staging files at names production no longer uses.
    private static final String KEYSTORE_NAME = CSRModule.SOFTWARE_KEYSTORE_FILE;
    private static final String CORRUPTED_INFIX = CSRModule.CORRUPTED_INFIX;
    private static final String SUPERSEDED_INFIX = CSRModule.SUPERSEDED_INFIX;
    private static final String FORENSICS_DIR = "keystore_forensics";

    /** Regular file that stands in for a directory, so anything created under it must fail. */
    private static final String BLOCKED_PARENT = "blocked-no-backup-parent";

    /** Real but separate no-backup directory, used to make one operation fail in isolation. */
    private static final String ALT_NO_BACKUP_DIR = "alt-no-backup";

    /** Alias of the key written by the post-downgrade re-enrolment in the migration tests. */
    private static final String ROLLED_BACK_ALIAS = "downgrade-reenrolled-alias";

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
            // One prefix covers the keystore, its .tmp, and both quarantine infixes - including the
            // flat layout pre-subdirectory releases used, which the migration tests stage here.
            File[] keystoreFiles = dir.listFiles((unused, name) -> name.startsWith(KEYSTORE_NAME));
            if (keystoreFiles != null) {
                for (File file : keystoreFiles) {
                    file.delete();
                }
            }
            File[] leftovers = new File(dir, FORENSICS_DIR).listFiles();
            if (leftovers != null) {
                for (File leftover : leftovers) {
                    leftover.delete();
                }
            }
        }

        // Scaffolding the failure-injection tests below leave behind, in the real no-backup dir.
        new File(context.getNoBackupFilesDir(), BLOCKED_PARENT).delete();
        deleteRecursively(new File(context.getNoBackupFilesDir(), ALT_NO_BACKUP_DIR));
    }

    private static void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
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
    public void testGenerateCSRForP256ProducesParseableCSRWithExpectedDN() throws Exception {
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
    public void testGenerateCSRForP384ProducesParseableCSR() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("alias-p384", "secp384r1"));
        PKCS10CertificationRequest csr = parseCSR(result.csr);
        assertTrue(csr.getSubject().toString().contains("CN=test-device"));
    }

    @Test
    public void testGenerateCSRForP521ProducesParseableCSR() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("alias-p521", "secp521r1"));
        PKCS10CertificationRequest csr = parseCSR(result.csr);
        assertTrue(csr.getSubject().toString().contains("CN=test-device"));
    }

    @Test
    public void testGenerateCSRSignatureVerifiesAgainstPublicKey() throws Exception {
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
    public void testSoftwareKeyLifecycleCreateThenExistsThenDeleteThenGone() throws Exception {
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
    public void testKeyExistsForUnknownAliasResolvesFalse() {
        RecordingPromise promise = new RecordingPromise();
        module.keyExists("never-created-alias", promise);
        assertTrue(promise.resolved);
        assertEquals(Boolean.FALSE, promise.resolvedValue);
    }

    @Test
    public void testGetPublicKeyForUnknownAliasRejects() {
        RecordingPromise promise = new RecordingPromise();
        module.getPublicKey("never-created-alias", promise);
        assertTrue(promise.rejected);
        assertEquals("KEY_NOT_FOUND", promise.rejectedCode);
    }

    @Test
    public void testDeleteKeyForUnknownAliasResolvesFalse() {
        RecordingPromise promise = new RecordingPromise();
        module.deleteKey("never-created-alias", promise);
        assertTrue(promise.resolved);
        assertEquals(Boolean.FALSE, promise.resolvedValue);
    }

    // ---- Software keystore round-trip: write then load back ----

    @Test
    public void testSoftwareKeystoreWriteThenReloadRoundTrips() throws Exception {
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
    public void testGenerateCSRResultIncludesKeystoreDescriptorForSoftwareKey() throws Exception {
        CSRModule.CSRGenerationResult result = module.generateCSRInternal(paramsFor("descriptor-alias", "secp256r1"));

        assertNotNull("software-backed keys must expose a keystore descriptor", result.keystorePath);
        assertTrue(result.keystorePath.endsWith(KEYSTORE_NAME));
    }

    // ---- Backup exclusion: the key lives outside the backup set, and legacy copies are moved ----

    @Test
    public void testKeystoreLivesInNoBackupDirectory() throws Exception {
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
    public void testLegacyKeystoreIsMovedOutOfBackupEligibleStorageWithKeysIntact() throws Exception {
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
    public void testLegacyKeystoreSupersededByCurrentLocationIsDeleted() throws Exception {
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
        // Backdate it. On a straight upgrade the legacy copy is by definition the older one; only
        // the downgrade case below produces a newer one, and that case is handled differently.
        assertTrue(legacy.setLastModified(current.lastModified() - 60_000L));

        module.getKeystoreFile();

        assertFalse("stale legacy keystore must be deleted", legacy.exists());
        assertEquals("live keystore must not be overwritten by the stale copy",
                currentLength, current.length());
        assertTrue("an older legacy copy is stale, so nothing should be quarantined",
                quarantinedNames(current, SUPERSEDED_INFIX).isEmpty());
    }

    @Test
    public void testLegacyKeystoreNewerThanNoBackupCopyWinsAndSupersededCopyIsQuarantined()
            throws Exception {
        // Downgrade then upgrade: the device ran a post-migration build (key in no_backup/), was
        // rolled back to a pre-migration build, and re-enrolled - writing a *newer* key into
        // getFilesDir(). Treating that one as stale would reactivate the older no-backup key and the
        // certificate issued for the newer one would stop matching. Only reachable off the Play
        // Store, which refuses to install a lower version.
        // Staging cannot go through two generateCSR calls: the second one would migrate the first
        // keystore back out of getFilesDir() before writing, so the two copies would never coexist.
        // Produce each keystore with production code, then place them by hand.
        module.generateCSRInternal(paramsFor(ROLLED_BACK_ALIAS, "secp256r1"));
        File current = new File(context.getNoBackupFilesDir(), KEYSTORE_NAME);
        byte[] reenrolledKeystore = java.nio.file.Files.readAllBytes(current.toPath());
        assertTrue(current.delete());

        // The no-backup keystore as it stood before the downgrade: a different key, and older.
        module.generateCSRInternal(paramsFor("pre-downgrade-alias", "secp256r1"));
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        java.nio.file.Files.write(legacy.toPath(), reenrolledKeystore);
        assertTrue("staging requires both copies to exist", current.exists() && legacy.exists());
        assertTrue(current.setLastModified(legacy.lastModified() - 60_000L));

        RecordingPromise promise = new RecordingPromise();
        module.keyExists(ROLLED_BACK_ALIAS, promise);

        assertEquals("the newer legacy keystore must win, not be deleted as stale",
                Boolean.TRUE, promise.resolvedValue);
        assertFalse("the newer copy must not stay in backup-eligible storage", legacy.exists());

        // The loser is a complete private key and the comparison that picked a winner is a
        // modification time, so it is kept for forensics rather than silently discarded.
        List<String> superseded = quarantinedNames(current, SUPERSEDED_INFIX);
        assertEquals("the superseded no-backup copy should be quarantined, not deleted",
                1, superseded.size());
    }

    @Test
    public void testEqualModificationTimesKeepBothKeysInsteadOfDeletingTheLegacyOne()
            throws Exception {
        // The two downgrade tests above put the stamps a minute apart, which only proves the
        // comparison works when the filesystem's mtime resolution is fine enough to rank the files.
        // On a filesystem that reports modification times at one- or two-second resolution - the same
        // hazard cleanupQuarantinedFiles() reads recency from the filename to avoid - the pair that
        // the downgrade path produces lands on identical stamps, because generateCSR() writes
        // getFilesDir()/software_keys.p12 moments after the no-backup copy was last touched. A tie
        // that fell through to moveOutOfBackupEligibleStorage() would delete the legacy file as
        // stale, which on this path is the *newer* private key.
        module.generateCSRInternal(paramsFor(ROLLED_BACK_ALIAS, "secp256r1"));
        File current = new File(context.getNoBackupFilesDir(), KEYSTORE_NAME);
        byte[] reenrolledKeystore = java.nio.file.Files.readAllBytes(current.toPath());
        assertTrue(current.delete());

        module.generateCSRInternal(paramsFor("pre-downgrade-alias", "secp256r1"));
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        java.nio.file.Files.write(legacy.toPath(), reenrolledKeystore);
        assertTrue("staging requires both copies to exist", current.exists() && legacy.exists());
        // Both stamps identical: the tie a coarse-resolution filesystem would report.
        assertTrue(current.setLastModified(legacy.lastModified()));
        assertEquals("staging requires the stamps to be indistinguishable",
                legacy.lastModified(), current.lastModified());

        RecordingPromise promise = new RecordingPromise();
        module.keyExists(ROLLED_BACK_ALIAS, promise);

        // A tie is unresolvable from the filesystem, so neither key may be discarded: the legacy copy
        // becomes live and the no-backup copy is kept for forensics.
        assertEquals("an unrankable legacy keystore must not be deleted as stale",
                Boolean.TRUE, promise.resolvedValue);
        assertFalse("the legacy copy must not stay in backup-eligible storage", legacy.exists());
        assertEquals("the tied no-backup copy should be quarantined, not deleted",
                1, quarantinedNames(current, SUPERSEDED_INFIX).size());
    }

    @Test
    public void testSupersededKeystoreThatCannotBeQuarantinedFailsInsteadOfDeletingTheNewerKey()
            throws Exception {
        // Same downgrade staging as above, but with the quarantine destination unusable. Returning
        // normally here would drop straight into the "destination exists, so the source is stale"
        // branch and delete the newer key.
        module.generateCSRInternal(paramsFor(ROLLED_BACK_ALIAS, "secp256r1"));
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        assertTrue(new File(context.getNoBackupFilesDir(), KEYSTORE_NAME).renameTo(legacy));

        File altNoBackupDir = new File(context.getNoBackupFilesDir(), ALT_NO_BACKUP_DIR);
        assertTrue(altNoBackupDir.isDirectory() || altNoBackupDir.mkdirs());
        File superseded = new File(altNoBackupDir, KEYSTORE_NAME);
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(superseded)) {
            fos.write("pre-downgrade keystore".getBytes());
        }
        assertTrue(superseded.setLastModified(legacy.lastModified() - 60_000L));
        // A regular file occupying the keystore_forensics/ path makes mkdirs() fail for every user
        // on every filesystem, root included.
        assertTrue(new File(altNoBackupDir, FORENSICS_DIR).createNewFile());
        context.setNoBackupFilesDirOverride(altNoBackupDir);

        assertThrows(java.io.IOException.class, () -> module.getKeystoreFile());
        assertTrue("the newer key must be left where it is rather than deleted as stale",
                legacy.exists());
        assertTrue("the superseded copy must not be destroyed by a failed quarantine",
                superseded.exists());
    }

    @Test
    public void testLegacyTempKeystoreIsDeleted() throws Exception {
        // An interrupted atomic write leaves a .tmp that is a complete copy of the keystore.
        File legacyTemp = new File(context.getFilesDir(), KEYSTORE_NAME + ".tmp");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacyTemp)) {
            fos.write("interrupted write holding a full keystore copy".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("leftover .tmp copies must not stay backup-eligible", legacyTemp.exists());
    }

    @Test
    public void testNoBackupDirUnavailableFailsInsteadOfWritingToAnUnprotectedPath() {
        context.setNoBackupFilesDirUnavailable(true);

        // new File((File) null, "software_keys.p12") is legal Java and yields a bare relative path
        // resolved against the process working directory - no backup exclusion, no 0600. Refusing
        // is the only safe outcome, and it has to be loud rather than logged.
        assertThrows(java.io.IOException.class, () -> module.getKeystoreFile());
    }

    @Test
    public void testNoBackupDirUnavailableMakesKeyExistsRejectInsteadOfAnsweringFalse() {
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
    public void testNoBackupDirUnavailableMakesGetPublicKeyRejectInsteadOfReportingKeyNotFound() {
        context.setNoBackupFilesDirUnavailable(true);

        RecordingPromise promise = new RecordingPromise();
        module.getPublicKey("some-alias", promise);

        // KEY_NOT_FOUND is the answer for "this alias has no key", and an app is entitled to
        // re-enrol on it. Unreachable storage is not that, so it has to arrive as a distinct error.
        assertTrue(promise.rejected);
        assertEquals("GET_PUBLIC_KEY_ERROR", promise.rejectedCode);
    }

    @Test
    public void testNoBackupDirUnavailableMakesDeleteKeyRejectInsteadOfResolvingFalse() {
        context.setNoBackupFilesDirUnavailable(true);

        RecordingPromise promise = new RecordingPromise();
        module.deleteKey("some-alias", promise);

        // Resolving false would read as "there was nothing to delete" when in fact the keystore was
        // never reached and a key may well still be in it.
        assertTrue(promise.rejected);
        assertEquals("DELETE_KEY_ERROR", promise.rejectedCode);
    }

    @Test
    public void testNoBackupDirUnavailableMakesHardwareBackedGenerateCSRFailInsteadOfLeavingAStaleSoftwareKey() {
        // The hardware path deletes any software key under the same alias first, precisely so a
        // later getPublicKey() cannot return the stale one. If that deletion cannot reach the
        // keystore, it does not know whether a stale key is there, and a CSR issued anyway leaves the
        // dual-store collision in place. Asserting on the type is what makes this test meaningful: a
        // swallowed KeystoreLocationException lets generation continue to the hardware keystore,
        // which fails with some other exception in this environment and would otherwise look alike.
        ReflectionHelpers.setStaticField(android.os.Build.VERSION.class, "SDK_INT", 31);
        context.setNoBackupFilesDirUnavailable(true);

        JavaOnlyMap params = paramsFor("hardware-path-alias", "secp256r1");
        params.putBoolean("useHardwareKey", true);

        assertThrows(CSRModule.KeystoreLocationException.class,
                () -> module.generateCSRInternal(params));
    }

    @Test
    public void testLegacyKeystoreMigrationFailureFailsLoudlyInsteadOfShadowingTheKey() throws Exception {
        // Stage a real keystore where pre-migration installs kept it, then point the module at a
        // no-backup directory that cannot be written to.
        String alias = "migration-failure-alias";
        module.generateCSRInternal(paramsFor(alias, "secp256r1"));
        File legacy = new File(context.getFilesDir(), KEYSTORE_NAME);
        assertTrue(new File(context.getNoBackupFilesDir(), KEYSTORE_NAME).renameTo(legacy));

        // The failure is injected rather than chmod-ed into place: setWritable(false) is a silent
        // no-op as root, so a permission-based version of this test skips instead of asserting on a
        // containerised CI runner - and this is the headline behaviour of the whole change.
        // A regular file occupies BLOCKED_PARENT, so nothing can be created underneath it.
        File blockedParent = new File(context.getNoBackupFilesDir(), BLOCKED_PARENT);
        assertTrue(blockedParent.createNewFile());
        context.setNoBackupFilesDirOverride(new File(blockedParent, "no_backup"));

        // Returning the no-backup path here would make loadSoftwareKeyStore() see no file and
        // build an empty keystore, so the device would re-enrol with a new key while its issued
        // certificate silently stopped matching - and the old key would stay backup-eligible.
        assertThrows(java.io.IOException.class, () -> module.getKeystoreFile());
        assertTrue("the only copy of the key must be left intact for the next attempt",
                legacy.exists());

        // Same for the read paths that would otherwise answer "no key here".
        RecordingPromise promise = new RecordingPromise();
        module.keyExists(alias, promise);
        assertTrue("a stranded legacy keystore must reject, not resolve false", promise.rejected);
    }

    @Test
    public void testLegacyFlatQuarantinedFilesAreMovedIntoNoBackupStorage() throws Exception {
        // This is the layout an already-installed device actually holds: every release before the
        // keystore_forensics/ subdirectory existed wrote quarantined copies flat into the files dir
        // next to the live keystore. Each one is a complete copy of a private key, so a migration
        // that only swept the subdirectory would leave them backup-eligible forever.
        File legacyQuarantined =
                new File(context.getFilesDir(), KEYSTORE_NAME + CORRUPTED_INFIX + "20250101_000000");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacyQuarantined)) {
            fos.write("quarantined key material".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("flat quarantined copies must not stay in backup-eligible storage",
                legacyQuarantined.exists());
        assertTrue("flat quarantined copies should be relocated for forensics, not discarded",
                new File(new File(context.getNoBackupFilesDir(), FORENSICS_DIR),
                        legacyQuarantined.getName()).exists());
    }

    @Test
    public void testLegacyQuarantinedFilesAreMovedIntoNoBackupStorage() throws Exception {
        File legacyForensicsDir = new File(context.getFilesDir(), FORENSICS_DIR);
        assertTrue(legacyForensicsDir.isDirectory() || legacyForensicsDir.mkdirs());
        File legacyQuarantined =
                new File(legacyForensicsDir, KEYSTORE_NAME + CORRUPTED_INFIX + "20250101_000000000");
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(legacyQuarantined)) {
            fos.write("quarantined key material".getBytes());
        }

        module.getKeystoreFile();

        assertFalse("quarantined copies must not stay in backup-eligible storage",
                legacyQuarantined.exists());
        assertTrue("quarantined copies should be relocated for forensics, not discarded",
                new File(new File(context.getNoBackupFilesDir(), FORENSICS_DIR),
                        legacyQuarantined.getName()).exists());
        assertFalse("emptied legacy forensics directory should be removed", legacyForensicsDir.exists());
    }

    // ---- Corruption handling: corrupt keystore is quarantined, regeneration proceeds ----

    @Test
    public void testCorruptKeystoreIsQuarantinedAndRegenerationSucceeds() throws Exception {
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
    public void testCorruptedFileRetentionCappedAtThreeMostRecent() throws Exception {
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
        return new File(keystoreFile.getParentFile(), FORENSICS_DIR);
    }

    private List<String> quarantinedNames(File keystoreFile) {
        return quarantinedNames(keystoreFile, CORRUPTED_INFIX);
    }

    private List<String> quarantinedNames(File keystoreFile, String infix) {
        File[] files = forensicsDir(keystoreFile).listFiles(
                (dir, name) -> name.startsWith(keystoreFile.getName() + infix));
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
    public void testIsValidIPAddressAcceptsLiteralIPv4() {
        assertTrue(module.isValidIPAddress("192.168.1.1"));
        assertTrue(module.isValidIPAddress("10.0.0.1"));
    }

    @Test
    public void testIsValidIPAddressAcceptsLiteralIPv6() {
        assertTrue(module.isValidIPAddress("::1"));
        assertTrue(module.isValidIPAddress("2001:db8::1"));
    }

    @Test
    public void testIsValidIPAddressRejectsHostnames() {
        assertFalse(module.isValidIPAddress("localhost"));
        assertFalse(module.isValidIPAddress("example.com"));
    }

    @Test
    public void testIsValidIPAddressRejectsHostnamePortInjection() {
        // "host:port" strings are rejected by InetAddress.getByName() itself - a single
        // colon is not valid syntax for a hostname or an IP literal, so this fails via the
        // outer UnknownHostException catch rather than the colon-counting IPv6 guard below it.
        assertFalse(module.isValidIPAddress("example.com:8080"));
        assertFalse(module.isValidIPAddress("evil-host:1"));
    }

    @Test
    public void testIsValidIPAddressAcceptsBracketedIPv6() {
        // Covers the bracket-stripping normalization, which no other test input reaches: a
        // bracketed literal only compares equal to getHostAddress()'s unbracketed expanded form
        // after the brackets are removed. Like bare "::1", it then decides in the colon branch
        // via the re-parse comparison (the "host:port" cases above never get that far).
        assertTrue(module.isValidIPAddress("[::1]"));
        assertTrue(module.isValidIPAddress("[2001:db8::1]"));
    }

    @Test
    public void testIsValidIPAddressRejectsHostnamesWithoutRelyingOnDNS() {
        // ".invalid" is reserved by RFC 2606 and must never resolve, so this rejection is a
        // real hostname rejection on any runner - unlike "example.com", which passes via the
        // literal-comparison path when DNS resolves and via UnknownHostException when it
        // doesn't, and so would pass vacuously on a CI runner with no resolver.
        assertFalse(module.isValidIPAddress("not-a-real-host.invalid"));
    }

    @Test
    public void testIsValidIPAddressRejectsNullAndEmpty() {
        assertFalse(module.isValidIPAddress(null));
        assertFalse(module.isValidIPAddress(""));
        assertFalse(module.isValidIPAddress("   "));
    }

    @Test
    public void testGenerateCSRWithInvalidIPAddressIsRejected() {
        JavaOnlyMap params = paramsFor("bad-ip-alias", "secp256r1");
        params.putString("ipAddress", "not-a-hostname-or-ip!!");

        RecordingPromise promise = new RecordingPromise();
        module.generateCSR(params, promise);

        assertTrue(promise.rejected);
        assertEquals("INVALID_IP", promise.rejectedCode);
    }

    @Test
    public void testGenerateCSRWithMissingAliasIsRejected() {
        JavaOnlyMap params = new JavaOnlyMap();
        params.putString("commonName", "test-device");

        RecordingPromise promise = new RecordingPromise();
        module.generateCSR(params, promise);

        assertTrue(promise.rejected);
        assertEquals("MISSING_ALIAS", promise.rejectedCode);
    }

    @Test
    public void testGenerateCSRWithInvalidCurveIsRejected() {
        JavaOnlyMap params = paramsFor("bad-curve-alias", "secp256k1");

        RecordingPromise promise = new RecordingPromise();
        module.generateCSR(params, promise);

        assertTrue(promise.rejected);
        assertEquals("INVALID_CURVE", promise.rejectedCode);
    }

    @Test
    public void testGenerateCSRBridgeResultIncludesKeystoreMapForSoftwareKey() {
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
            assertTrue(keystore.getString("path").endsWith(KEYSTORE_NAME));
            assertEquals("", keystore.getString("password"));
            assertEquals("pkcs12", keystore.getString("format"));
        }
    }

    // ---- getHardwareKeystoreCapabilities / TLS-compatibility detection ----

    @Test
    public void testHardwareCapabilitiesBelowApi31NotTlsCompatible() {
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
    public void testHardwareCapabilitiesApi31PlusTlsCompatible() {
        // Android 12 (API 31) - PURPOSE_AGREE_KEY support added.
        ReflectionHelpers.setStaticField(android.os.Build.VERSION.class, "SDK_INT", 31);
        CSRModule.HardwareCapabilities caps = module.getHardwareKeystoreCapabilitiesInternal();
        assertTrue(caps.tlsCompatible);
        assertEquals(31, caps.androidSdkVersion);
    }

    @Test
    public void testHardwareCapabilitiesReturnsDocumentedShape() {
        CSRModule.HardwareCapabilities caps = module.getHardwareKeystoreCapabilitiesInternal();
        assertNotNull(caps.manufacturer);
        assertNotNull(caps.model);
        assertNotNull(caps.device);
    }

    @Test
    public void testGenerateCSRHardwareRequestedButUnsupportedFallsBackToSoftware() throws Exception {
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
