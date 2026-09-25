package com.ecccsr

import android.os.Build
import com.ecccsr.testutil.FakeContext
import com.ecccsr.testutil.Outcome
import com.ecccsr.testutil.settle
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.util.io.pem.PemReader
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.util.ReflectionHelpers
import java.io.File
import java.io.IOException
import java.io.StringReader
import java.security.KeyStore
import java.util.Base64

/**
 * Unit tests for CSRCore that exercise the real production code: the entry points the Expo module
 * calls, and generateCSRInternal / getHardwareKeystoreCapabilitiesInternal where a test needs the
 * typed result or the underlying exception rather than the CSRException.
 */
@RunWith(RobolectricTestRunner::class)
class CSRCoreTest {

  private lateinit var module: CSRCore
  private lateinit var context: FakeContext
  private val originalSdkInt = Build.VERSION.SDK_INT

  @Before
  fun setUp() {
    context = FakeContext(RuntimeEnvironment.getApplication())
    module = CSRCore(context)

    // Robolectric may hand out the same app directories to more than one test method, so a
    // leftover keystore or quarantined file would let the corruption tests below pass on
    // another test's artifacts. Start every test from a known-empty state, in both the live
    // no-backup location and the legacy backup-eligible one the migration tests populate.
    for (dir in listOf(checkNotNull(context.noBackupFilesDir), context.filesDir)) {
      // One prefix covers the keystore, its .tmp, and both quarantine infixes - including the
      // flat layout pre-subdirectory releases used, which the migration tests stage here.
      dir.listFiles { _, name -> name.startsWith(KEYSTORE_NAME) }?.forEach { it.delete() }
      File(dir, FORENSICS_DIR).listFiles()?.forEach { it.delete() }
    }

    // Scaffolding the failure-injection tests below leave behind, in the real no-backup dir.
    File(context.noBackupFilesDir, BLOCKED_PARENT).delete()
    File(context.noBackupFilesDir, ALT_NO_BACKUP_DIR).deleteRecursively()
  }

  @After
  fun restoreSdkInt() {
    ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", originalSdkInt)
  }

  private fun paramsFor(alias: String, curve: String?) = CSRParams().apply {
    commonName = "test-device"
    privateKeyAlias = alias
    this.curve = curve
  }

  // ---- CSR generation: valid, parseable CSR with the expected DN, per curve ----

  @Test
  fun testGenerateCSRForP256ProducesParseableCSRWithExpectedDN() {
    val params = paramsFor("alias-p256", "secp256r1")
    params.country = "US"
    params.organization = "Generac Power Systems"

    val result = module.generateCSRInternal(params)

    val csr = parseCSR(result.csr)
    val subject = csr.subject.toString()
    assertTrue(subject.contains("CN=test-device"))
    assertTrue(subject.contains("C=US"))
    assertTrue(subject.contains("O=Generac Power Systems"))
    assertEquals("alias-p256", result.privateKeyAlias)
    assertFalse(result.useHardwareKey)
  }

  @Test
  fun testGenerateCSRForP384ProducesParseableCSR() {
    val result = module.generateCSRInternal(paramsFor("alias-p384", "secp384r1"))
    val csr = parseCSR(result.csr)
    assertTrue(csr.subject.toString().contains("CN=test-device"))
  }

  @Test
  fun testGenerateCSRForP521ProducesParseableCSR() {
    val result = module.generateCSRInternal(paramsFor("alias-p521", "secp521r1"))
    val csr = parseCSR(result.csr)
    assertTrue(csr.subject.toString().contains("CN=test-device"))
  }

  @Test
  fun testGenerateCSRSignatureVerifiesAgainstPublicKey() {
    val result = module.generateCSRInternal(paramsFor("alias-verify", "secp256r1"))
    val csr = parseCSR(result.csr)

    val bc = BouncyCastleProvider()
    val embeddedPublicKey = JcaPKCS10CertificationRequest(csr).setProvider(bc).publicKey
    val isValid = csr.isSignatureValid(
      JcaContentVerifierProviderBuilder()
        .setProvider(bc)
        .build(embeddedPublicKey),
    )
    assertTrue("CSR signature should verify against its own embedded public key", isValid)
  }

  @Test
  fun testGenerateCSRSignsWithDigestMatchingCurve() {
    // ecdsa-with-SHA256 / SHA384 / SHA512. iOS encodes the same OIDs, so both platforms issue
    // algorithm-consistent CSRs for the same curve.
    assertSignatureAlgorithm("alias-sig-p256", "secp256r1", "1.2.840.10045.4.3.2")
    assertSignatureAlgorithm("alias-sig-p384", "secp384r1", "1.2.840.10045.4.3.3")
    assertSignatureAlgorithm("alias-sig-p521", "secp521r1", "1.2.840.10045.4.3.4")
  }

  private fun assertSignatureAlgorithm(alias: String, curve: String, expectedOid: String) {
    val result = module.generateCSRInternal(paramsFor(alias, curve))
    val csr = parseCSR(result.csr)
    assertEquals(curve, expectedOid, csr.signatureAlgorithm.algorithm.id)

    val bc = BouncyCastleProvider()
    val embeddedPublicKey = JcaPKCS10CertificationRequest(csr).setProvider(bc).publicKey
    assertTrue(
      "$curve CSR signature should verify",
      csr.isSignatureValid(
        JcaContentVerifierProviderBuilder()
          .setProvider(bc)
          .build(embeddedPublicKey),
      ),
    )
  }

  private fun parseCSR(pem: String): PKCS10CertificationRequest {
    val pemObject = PemReader(StringReader(pem)).use { it.readPemObject() }
    assertNotNull("PEM should parse", pemObject)
    return PKCS10CertificationRequest(pemObject.content)
  }

  // ---- Key lifecycle: create -> keyExists -> getPublicKey -> deleteKey -> keyExists ----

  @Test
  fun testSoftwareKeyLifecycleCreateThenExistsThenDeleteThenGone() {
    val alias = "lifecycle-alias-${System.identityHashCode(this)}"
    module.generateCSRInternal(paramsFor(alias, "secp256r1"))

    assertEquals(true, settle { module.keyExists(alias) }.value())

    val publicKey = settle { module.getPublicKey(alias) }.value()
    assertNotNull(publicKey)
    // Must be valid base64
    Base64.getDecoder().decode(publicKey as String)

    assertEquals(true, settle { module.deleteKey(alias) }.value())

    assertEquals(false, settle { module.keyExists(alias) }.value())
  }

  @Test
  fun testKeyExistsForUnknownAliasResolvesFalse() {
    assertEquals(false, settle { module.keyExists("never-created-alias") }.value())
  }

  @Test
  fun testGetPublicKeyForUnknownAliasRejects() {
    settle { module.getPublicKey("never-created-alias") }.rejected("KEY_NOT_FOUND")
  }

  @Test
  fun testDeleteKeyForUnknownAliasResolvesFalse() {
    assertEquals(false, settle { module.deleteKey("never-created-alias") }.value())
  }

  // ---- Software keystore round-trip: write then load back ----

  @Test
  fun testSoftwareKeystoreWriteThenReloadRoundTrips() {
    val alias = "roundtrip-alias"
    module.generateCSRInternal(paramsFor(alias, "secp256r1"))

    val keystoreFile = module.getKeystoreFile()
    assertTrue("keystore file should exist after key generation", keystoreFile.exists())

    val reloaded = KeyStore.getInstance("PKCS12")
    keystoreFile.inputStream().use { reloaded.load(it, "".toCharArray()) }
    assertTrue(
      "reloaded keystore should contain the alias written by generateCSR",
      reloaded.containsAlias(alias),
    )
  }

  @Test
  fun testGenerateCSRResultIncludesKeystoreDescriptorForSoftwareKey() {
    val result = module.generateCSRInternal(paramsFor("descriptor-alias", "secp256r1"))

    assertNotNull("software-backed keys must expose a keystore descriptor", result.keystorePath)
    assertTrue(result.keystorePath.orEmpty().endsWith(KEYSTORE_NAME))
  }

  // ---- Backup exclusion: the key lives outside the backup set, and legacy copies are moved ----

  @Test
  fun testKeystoreLivesInNoBackupDirectory() {
    val keystoreFile = module.getKeystoreFile()

    // getNoBackupFilesDir() is excluded from Auto Backup, cloud backup and device transfer
    // unconditionally. That is what lets this module drop backup_rules.xml /
    // data_extraction_rules.xml and the manifest wiring the consuming app previously had to get
    // right - and it cannot be defeated by another library claiming the manifest attributes.
    assertEquals(context.noBackupFilesDir, keystoreFile.parentFile)
    assertNotEquals(
      "keystore must not sit in the backup-eligible files dir",
      context.filesDir,
      keystoreFile.parentFile,
    )
  }

  @Test
  fun testLegacyKeystoreIsMovedOutOfBackupEligibleStorageWithKeysIntact() {
    // Produce a real keystore through production code, then stage it where installs created
    // before the no-backup change kept it.
    val alias = "legacy-migration-alias"
    module.generateCSRInternal(paramsFor(alias, "secp256r1"))
    val current = File(context.noBackupFilesDir, KEYSTORE_NAME)
    val legacy = File(context.filesDir, KEYSTORE_NAME)
    assertTrue(
      "staging requires the generated keystore to start in no-backup storage",
      current.renameTo(legacy),
    )

    // Any keystore access must relocate the file and leave the key usable.
    val outcome = settle { module.keyExists(alias) }

    assertEquals("migrated keystore must still contain the key", true, outcome.value())
    assertTrue("keystore should have been migrated into no-backup storage", current.exists())
    assertFalse("legacy backup-eligible copy must not survive migration", legacy.exists())
  }

  @Test
  fun testLegacyKeystoreSupersededByCurrentLocationIsDeleted() {
    module.generateCSRInternal(paramsFor("current-alias", "secp256r1"))
    val current = File(context.noBackupFilesDir, KEYSTORE_NAME)
    val currentLength = current.length()

    // A stale pre-migration file next to a populated no-backup keystore still holds a private
    // key in backup-eligible storage, so it has to be removed rather than ignored - and it must
    // not clobber the live keystore on its way out.
    val legacy = File(context.filesDir, KEYSTORE_NAME)
    legacy.writeText("stale pre-migration keystore")
    // Backdate it. On a straight upgrade the legacy copy is by definition the older one; only
    // the downgrade case below produces a newer one, and that case is handled differently.
    assertTrue(legacy.setLastModified(current.lastModified() - 60_000L))

    module.getKeystoreFile()

    assertFalse("stale legacy keystore must be deleted", legacy.exists())
    assertEquals(
      "live keystore must not be overwritten by the stale copy",
      currentLength,
      current.length(),
    )
    assertTrue(
      "an older legacy copy is stale, so nothing should be quarantined",
      quarantinedNames(current, SUPERSEDED_INFIX).isEmpty(),
    )
  }

  @Test
  fun testLegacyKeystoreNewerThanNoBackupCopyWinsAndSupersededCopyIsQuarantined() {
    // Downgrade then upgrade: the device ran a post-migration build (key in no_backup/), was
    // rolled back to a pre-migration build, and re-enrolled - writing a *newer* key into
    // getFilesDir(). Treating that one as stale would reactivate the older no-backup key and the
    // certificate issued for the newer one would stop matching. Only reachable off the Play
    // Store, which refuses to install a lower version.
    // Staging cannot go through two generateCSR calls: the second one would migrate the first
    // keystore back out of getFilesDir() before writing, so the two copies would never coexist.
    // Produce each keystore with production code, then place them by hand.
    module.generateCSRInternal(paramsFor(ROLLED_BACK_ALIAS, "secp256r1"))
    val current = File(context.noBackupFilesDir, KEYSTORE_NAME)
    val reenrolledKeystore = current.readBytes()
    assertTrue(current.delete())

    // The no-backup keystore as it stood before the downgrade: a different key, and older.
    module.generateCSRInternal(paramsFor("pre-downgrade-alias", "secp256r1"))
    val legacy = File(context.filesDir, KEYSTORE_NAME)
    legacy.writeBytes(reenrolledKeystore)
    assertTrue("staging requires both copies to exist", current.exists() && legacy.exists())
    assertTrue(current.setLastModified(legacy.lastModified() - 60_000L))

    val outcome = settle { module.keyExists(ROLLED_BACK_ALIAS) }

    assertEquals(
      "the newer legacy keystore must win, not be deleted as stale",
      true,
      outcome.value(),
    )
    assertFalse("the newer copy must not stay in backup-eligible storage", legacy.exists())

    // The loser is a complete private key and the comparison that picked a winner is a
    // modification time, so it is kept for forensics rather than silently discarded.
    val superseded = quarantinedNames(current, SUPERSEDED_INFIX)
    assertEquals(
      "the superseded no-backup copy should be quarantined, not deleted",
      1,
      superseded.size,
    )
  }

  @Test
  fun testEqualModificationTimesKeepBothKeysInsteadOfDeletingTheLegacyOne() {
    // The two downgrade tests above put the stamps a minute apart, which only proves the
    // comparison works when the filesystem's mtime resolution is fine enough to rank the files.
    // On a filesystem that reports modification times at one- or two-second resolution - the same
    // hazard cleanupQuarantinedFiles() reads recency from the filename to avoid - the pair that
    // the downgrade path produces lands on identical stamps, because generateCSR() writes
    // getFilesDir()/software_keys.p12 moments after the no-backup copy was last touched. A tie
    // that fell through to moveOutOfBackupEligibleStorage() would delete the legacy file as
    // stale, which on this path is the *newer* private key.
    module.generateCSRInternal(paramsFor(ROLLED_BACK_ALIAS, "secp256r1"))
    val current = File(context.noBackupFilesDir, KEYSTORE_NAME)
    val reenrolledKeystore = current.readBytes()
    assertTrue(current.delete())

    module.generateCSRInternal(paramsFor("pre-downgrade-alias", "secp256r1"))
    val legacy = File(context.filesDir, KEYSTORE_NAME)
    legacy.writeBytes(reenrolledKeystore)
    assertTrue("staging requires both copies to exist", current.exists() && legacy.exists())
    // Both stamps identical: the tie a coarse-resolution filesystem would report.
    assertTrue(current.setLastModified(legacy.lastModified()))
    assertEquals(
      "staging requires the stamps to be indistinguishable",
      legacy.lastModified(),
      current.lastModified(),
    )

    val outcome = settle { module.keyExists(ROLLED_BACK_ALIAS) }

    // A tie is unresolvable from the filesystem, so neither key may be discarded: the legacy copy
    // becomes live and the no-backup copy is kept for forensics.
    assertEquals(
      "an unrankable legacy keystore must not be deleted as stale",
      true,
      outcome.value(),
    )
    assertFalse("the legacy copy must not stay in backup-eligible storage", legacy.exists())
    assertEquals(
      "the tied no-backup copy should be quarantined, not deleted",
      1,
      quarantinedNames(current, SUPERSEDED_INFIX).size,
    )
  }

  @Test
  fun testSupersededKeystoreThatCannotBeQuarantinedFailsInsteadOfDeletingTheNewerKey() {
    // Same downgrade staging as above, but with the quarantine destination unusable. Returning
    // normally here would drop straight into the "destination exists, so the source is stale"
    // branch and delete the newer key.
    module.generateCSRInternal(paramsFor(ROLLED_BACK_ALIAS, "secp256r1"))
    val legacy = File(context.filesDir, KEYSTORE_NAME)
    assertTrue(File(context.noBackupFilesDir, KEYSTORE_NAME).renameTo(legacy))

    val altNoBackupDir = File(context.noBackupFilesDir, ALT_NO_BACKUP_DIR)
    assertTrue(altNoBackupDir.isDirectory || altNoBackupDir.mkdirs())
    val superseded = File(altNoBackupDir, KEYSTORE_NAME)
    superseded.writeText("pre-downgrade keystore")
    assertTrue(superseded.setLastModified(legacy.lastModified() - 60_000L))
    // A regular file occupying the keystore_forensics/ path makes mkdirs() fail for every user
    // on every filesystem, root included.
    assertTrue(File(altNoBackupDir, FORENSICS_DIR).createNewFile())
    context.noBackupFilesDirOverride = altNoBackupDir

    assertThrows(IOException::class.java) { module.getKeystoreFile() }
    assertTrue(
      "the newer key must be left where it is rather than deleted as stale",
      legacy.exists(),
    )
    assertTrue(
      "the superseded copy must not be destroyed by a failed quarantine",
      superseded.exists(),
    )
  }

  @Test
  fun testLegacyTempKeystoreIsDeleted() {
    // An interrupted atomic write leaves a .tmp that is a complete copy of the keystore.
    val legacyTemp = File(context.filesDir, "$KEYSTORE_NAME.tmp")
    legacyTemp.writeText("interrupted write holding a full keystore copy")

    module.getKeystoreFile()

    assertFalse("leftover .tmp copies must not stay backup-eligible", legacyTemp.exists())
  }

  @Test
  fun testNoBackupDirUnavailableFailsInsteadOfWritingToAnUnprotectedPath() {
    context.noBackupFilesDirUnavailable = true

    // File(null as File?, "software_keys.p12") is legal and yields a bare relative path
    // resolved against the process working directory - no backup exclusion, no 0600. Refusing
    // is the only safe outcome, and it has to be loud rather than logged.
    assertThrows(IOException::class.java) { module.getKeystoreFile() }
  }

  @Test
  fun testNoBackupDirUnavailableMakesKeyExistsRejectInsteadOfAnsweringFalse() {
    context.noBackupFilesDirUnavailable = true

    val outcome = settle { module.keyExists("some-alias") }

    // The software-keystore branch normally swallows failures and resolves false. Doing that
    // when storage itself is unreachable would tell the app its key is gone, and the app would
    // re-enrol with a new key while its issued certificate silently stopped matching.
    assertTrue("unreachable keystore storage must reject, not resolve false", outcome is Outcome.Rejected)
    outcome.rejected("KEY_EXISTS_ERROR")
  }

  @Test
  fun testNoBackupDirUnavailableMakesGetPublicKeyRejectInsteadOfReportingKeyNotFound() {
    context.noBackupFilesDirUnavailable = true

    val outcome = settle { module.getPublicKey("some-alias") }

    // KEY_NOT_FOUND is the answer for "this alias has no key", and an app is entitled to
    // re-enrol on it. Unreachable storage is not that, so it has to arrive as a distinct error.
    outcome.rejected("GET_PUBLIC_KEY_ERROR")
  }

  @Test
  fun testNoBackupDirUnavailableMakesDeleteKeyRejectInsteadOfResolvingFalse() {
    context.noBackupFilesDirUnavailable = true

    val outcome = settle { module.deleteKey("some-alias") }

    // Resolving false would read as "there was nothing to delete" when in fact the keystore was
    // never reached and a key may well still be in it.
    outcome.rejected("DELETE_KEY_ERROR")
  }

  @Test
  fun testNoBackupDirUnavailableMakesHardwareBackedGenerateCSRFailInsteadOfLeavingAStaleSoftwareKey() {
    // The hardware path deletes any software key under the same alias first, precisely so a
    // later getPublicKey() cannot return the stale one. If that deletion cannot reach the
    // keystore, it does not know whether a stale key is there, and a CSR issued anyway leaves the
    // dual-store collision in place. Asserting on the type is what makes this test meaningful: a
    // swallowed KeystoreLocationException lets generation continue to the hardware keystore,
    // which fails with some other exception in this environment and would otherwise look alike.
    ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 31)
    context.noBackupFilesDirUnavailable = true

    val params = paramsFor("hardware-path-alias", "secp256r1")
    params.useHardwareKey = true

    assertThrows(CSRCore.KeystoreLocationException::class.java) {
      module.generateCSRInternal(params)
    }
  }

  @Test
  fun testLegacyKeystoreMigrationFailureFailsLoudlyInsteadOfShadowingTheKey() {
    // Stage a real keystore where pre-migration installs kept it, then point the module at a
    // no-backup directory that cannot be written to.
    val alias = "migration-failure-alias"
    module.generateCSRInternal(paramsFor(alias, "secp256r1"))
    val legacy = File(context.filesDir, KEYSTORE_NAME)
    assertTrue(File(context.noBackupFilesDir, KEYSTORE_NAME).renameTo(legacy))

    // The failure is injected rather than chmod-ed into place: setWritable(false) is a silent
    // no-op as root, so a permission-based version of this test skips instead of asserting on a
    // containerised CI runner - and this is the headline behaviour of the whole change.
    // A regular file occupies BLOCKED_PARENT, so nothing can be created underneath it.
    val blockedParent = File(context.noBackupFilesDir, BLOCKED_PARENT)
    assertTrue(blockedParent.createNewFile())
    context.noBackupFilesDirOverride = File(blockedParent, "no_backup")

    // Returning the no-backup path here would make loadSoftwareKeyStore() see no file and
    // build an empty keystore, so the device would re-enrol with a new key while its issued
    // certificate silently stopped matching - and the old key would stay backup-eligible.
    assertThrows(IOException::class.java) { module.getKeystoreFile() }
    assertTrue("the only copy of the key must be left intact for the next attempt", legacy.exists())

    // Same for the read paths that would otherwise answer "no key here".
    val outcome = settle { module.keyExists(alias) }
    assertTrue("a stranded legacy keystore must reject, not resolve false", outcome is Outcome.Rejected)
  }

  @Test
  fun testLegacyFlatQuarantinedFilesAreMovedIntoNoBackupStorage() {
    // This is the layout an already-installed device actually holds: every release before the
    // keystore_forensics/ subdirectory existed wrote quarantined copies flat into the files dir
    // next to the live keystore. Each one is a complete copy of a private key, so a migration
    // that only swept the subdirectory would leave them backup-eligible forever.
    val legacyQuarantined = File(context.filesDir, "$KEYSTORE_NAME${CORRUPTED_INFIX}20250101_000000")
    legacyQuarantined.writeText("quarantined key material")

    module.getKeystoreFile()

    assertFalse(
      "flat quarantined copies must not stay in backup-eligible storage",
      legacyQuarantined.exists(),
    )
    assertTrue(
      "flat quarantined copies should be relocated for forensics, not discarded",
      File(File(context.noBackupFilesDir, FORENSICS_DIR), legacyQuarantined.name).exists(),
    )
  }

  @Test
  fun testLegacyQuarantinedFilesAreMovedIntoNoBackupStorage() {
    val legacyForensicsDir = File(context.filesDir, FORENSICS_DIR)
    assertTrue(legacyForensicsDir.isDirectory || legacyForensicsDir.mkdirs())
    val legacyQuarantined =
      File(legacyForensicsDir, "$KEYSTORE_NAME${CORRUPTED_INFIX}20250101_000000000")
    legacyQuarantined.writeText("quarantined key material")

    module.getKeystoreFile()

    assertFalse(
      "quarantined copies must not stay in backup-eligible storage",
      legacyQuarantined.exists(),
    )
    assertTrue(
      "quarantined copies should be relocated for forensics, not discarded",
      File(File(context.noBackupFilesDir, FORENSICS_DIR), legacyQuarantined.name).exists(),
    )
    assertFalse("emptied legacy forensics directory should be removed", legacyForensicsDir.exists())
  }

  // ---- Corruption handling: corrupt keystore is quarantined, regeneration proceeds ----

  @Test
  fun testCorruptKeystoreIsQuarantinedAndRegenerationSucceeds() {
    // Establish a real keystore file first so getKeystoreFile() points at a live path.
    module.generateCSRInternal(paramsFor("pre-corruption-alias", "secp256r1"))
    val keystoreFile = module.getKeystoreFile()

    // Corrupt it.
    keystoreFile.writeText("not a valid pkcs12 file")

    // Regeneration must not throw and must succeed despite the corrupt file on disk.
    val result = module.generateCSRInternal(paramsFor("post-corruption-alias", "secp256r1"))
    assertNotNull(result.csr)

    // Quarantined files live in a keystore_forensics/ subdirectory (not alongside the live
    // keystore file) so a single backup-exclusion entry can cover all timestamped filenames.
    // setUp() empties that directory, so an exact count proves this corruption produced the
    // file rather than an earlier test leaving one behind.
    val corrupted = quarantinedNames(keystoreFile)
    assertEquals(
      "this corruption should have quarantined exactly one .corrupted. file",
      1,
      corrupted.size,
    )
  }

  @Test
  fun testCorruptedFileRetentionCappedAtThreeMostRecent() {
    module.generateCSRInternal(paramsFor("retention-seed-alias", "secp256r1"))
    val keystoreFile = module.getKeystoreFile()

    // Simulate 5 corruption cycles, recording the quarantine filename each one produces so
    // the retention *order* can be asserted, not just the surviving count.
    val quarantinedInOrder = mutableListOf<String>()
    for (i in 0 until 5) {
      keystoreFile.writeText("corrupt-$i")
      // The quarantine filename carries a millisecond timestamp, and cleanupCorruptedFiles()
      // ranks on that name rather than on lastModified() - so this sleep only has to outrun
      // the millisecond clock, not the host filesystem's timestamp resolution. Without it two
      // cycles could land in the same millisecond, producing an identical filename that
      // renameTo would silently overwrite.
      Thread.sleep(10)
      module.generateCSRInternal(paramsFor("retention-alias-$i", "secp256r1"))

      for (name in quarantinedNames(keystoreFile)) {
        if (name !in quarantinedInOrder) {
          quarantinedInOrder.add(name)
        }
      }
    }

    assertEquals(
      "each of the 5 corruption cycles should quarantine a distinctly-named file",
      5,
      quarantinedInOrder.size,
    )

    val survivors = quarantinedNames(keystoreFile)
    assertEquals(
      "exactly 3 .corrupted files should be retained after 5 corruption cycles",
      3,
      survivors.size,
    )

    // Pin *which* 3 survive: the 3 most recently quarantined, i.e. the last 3 created.
    val expected = quarantinedInOrder.subList(2, 5).sorted()
    assertEquals(
      "retention must keep the 3 most recent quarantined files and drop the oldest 2",
      expected,
      survivors.sorted(),
    )
  }

  private fun forensicsDir(keystoreFile: File): File = File(keystoreFile.parentFile, FORENSICS_DIR)

  private fun quarantinedNames(keystoreFile: File, infix: String = CORRUPTED_INFIX): List<String> =
    forensicsDir(keystoreFile)
      .listFiles { _, name -> name.startsWith(keystoreFile.name + infix) }
      ?.map { it.name }
      .orEmpty()

  // ---- Input validation: exercise the real production isValidIPAddress ----

  @Test
  fun testIsValidIPAddressAcceptsLiteralIPv4() {
    assertTrue(module.isValidIPAddress("192.168.1.1"))
    assertTrue(module.isValidIPAddress("10.0.0.1"))
  }

  @Test
  fun testIsValidIPAddressAcceptsLiteralIPv6() {
    assertTrue(module.isValidIPAddress("::1"))
    assertTrue(module.isValidIPAddress("2001:db8::1"))
  }

  @Test
  fun testIsValidIPAddressRejectsHostnames() {
    assertFalse(module.isValidIPAddress("localhost"))
    assertFalse(module.isValidIPAddress("example.com"))
  }

  @Test
  fun testIsValidIPAddressRejectsHostnamePortInjection() {
    // "host:port" strings are rejected by InetAddress.getByName() itself - a single
    // colon is not valid syntax for a hostname or an IP literal, so this fails via the
    // outer UnknownHostException catch rather than the colon-counting IPv6 guard below it.
    assertFalse(module.isValidIPAddress("example.com:8080"))
    assertFalse(module.isValidIPAddress("evil-host:1"))
  }

  @Test
  fun testIsValidIPAddressAcceptsBracketedIPv6() {
    // Covers the bracket-stripping normalization, which no other test input reaches: a
    // bracketed literal only compares equal to getHostAddress()'s unbracketed expanded form
    // after the brackets are removed. Like bare "::1", it then decides in the colon branch
    // via the re-parse comparison (the "host:port" cases above never get that far).
    assertTrue(module.isValidIPAddress("[::1]"))
    assertTrue(module.isValidIPAddress("[2001:db8::1]"))
  }

  @Test
  fun testIsValidIPAddressRejectsHostnamesWithoutRelyingOnDNS() {
    // ".invalid" is reserved by RFC 2606 and must never resolve, so this rejection is a
    // real hostname rejection on any runner - unlike "example.com", which passes via the
    // literal-comparison path when DNS resolves and via UnknownHostException when it
    // doesn't, and so would pass vacuously on a CI runner with no resolver.
    assertFalse(module.isValidIPAddress("not-a-real-host.invalid"))
  }

  @Test
  fun testIsValidIPAddressRejectsNullAndEmpty() {
    assertFalse(module.isValidIPAddress(null))
    assertFalse(module.isValidIPAddress(""))
    assertFalse(module.isValidIPAddress("   "))
  }

  @Test
  fun testGenerateCSRWithInvalidIPAddressIsRejected() {
    val params = paramsFor("bad-ip-alias", "secp256r1")
    params.ipAddress = "not-a-hostname-or-ip!!"

    settle { module.generateCSR(params) }.rejected("INVALID_IP")
  }

  @Test
  fun testGenerateCSRWithMissingAliasIsRejected() {
    val params = CSRParams().apply { commonName = "test-device" }

    settle { module.generateCSR(params) }.rejected("MISSING_ALIAS")
  }

  @Test
  fun testGenerateCSRWithInvalidCurveIsRejected() {
    val params = paramsFor("bad-curve-alias", "secp256k1")

    settle { module.generateCSR(params) }.rejected("INVALID_CURVE")
  }

  @Test
  fun testGenerateCSRTreatsNullParamsAsNotProvided() {
    // Expo leaves a Record field at its null default for an absent or undefined property, and
    // sets it to null for an explicit JS null. All three must take the default, as on iOS.
    val params = paramsFor("null-params-alias", null)
    params.country = null
    params.ipAddress = null

    val csr = parseCSR(module.generateCSRInternal(params).csr)
    assertTrue(csr.subject.toString().contains("C=US"))
    assertEquals("default curve is P-384", "1.2.840.10045.4.3.3", csr.signatureAlgorithm.algorithm.id)
  }

  @Test
  fun testGenerateCSRReportsAFailedStaleKeyCleanupAsAWarning() {
    // Robolectric has no AndroidKeyStore provider, so removing a stale hardware key under this
    // alias fails. Generation carries on into the software keystore, but the caller is told a
    // stale key may have survived rather than only finding it in logcat.
    val response = settle { module.generateCSR(paramsFor("stale-cleanup-alias", "secp256r1")) }.map()

    val warnings = response["warnings"] as List<*>?
    assertNotNull("a failed stale-key cleanup must be reported", warnings)
    assertTrue(warnings!!.single().toString().startsWith(CSRCore.STALE_KEY_CLEANUP_FAILED))
  }

  @Test
  fun testGenerateCSRResponseIncludesKeystoreMapForSoftwareKey() {
    // Asserts on the map the Expo module hands to JS, not just the typed CSRGenerationResult
    // the other tests exercise.
    val params = paramsFor("response-descriptor-alias", "secp256r1")

    val response = settle { module.generateCSR(params) }.map()
    assertTrue(
      "response must include a keystore map for a software-backed key",
      response.containsKey("keystore"),
    )

    val keystore = response["keystore"] as Map<*, *>?
    assertNotNull(keystore)
    assertTrue((keystore?.get("path") as String).endsWith(KEYSTORE_NAME))
    assertEquals("", keystore["password"])
    assertEquals("pkcs12", keystore["format"])
  }

  // ---- getHardwareKeystoreCapabilities / TLS-compatibility detection ----

  @Test
  fun testHardwareCapabilitiesBelowApi31NotTlsCompatible() {
    // Android 11 (API 30) - below the API 31 PURPOSE_AGREE_KEY requirement.
    // Build.VERSION.SDK_INT is set directly (rather than via @Config(sdk=)) because
    // @Config triggers Robolectric's binary-resource loading path, which fails the manifest
    // merge in the standalone build this test was written against.
    ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 30)
    val caps = module.getHardwareKeystoreCapabilitiesInternal()
    assertFalse(caps.tlsCompatible)
    assertEquals(30, caps.androidSdkVersion)
  }

  @Test
  fun testHardwareCapabilitiesApi31PlusTlsCompatible() {
    // Android 12 (API 31) - PURPOSE_AGREE_KEY support added.
    ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 31)
    val caps = module.getHardwareKeystoreCapabilitiesInternal()
    assertTrue(caps.tlsCompatible)
    assertEquals(31, caps.androidSdkVersion)
  }

  @Test
  fun testHardwareCapabilitiesReturnsDocumentedShape() {
    val caps = module.getHardwareKeystoreCapabilitiesInternal()
    assertNotNull(caps.manufacturer)
    assertNotNull(caps.model)
    assertNotNull(caps.device)
  }

  @Test
  fun testGenerateCSRHardwareRequestedButUnsupportedFallsBackToSoftware() {
    // Set SDK explicitly rather than relying on Robolectric's ambient default (which is
    // derived from build.gradle's targetSdk/compileSdk 36, not a low fallback value) -
    // canUseHardwareKeysForTLS() requires API 31+, so API 30 forces software fallback.
    ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", 30)
    val params = paramsFor("hw-fallback-alias", "secp256r1")
    params.useHardwareKey = true

    val result = module.generateCSRInternal(params)

    assertTrue(result.hardwareKeyRequested)
    assertFalse(
      "device isn't TLS-compatible for hardware keys, must fall back to software",
      result.useHardwareKey,
    )
    assertFalse("software fallback key can't be hardware-backed", result.isHardwareBacked)
    assertFalse("API 30 device must report TLS-incompatible", result.tlsCompatible)
    assertNotNull(
      "fallback to software must still produce a keystore descriptor",
      result.keystorePath,
    )
  }

  private companion object {
    // Read from production rather than copied, so a rename on either side breaks the build instead
    // of quietly leaving these tests staging files at names production no longer uses.
    const val KEYSTORE_NAME = CSRCore.SOFTWARE_KEYSTORE_FILE
    const val CORRUPTED_INFIX = CSRCore.CORRUPTED_INFIX
    const val SUPERSEDED_INFIX = CSRCore.SUPERSEDED_INFIX
    const val FORENSICS_DIR = "keystore_forensics"

    /** Regular file that stands in for a directory, so anything created under it must fail. */
    const val BLOCKED_PARENT = "blocked-no-backup-parent"

    /** Real but separate no-backup directory, used to make one operation fail in isolation. */
    const val ALT_NO_BACKUP_DIR = "alt-no-backup"

    /** Alias of the key written by the post-downgrade re-enrolment in the migration tests. */
    const val ROLLED_BACK_ALIAS = "downgrade-reenrolled-alias"
  }
}
