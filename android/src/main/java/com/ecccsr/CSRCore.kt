package com.ecccsr

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilenameFilter
import java.io.FilterOutputStream
import java.io.IOException
import java.io.OutputStream
import java.io.StringWriter
import java.math.BigInteger
import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.SignatureException
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Java's `String.trim()`: strips every character up to U+0020, control characters included.
 *
 * Kotlin's `trim()` strips Unicode whitespace instead (NBSP, U+2000-U+200A, ...) and leaves control
 * characters alone. Using it would change which aliases, IP addresses and DN values are accepted,
 * and the alias a key is stored under - so keys created by the Java version could stop being found.
 */
private fun String.trimJava(): String = trim { it <= ' ' }

/**
 * ECC key pair and CSR generation, with no dependency on React Native or Expo.
 *
 * The JS-facing module is the Expo module in `CSRModule.kt`, which only adapts arguments and
 * promises. Everything that decides behaviour - validation, key storage, error codes, response
 * shape - lives here so it stays unit-testable on a plain Robolectric [Context].
 *
 * Members documented as visible for tests are public rather than `internal`: the tests are Java,
 * and Kotlin mangles the JVM names of internal functions, so Java cannot call them by name.
 */
class CSRCore(private val context: Context) {

  /**
   * Where an entry point reports its outcome. Implemented by the Expo module over its promise,
   * and by tests to capture the outcome synchronously.
   *
   * Each entry point calls exactly one of these exactly once. The codes passed to reject are
   * part of the JS contract (callers match on `error.code`), so treat them as API.
   */
  interface Reply {
    fun resolve(value: Any?)

    fun reject(code: String, message: String?, cause: Throwable?)

    // A real JVM default method (build.gradle compiles with -Xjvm-default=all), so Java
    // implementations such as the tests' RecordingPromise inherit it.
    fun reject(code: String, message: String?) {
      reject(code, message, null)
    }
  }

  /**
   * The software keystore's location could not be established: either no-backup storage is
   * unavailable, or a legacy keystore is stranded in backup-eligible storage.
   *
   * Distinct from a generic failure because the keystore-reading entry points below deliberately
   * swallow "no software keystore here" and answer false / KEY_NOT_FOUND. Answering that way when
   * storage itself is broken would tell the app its key is gone, and the app would re-enrol with a
   * fresh key while the existing certificate silently stopped matching.
   *
   * Every method that catches broadly around a keystore access rethrows this type ahead of its
   * generic clause - keyExists, getPublicKey, deleteKey, deleteSoftwareKeyIfExists and
   * generateCSRInternal - so it reaches the entry point and the promise rejects. Adding a new such
   * catch without that clause is what turns this back into a log line.
   */
  class KeystoreLocationException : IOException {
    constructor(message: String) : super(message)

    constructor(message: String, cause: Throwable) : super(message, cause)
  }

  /** Thrown for validation failures that should be surfaced to JS as a specific error code. */
  class CSRRejectedException(@JvmField val code: String, message: String) : Exception(message)

  /**
   * Typed result of a CSR generation; [generateCSR] maps it for JS.
   *
   * Construct with named arguments so call sites can't silently swap the same-typed booleans.
   */
  class CSRGenerationResult(
    @JvmField val csr: String,
    @JvmField val privateKeyAlias: String,
    @JvmField val publicKeyBase64: String,
    @JvmField val isHardwareBacked: Boolean,
    @JvmField val useHardwareKey: Boolean,
    @JvmField val hardwareKeyRequested: Boolean,
    @JvmField val tlsCompatible: Boolean,
    @JvmField val keystorePath: String?, // null when useHardwareKey is true
  )

  /** Typed result of a capability check; [getHardwareKeystoreCapabilities] maps it for JS. */
  class HardwareCapabilities(
    @JvmField val tlsCompatible: Boolean,
    @JvmField val androidSdkVersion: Int,
    @JvmField val hasStrongBox: Boolean,
    @JvmField val manufacturer: String?,
    @JvmField val model: String?,
    @JvmField val device: String?,
  )

  init {
    ensureBouncyCastleProvider()
  }

  /**
   * Directory holding the software keystore: [Context.getNoBackupFilesDir], not `getFilesDir()`.
   *
   * Android never includes the no-backup directory in Auto Backup, cloud backup, or device
   * transfer, and that is true regardless of what the consuming app puts in its manifest. This
   * matters because android:fullBackupContent and android:dataExtractionRules each accept exactly
   * one resource reference and nothing merges them, so a library cannot reliably contribute
   * backup exclusions - whichever library or app sets the attribute wins and everyone else's
   * rules are silently inactive. Storing the private key outside the backup set removes that
   * coordination problem instead of documenting around it.
   *
   * Side effect: migrates any pre-existing keystore out of the legacy backup-eligible location.
   *
   * @throws IOException if the no-backup directory is unavailable, or if a legacy keystore could
   *         not be migrated. Both cases are failed loudly rather than worked around, because the
   *         quiet alternatives put private key material somewhere the caller does not expect.
   */
  @Throws(IOException::class)
  private fun getKeystoreDir(): File {
    // Typed nullable explicitly so the check below can't be optimised away if the platform
    // declaration is ever annotated non-null.
    val noBackupDir: File? = context.noBackupFilesDir
    if (noBackupDir == null) {
      // File(null as File?, name) is legal and yields the bare relative path "software_keys.p12",
      // resolved against the process working directory - outside the no-backup guarantee this
      // class relies on and outside the 0600 hardening below. The blast radius is key material,
      // so refuse rather than write to an unknown location.
      throw KeystoreLocationException(
        "getNoBackupFilesDir() returned null; refusing to store the private key outside no-backup storage")
    }
    migrateLegacyKeystoreIfNeeded(noBackupDir)
    return noBackupDir
  }

  /**
   * Move the keystore, any stale temp file, and any quarantined copies out of getFilesDir().
   *
   * Installs created before this change hold the key at files/software_keys.p12, which IS
   * backup-eligible whenever the consuming app allows backups and does not exclude the file
   * domain. Leaving it there would keep that exposure alive for every existing install, so the
   * legacy copy is not merely ignored - it is relocated, or deleted when the new location is
   * already populated and the legacy file is therefore stale.
   *
   * Deliberately not cached behind a flag: the check is a single stat, and running it on every
   * lookup means a partially-completed migration self-heals on the next call.
   *
   * @throws IOException if the live keystore exists in the legacy location and cannot be moved.
   *         Only that one file is fatal; see [migrateLegacyQuarantinedFiles] for why the
   *         quarantined copies are best-effort.
   */
  @Throws(IOException::class)
  private fun migrateLegacyKeystoreIfNeeded(noBackupDir: File) {
    val legacyDir: File? = context.filesDir
    if (legacyDir == null || legacyDir == noBackupDir) {
      return
    }

    synchronized(SOFTWARE_KEYSTORE_LOCK) {
      val legacyKeystore = File(legacyDir, SOFTWARE_KEYSTORE_FILE)
      val currentKeystore = File(noBackupDir, SOFTWARE_KEYSTORE_FILE)

      quarantineSupersededKeystore(legacyKeystore, currentKeystore, noBackupDir)

      if (!moveOutOfBackupEligibleStorage(legacyKeystore, currentKeystore)) {
        // Returning normally here would hand callers the no-backup path while the only
        // copy of the key sits at the legacy one. loadSoftwareKeyStore() would find no
        // file, create an empty keystore, and the device would silently re-enrol with a
        // new key while its issued certificate stopped matching. Fail so the caller can
        // retry instead.
        throw KeystoreLocationException(
          "Failed to migrate legacy software keystore out of backup-eligible storage: " +
            legacyKeystore.absolutePath)
      }

      // A leftover .tmp is a complete copy of the keystore, so it is just as sensitive.
      val legacyTemp = File(legacyDir, SOFTWARE_KEYSTORE_FILE + TEMP_SUFFIX)
      if (legacyTemp.exists() && !legacyTemp.delete()) {
        Log.w(MODULE_NAME, "Failed to delete legacy temp keystore from backup-eligible storage")
      }

      migrateLegacyQuarantinedFiles(legacyDir, noBackupDir)
    }
  }

  /**
   * Step aside for a legacy keystore that is not older than the no-backup one.
   *
   * [moveOutOfBackupEligibleStorage] reads a populated destination as proof the legacy file
   * is a stale leftover, which is true for a straight upgrade: the migration renames the file, so
   * the two cannot both exist afterwards. It is not true across downgrade then upgrade. A device
   * that ran a post-migration build (key in no_backup/), downgraded to a pre-migration build, and
   * re-enrolled wrote a *newer* key into getFilesDir(). Deleting that one as stale would silently
   * reactivate the older no-backup key while the certificate issued for the newer one stopped
   * matching - the failure this whole migration exists to avoid. Only reachable on
   * sideload/enterprise/dev channels, since the Play Store refuses to install a lower version.
   *
   * The loser is quarantined rather than deleted. It is a complete private key, and the comparison
   * that picked a winner is a modification time; if that inference is ever wrong, a forensic copy
   * in no-backup storage is recoverable and a deletion is not.
   *
   * A tie is treated as "the legacy copy may be newer", not as "the no-backup copy wins", which is
   * why the comparison is strictly less-than. [cleanupQuarantinedFiles] documents why
   * lastModified() cannot rank two files on a filesystem that reports modification times at one-
   * or two-second resolution, and both files here are produced within the same second on the path
   * that produces them: a single generateCSR() call writes getFilesDir()/software_keys.p12 moments
   * after the no-backup copy was last touched. Equal stamps under a `<=` test would return
   * early, and [moveOutOfBackupEligibleStorage] would then read the populated destination as
   * proof the legacy file is stale and delete it - deleting the newer key and reactivating the
   * older one. Quarantining on a tie keeps both: the legacy copy becomes live and the no-backup one
   * is preserved for forensics. The tie is not resolvable from the filesystem - the no-backup copy
   * carries no embedded timestamp, so the filename-based recency trick that
   * [cleanupQuarantinedFiles] uses does not transfer - so the safe answer is to keep both
   * copies. Cost is one extra forensic copy in the (unreachable-by-rename) case where both files
   * legitimately share a stamp, and the retention cap already bounds those at three.
   *
   * @throws IOException if the older copy cannot be quarantined. Returning normally would hand the
   *         caller straight back to [moveOutOfBackupEligibleStorage], which would then
   *         delete the newer legacy key as superseded - so failing here is what keeps the
   *         newer-copy guarantee from degrading into the exact data loss it prevents.
   */
  @Throws(IOException::class)
  private fun quarantineSupersededKeystore(legacyKeystore: File, currentKeystore: File, noBackupDir: File) {
    if (!legacyKeystore.exists() || !currentKeystore.exists() ||
      legacyKeystore.lastModified() < currentKeystore.lastModified()
    ) {
      return
    }

    val forensicsDir = File(noBackupDir, CORRUPTED_KEYSTORE_DIR)
    if (!forensicsDir.isDirectory && !forensicsDir.mkdirs()) {
      throw KeystoreLocationException(
        "A software keystore in backup-eligible storage is not older than the no-backup " +
          "copy but the superseded no-backup copy cannot be quarantined: " +
          "forensics directory unavailable")
    }

    val superseded = File(forensicsDir, SOFTWARE_KEYSTORE_FILE + SUPERSEDED_INFIX + quarantineTimestamp())
    if (!currentKeystore.renameTo(superseded)) {
      throw KeystoreLocationException(
        "A software keystore in backup-eligible storage is not older than the no-backup " +
          "copy but the superseded no-backup copy could not be quarantined: " +
          currentKeystore.absolutePath)
    }

    Log.w(MODULE_NAME, "Legacy software keystore is not older than the no-backup copy (downgrade " +
      "then upgrade, or an unrankable tie); quarantined the superseded copy as " +
      superseded.name)
    cleanupQuarantinedFiles(forensicsDir, SOFTWARE_KEYSTORE_FILE, SUPERSEDED_INFIX)
  }

  /**
   * Relocate quarantined corrupt keystores - each a complete copy of a private key - into
   * no-backup storage.
   *
   * Two legacy layouts exist and both have to be swept. Every release before this one wrote them
   * flat into getFilesDir() next to the live keystore ("software_keys.p12.corrupted.<ts>"), which
   * is what an already-installed device actually holds. A getFilesDir()/keystore_forensics/
   * directory only appears if a previous migration attempt was interrupted partway.
   *
   * Failures here are logged rather than thrown: unlike the live keystore, a stranded quarantine
   * copy is a privacy problem and not a correctness one, and the next lookup retries.
   *
   * One branch is worse than the others and is logged at error level accordingly: if the
   * destination directory cannot be created, no copy moves at all, and a retry hits the same
   * failure every time rather than making progress. The live keystore has already moved by that
   * point, so the caller sees a healthy migration while N complete copies of a private key stay in
   * backup-eligible storage.
   */
  private fun migrateLegacyQuarantinedFiles(legacyDir: File, noBackupDir: File) {
    val legacyQuarantined = mutableListOf<File>()

    val quarantineFilter = FilenameFilter { _, name -> name.startsWith(SOFTWARE_KEYSTORE_FILE + CORRUPTED_INFIX) }

    legacyDir.listFiles(quarantineFilter)?.let { legacyQuarantined.addAll(it) }

    // Filtered on the same prefix as the flat sweep and as the retention cap below. An
    // unfiltered listing would also move entries the cap cannot see - including directories,
    // which renameTo() relocates just as happily - so they would accumulate uncapped.
    val legacyForensicsDir = File(legacyDir, CORRUPTED_KEYSTORE_DIR)
    legacyForensicsDir.listFiles(quarantineFilter)?.let { legacyQuarantined.addAll(it) }

    if (legacyQuarantined.isEmpty()) {
      return
    }

    val forensicsDir = File(noBackupDir, CORRUPTED_KEYSTORE_DIR)
    if (!forensicsDir.isDirectory && !forensicsDir.mkdirs()) {
      Log.e(MODULE_NAME, "Failed to create no-backup forensics directory during migration: " +
        legacyQuarantined.size +
        " legacy private key copies remain in backup-eligible storage")
      return
    }

    for (file in legacyQuarantined) {
      moveOutOfBackupEligibleStorage(file, File(forensicsDir, file.name))
    }

    val unmovable = legacyForensicsDir.listFiles()
    if (unmovable != null && unmovable.isNotEmpty()) {
      Log.w(MODULE_NAME, "Legacy forensics directory holds " + unmovable.size +
        " entry/entries this migration does not recognise; leaving it in place")
    } else if (legacyForensicsDir.isDirectory && !legacyForensicsDir.delete()) {
      Log.w(MODULE_NAME, "Failed to remove emptied legacy forensics directory")
    }

    // Migrated copies bypass the quarantine path that normally enforces the cap, so apply it
    // here. Note this runs over the destination directory, so it ranks migrated copies together
    // with any this release already quarantined and can drop either - which is the intent: the
    // cap is on how many quarantined copies of a private key exist, not on how many arrived.
    cleanupQuarantinedFiles(forensicsDir, SOFTWARE_KEYSTORE_FILE, CORRUPTED_INFIX)
  }

  /**
   * Relocate one file into no-backup storage.
   *
   * If the destination already exists, the source is a stale leftover and gets deleted - keeping
   * it would leave a copy of the private key in the backup set for no benefit.
   *
   * @return false only when the file exists but could not be relocated, i.e. the source is still
   *         sitting in backup-eligible storage and the destination is still absent. A failed
   *         cleanup of a superseded source returns true: the destination is authoritative in that
   *         case, so callers can proceed.
   */
  private fun moveOutOfBackupEligibleStorage(source: File, destination: File): Boolean {
    if (!source.exists()) {
      return true
    }
    if (destination.exists()) {
      if (!source.delete()) {
        Log.w(MODULE_NAME, "Failed to delete superseded legacy file: " + source.name)
      }
      return true
    }
    if (source.renameTo(destination)) {
      Log.i(MODULE_NAME, "Migrated " + source.name + " to no-backup storage")
      return true
    }
    Log.w(MODULE_NAME, "Failed to migrate " + source.name + " to no-backup storage")
    return false
  }

  /**
   * Get File object for software keystore (plain file, no encryption).
   * Replaces EncryptedFile approach which had Tink keyset synchronization issues.
   *
   * Side effect: re-applies 0600 permissions to the file if it already exists. This is
   * idempotent and cheap, so callers don't need to treat this as a pure path lookup.
   *
   * Visible for tests.
   *
   * @throws IOException see [getKeystoreDir]
   */
  @Throws(IOException::class)
  fun getKeystoreFile(): File {
    val file = File(getKeystoreDir(), SOFTWARE_KEYSTORE_FILE)
    // Set secure permissions if file exists
    if (file.exists()) {
      setSecureFilePermissions(file)
    }
    return file
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
  @Throws(Exception::class)
  private fun loadSoftwareKeyStore(): KeyStore {
    val keyStore = KeyStore.getInstance("PKCS12")
    val keystoreFile = getKeystoreFile()

    if (!keystoreFile.exists()) {
      // No keystore exists, initialize empty
      keyStore.load(null, KEYSTORE_PASSWORD)
      return keyStore
    }

    try {
      FileInputStream(keystoreFile).use { fis -> keyStore.load(fis, KEYSTORE_PASSWORD) }
      return keyStore
    } catch (e: Exception) {
      if (e !is IOException && e !is GeneralSecurityException) {
        throw e
      }
      // Keystore file exists but can't be loaded (corrupted, wrong format, etc.)
      // Move it aside and start fresh to prevent permanent failure
      Log.e(MODULE_NAME, "Corrupt keystore detected, recovering by creating fresh keystore", e)

      val forensicsDir = File(keystoreFile.parentFile, CORRUPTED_KEYSTORE_DIR)
      if (!forensicsDir.isDirectory && !forensicsDir.mkdirs()) {
        Log.w(MODULE_NAME, "Failed to create forensics directory, deleting corrupt keystore instead")
        if (!keystoreFile.delete()) {
          throw IOException("Failed to delete corrupt keystore file", e)
        }
        keyStore.load(null, KEYSTORE_PASSWORD)
        return keyStore
      }

      val corruptedFile = File(forensicsDir, keystoreFile.name + CORRUPTED_INFIX + quarantineTimestamp())

      if (keystoreFile.renameTo(corruptedFile)) {
        Log.w(MODULE_NAME, "Moved corrupt keystore to: " + corruptedFile.name)

        // Clean up old .corrupted files (keep only the most recent 3)
        cleanupQuarantinedFiles(forensicsDir, keystoreFile.name, CORRUPTED_INFIX)
      } else {
        // If rename fails, delete the corrupt file as last resort
        Log.w(MODULE_NAME, "Failed to rename corrupt keystore, deleting it")
        if (!keystoreFile.delete()) {
          throw IOException("Failed to delete corrupt keystore file", e)
        }
      }

      // Initialize fresh empty keystore
      keyStore.load(null, KEYSTORE_PASSWORD)
      return keyStore
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
   * Guarantee: by the time this method returns normally, the keystore file at
   * getKeystoreFile()'s path is fully written and in place - callers may read its path
   * immediately afterward without needing to wait for any further completion signal.
   */
  @Throws(Exception::class)
  private fun saveSoftwareKeyStore(keyStore: KeyStore) {
    val keystoreFile = getKeystoreFile()
    // Same directory as the target so the rename below stays within one filesystem (and so the
    // temp copy is never written to backup-eligible storage).
    val tempFile = File(keystoreFile.parentFile, SOFTWARE_KEYSTORE_FILE + TEMP_SUFFIX)

    // Delete temp file if it exists from previous failed write
    if (tempFile.exists() && !tempFile.delete()) {
      throw IOException("Failed to delete existing temp keystore file")
    }

    // On API 26+ the temp file is created owner-only, so it never exists with default permissions.
    // Below that, FileOutputStream creates it and the permissions are narrowed straight afterwards,
    // before any key material is written.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      Files.createFile(tempFile.toPath(), PosixFilePermissions.asFileAttribute(
        hashSetOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)))
    }

    FileOutputStream(tempFile).use { fos ->
      setSecureFilePermissions(tempFile)
      keyStore.store(fos, KEYSTORE_PASSWORD)
      // Flush to disk before the rename: otherwise a power loss can leave the renamed file
      // pointing at data that was never written.
      fos.fd.sync()
    }

    // Use atomic move on API 26+ for better reliability
    // Atomic operations ensure the final file is only created after successful write
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      try {
        Files.move(tempFile.toPath(), keystoreFile.toPath(),
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING)
      } catch (e: AtomicMoveNotSupportedException) {
        // Fallback to non-atomic rename
        Log.w(MODULE_NAME, "Atomic move not supported, using File.renameTo()")
        if (!tempFile.renameTo(keystoreFile)) {
          throw IOException("Failed to rename temp keystore to final location")
        }
      }
    } else {
      // Fallback for older APIs - not truly atomic but best effort
      if (!tempFile.renameTo(keystoreFile)) {
        throw IOException("Failed to rename temp keystore to final location")
      }
    }
  }

  /**
   * ContentSigner implementation for Android Keystore.
   *
   * Uses a FilterOutputStream to feed signature.update() incrementally during writes
   * rather than buffering the full payload. This is architecturally safer than buffering
   * the entire TBS (to-be-signed) data in a ByteArrayOutputStream and feeding it to the
   * Signature object only in getSignature().
   */
  private class AndroidKeystoreContentSigner(privateKey: PrivateKey, algorithm: String) : ContentSigner {
    private val sigAlgId: AlgorithmIdentifier = DefaultSignatureAlgorithmIdentifierFinder().find(algorithm)
    private val signature: Signature = Signature.getInstance(algorithm).apply { initSign(privateKey) }

    // Wrap a FilterOutputStream that feeds signature.update() on each write
    private val outputStream: OutputStream = object : FilterOutputStream(ByteArrayOutputStream()) {
      @Throws(IOException::class)
      override fun write(b: Int) {
        try {
          signature.update(b.toByte())
        } catch (e: SignatureException) {
          throw IOException("Signature update failed", e)
        }
      }

      @Throws(IOException::class)
      override fun write(b: ByteArray, off: Int, len: Int) {
        try {
          signature.update(b, off, len)
        } catch (e: SignatureException) {
          throw IOException("Signature update failed", e)
        }
      }
    }

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier = sigAlgId

    override fun getOutputStream(): OutputStream = outputStream

    override fun getSignature(): ByteArray {
      try {
        // Signature already updated incrementally via outputStream writes
        return signature.sign()
      } catch (e: Exception) {
        throw RuntimeException("Failed to sign", e)
      } finally {
        try {
          outputStream.close()
        } catch (ignored: IOException) {
          // FilterOutputStream close - safe to ignore
        }
      }
    }
  }

  @Throws(Exception::class)
  private fun createSelfSignedCertificate(keyPair: KeyPair, subjectDN: String, keystoreCurve: String): X509Certificate {
    val now = System.currentTimeMillis()
    val startDate = Date(now)
    val endDate = Date(now + 365L * 24 * 60 * 60 * 1000)

    val subject = X500Name(subjectDN)
    val serialNumber = BigInteger.valueOf(now)
    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)

    val certBuilder = X509v3CertificateBuilder(subject, serialNumber, startDate, endDate, subject, publicKeyInfo)

    val signer = JcaContentSignerBuilder(signatureAlgorithmFor(keystoreCurve))
      .setProvider(FULL_BC_PROVIDER)
      .build(keyPair.private)

    return JcaX509CertificateConverter()
      .setProvider(FULL_BC_PROVIDER)
      .getCertificate(certBuilder.build(signer))
  }

  /**
   * Matches the digest to the curve's security level. Hardware keys are generated with all three
   * digests allowed (see generateHardwareKeyPair), so this holds for both key paths.
   */
  private fun signatureAlgorithmFor(keystoreCurve: String): String {
    return when (keystoreCurve) {
      "secp384r1" -> "SHA384withECDSA"
      "secp521r1" -> "SHA512withECDSA"
      else -> "SHA256withECDSA"
    }
  }

  private fun canUseHardwareKeysForTLS(): Boolean {
    // Android 12 (API 31) added PURPOSE_AGREE_KEY support for ECDH in hardware keystore
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
  }

  /**
   * Visible for tests, so they assert against the same alias rule generateCSRInternal enforces,
   * rather than a copy that can drift from production.
   */
  fun isValidAlias(alias: String?): Boolean {
    return alias != null && alias.trimJava().isNotEmpty()
  }

  /**
   * Visible for tests, so they assert against the same curve allow-list generateCSRInternal
   * enforces, rather than a copy that can drift from production.
   */
  fun isValidCurve(curve: String?): Boolean {
    return curve == "secp256r1" || curve == "secp384r1" || curve == "secp521r1"
  }

  /**
   * IP address validation - accepts only literal IP addresses, not hostnames.
   *
   * InetAddress.getByName() accepts hostnames that resolve via DNS, so we must
   * verify the input is a literal address by comparing the input to the resolved
   * address string. This prevents hostname injection into SAN iPAddress extensions,
   * which would produce malformed certificates.
   */
  fun isValidIPAddress(ip: String?): Boolean {
    if (ip == null || ip.trimJava().isEmpty()) {
      return false
    }
    try {
      val trimmed = ip.trimJava()

      // Reject strings that look like hostnames or have suspicious patterns
      if (trimmed.contains(" ") || trimmed.contains("//") || trimmed.contains("@")) {
        return false
      }

      val addr = InetAddress.getByName(trimmed)

      // Verify input is a literal IP address, not a hostname that resolved
      // For IPv6: normalize both sides by parsing and re-stringifying
      // This handles compressed forms (2001:db8::1) vs uncompressed (2001:db8:0:0:0:0:0:1)
      val resolvedAddr = addr.hostAddress

      // Remove IPv6 brackets for comparison
      val inputForComparison = trimmed.replace("[", "").replace("]", "")

      // Remove zone ID from resolved address if present (e.g., fe80::1%eth0 -> fe80::1)
      val resolvedForComparison = resolvedAddr?.substringBefore('%')

      // Try direct comparison first (handles IPv4 and exact IPv6 matches)
      if (resolvedForComparison == inputForComparison) {
        return true
      }

      // For IPv6, also check if both addresses contain colons (not port numbers)
      // Port notation like "host:8080" should be rejected
      if (inputForComparison.contains(":")) {
        // Defense-in-depth: every valid IPv6 literal has at least 2 colons (even "::"),
        // and InetAddress.getByName already throws UnknownHostException above for a
        // single-colon string like "host:8080" before this line is reached - so this
        // branch is not currently reachable, but is kept in case that parsing behavior
        // ever changes across JVM/Android versions.
        val colonCount = inputForComparison.count { it == ':' }
        if (colonCount < 2) {
          return false
        }

        // If input is a valid IPv6 literal, parsing it should yield the same InetAddress
        return try {
          val inputAddr = InetAddress.getByName(inputForComparison)
          inputAddr == addr
        } catch (e: UnknownHostException) {
          // Input couldn't be re-parsed, likely invalid
          false
        }
      }

      // Not IPv4 match, not IPv6 literal - reject as hostname
      return false
    } catch (e: UnknownHostException) {
      return false
    }
  }

  // Explicitly set file permissions to mode 0600
  private fun setSecureFilePermissions(file: File) {
    try {
      // For API 26+, use NIO POSIX permissions first (more reliable and atomic)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val perms = hashSetOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
        Files.setPosixFilePermissions(file.toPath(), perms)
      } else {
        // Fallback for older APIs - set permissions using File methods
        // Note: This has a race condition - file is briefly accessible with default permissions
        file.setReadable(false, false) // No one can read
        file.setReadable(true, true) // Owner can read
        file.setWritable(false, false) // No one can write
        file.setWritable(true, true) // Owner can write
        file.setExecutable(false, false) // No execution
      }
    } catch (e: Exception) {
      // Escalate to error level - this is a security issue
      Log.e(MODULE_NAME, "SECURITY WARNING: Failed to set secure file permissions on keystore: " + e.message)
    }
  }

  // Sanitize DN values (already handled by X500NameBuilder, but add explicit method)
  fun sanitizeDNValue(value: String?): String {
    // X500NameBuilder already handles escaping, but trim whitespace
    return value?.trimJava() ?: ""
  }

  fun generateCSR(params: Map<String, *>, promise: Reply) {
    try {
      val result = generateCSRInternal(params)

      val response = HashMap<String, Any?>()
      response["csr"] = result.csr
      response["privateKeyAlias"] = result.privateKeyAlias
      response["publicKey"] = result.publicKeyBase64
      response["isHardwareBacked"] = result.isHardwareBacked
      response["useHardwareKey"] = result.useHardwareKey
      response["hardwareKeyRequested"] = result.hardwareKeyRequested
      response["tlsCompatible"] = result.tlsCompatible

      if (result.keystorePath != null) {
        val keystoreDescriptor = HashMap<String, Any?>()
        keystoreDescriptor["path"] = result.keystorePath
        // KEYSTORE_PASSWORD is always empty (see its declaration for the security
        // rationale) and is expected to remain so. If this ever becomes non-empty,
        // it would cross into JS as a plain string, visible to JS/crash logs - do
        // not add a real secret here without revisiting that exposure.
        keystoreDescriptor["password"] = String(KEYSTORE_PASSWORD)
        keystoreDescriptor["format"] = "pkcs12"
        response["keystore"] = keystoreDescriptor
      }

      promise.resolve(response)
    } catch (e: CSRRejectedException) {
      promise.reject(e.code, e.message)
    } catch (e: Exception) {
      Log.e(MODULE_NAME, e.message, e)
      promise.reject("CSR_GENERATION_ERROR", e.message, e)
    }
  }

  /**
   * Core CSR generation logic, separated from [generateCSR] so tests can assert on the
   * typed result and on the exception type rather than on a reply.
   */
  @Throws(Exception::class)
  fun generateCSRInternal(params: Map<String, *>): CSRGenerationResult {
    var keyPair: KeyPair? = null
    var csr: PKCS10CertificationRequest? = null
    var currentStep = "initialization"

    try {
      // Extract and validate parameters
      currentStep = "parameter extraction"
      val country = sanitizeDNValue(optString(params, "country", DEFAULT_COUNTRY))
      val state = sanitizeDNValue(optString(params, "state", DEFAULT_STATE))
      val locality = sanitizeDNValue(optString(params, "locality", DEFAULT_LOCALITY))
      val organization = sanitizeDNValue(optString(params, "organization", DEFAULT_ORGANIZATION))
      val organizationalUnit = sanitizeDNValue(optString(params, "organizationalUnit", DEFAULT_ORGANIZATIONAL_UNIT))
      val commonName = sanitizeDNValue(optString(params, "commonName", ""))
      val serialNumber = sanitizeDNValue(optString(params, "serialNumber", ""))
      val ipAddress = optString(params, "ipAddress", DEFAULT_IP_ADDRESS)
      val dnsName = optString(params, "dnsName", null)
      val curve = optString(params, "curve", DEFAULT_ECC_CURVE)
      val phoneInfo = optString(params, "phoneInfo", null)
      val rawAlias = optString(params, "privateKeyAlias", null)

      // Validate required parameters. The null checks are what isValidAlias/isValidCurve
      // already reject; repeating them here is only so the compiler knows the values are set.
      if (rawAlias == null || !isValidAlias(rawAlias)) {
        throw CSRRejectedException("MISSING_ALIAS", "privateKeyAlias is required")
      }
      val privateKeyAlias = rawAlias.trimJava()

      if (curve == null || !isValidCurve(curve)) {
        throw CSRRejectedException("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1")
      }

      // Validate IP address
      if (ipAddress != null && ipAddress.trimJava().isNotEmpty() && !isValidIPAddress(ipAddress)) {
        throw CSRRejectedException("INVALID_IP", "Invalid IP address format: $ipAddress")
      }

      // Keys are always allowed to be overwritten for simplicity.
      // If a key with the same alias exists, it will be replaced.

      // App can request hardware, but module decides based on TLS compatibility
      val requestedHardwareKey = optBoolean(params, "useHardwareKey", false)

      // Override app preference if hardware won't work for TLS
      val useHardwareKey = requestedHardwareKey && canUseHardwareKeysForTLS()

      if (requestedHardwareKey && !useHardwareKey) {
        Log.w(MODULE_NAME, "Hardware key requested but not supported for TLS on this device (requires Android 12+). Using software keystore.")
      }

      Log.d(MODULE_NAME, "Starting CSR generation - alias: " + privateKeyAlias +
        ", curve: " + curve + ", hardware: " + useHardwareKey)

      val keystoreCurve: String = curve

      // Delete any existing key with the same alias from the OPPOSITE keystore
      // to prevent dual-store collision where getPublicKey returns stale key
      currentStep = "removing stale keys"
      try {
        if (useHardwareKey) {
          // About to use hardware, delete any software key with same alias
          deleteSoftwareKeyIfExists(privateKeyAlias)
        } else {
          // About to use software, delete any hardware key with same alias
          deleteHardwareKeyIfExists(privateKeyAlias)
        }
      } catch (e: KeystoreLocationException) {
        // Not a cleanup failure to shrug off: the software keystore could not be reached at
        // all, so nothing here can tell whether a stale software key survives under this
        // alias. Continuing would generate a hardware key beside it and hand back a CSR,
        // leaving a later getPublicKey() free to return the stale software key - the exact
        // dual-store collision this deletion prevents. Rethrown so the promise rejects.
        throw e
      } catch (e: Exception) {
        // Log stale key deletion failure but continue - this is a cleanup operation
        // and shouldn't block the main operation. deleteSoftwareKeyIfExists() swallows
        // everything except KeystoreLocationException, so this mostly catches
        // deleteHardwareKeyIfExists() failures (e.g., transient Android Keystore
        // unavailability). For software key generation, blocking on hardware keystore
        // failures is overly strict.
        Log.w(MODULE_NAME, "Failed to delete stale key from opposite keystore (continuing): " +
          e.message + ". May cause dual-store collision if key exists.", e)
        // Continue with key generation instead of rejecting
      }

      // Generate key pair
      currentStep = "key generation"
      val generated = if (useHardwareKey) {
        generateHardwareKeyPair(privateKeyAlias, keystoreCurve)
      } else {
        generateSoftwareKeyPair(privateKeyAlias, keystoreCurve)
      }
      keyPair = generated ?: throw Exception("Key pair generation returned null")

      currentStep = "CSR building"
      val privateKey = keyPair.private
      val publicKey = keyPair.public

      Log.d(MODULE_NAME, "Key pair generated: " + privateKeyAlias +
        " (" + (if (useHardwareKey) "hardware" else "software") + ", " + keystoreCurve + ")")

      // Build subject DN using X500NameBuilder (handles escaping)
      val subjectBuilder = X500NameBuilder(BCStyle.INSTANCE)
      subjectBuilder.addRDN(BCStyle.C, country)
      subjectBuilder.addRDN(BCStyle.ST, state)
      subjectBuilder.addRDN(BCStyle.L, locality)
      subjectBuilder.addRDN(BCStyle.O, organization)
      subjectBuilder.addRDN(BCStyle.OU, organizationalUnit)
      subjectBuilder.addRDN(BCStyle.CN, commonName)
      if (serialNumber.isNotEmpty()) {
        subjectBuilder.addRDN(BCStyle.SERIALNUMBER, serialNumber)
      }
      val subject = subjectBuilder.build()

      val csrBuilder = JcaPKCS10CertificationRequestBuilder(subject, publicKey)

      // Add extensions
      val extGen = ExtensionsGenerator()

      val keyUsage = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyAgreement)
      extGen.addExtension(Extension.keyUsage, true, keyUsage)

      val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth)
      extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage)

      val sanList = mutableListOf<GeneralName>()
      if (ipAddress != null && ipAddress.trimJava().isNotEmpty()) {
        sanList.add(GeneralName(GeneralName.iPAddress, ipAddress.trimJava()))
      }

      if (dnsName != null && dnsName.trimJava().isNotEmpty()) {
        for (dns in dnsName.split(",")) {
          val trimmedDns = dns.trimJava()
          if (trimmedDns.isNotEmpty()) {
            sanList.add(GeneralName(GeneralName.dNSName, trimmedDns))
          }
        }
      }

      if (phoneInfo != null && phoneInfo.trimJava().isNotEmpty()) {
        sanList.add(GeneralName(GeneralName.uniformResourceIdentifier, "phone:" + phoneInfo.trimJava()))
      }

      if (sanList.isNotEmpty()) {
        val subjectAltNames = GeneralNames(sanList.toTypedArray())
        extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames)
      }

      csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())

      currentStep = "CSR signing"
      val signatureAlgorithm = signatureAlgorithmFor(keystoreCurve)
      val signer: ContentSigner = if (useHardwareKey) {
        AndroidKeystoreContentSigner(privateKey, signatureAlgorithm)
      } else {
        JcaContentSignerBuilder(signatureAlgorithm).setProvider(FULL_BC_PROVIDER).build(privateKey)
      }

      val builtCsr = csrBuilder.build(signer)
      csr = builtCsr

      currentStep = "result serialization"
      val csrWriter = StringWriter()
      JcaPEMWriter(csrWriter).use { pemWriter -> pemWriter.writeObject(builtCsr) }

      val keystorePath = if (useHardwareKey) null else getKeystoreFile().absolutePath

      Log.d(MODULE_NAME, "CSR generated successfully (requested: " +
        (if (requestedHardwareKey) "hardware" else "software") +
        ", actual: " + (if (useHardwareKey) "hardware" else "software") + ")")

      return CSRGenerationResult(
        csr = csrWriter.toString(),
        privateKeyAlias = privateKeyAlias,
        publicKeyBase64 = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP),
        isHardwareBacked = useHardwareKey && isHardwareBacked(privateKeyAlias),
        useHardwareKey = useHardwareKey,
        hardwareKeyRequested = requestedHardwareKey,
        tlsCompatible = canUseHardwareKeysForTLS(),
        keystorePath = keystorePath,
      )
    } catch (e: CSRRejectedException) {
      throw e
    } catch (e: KeystoreLocationException) {
      // Keep the type. Storage failed, not key generation, and the rewrap below would flatten
      // that into a plain Exception whose message says "key generation failed" - misdirecting
      // whoever reads the log and stopping any caller from telling the two apart.
      throw e
    } catch (e: Exception) {
      // Provide better error context
      var errorContext = "CSR generation failed at step: $currentStep"
      if (keyPair == null && currentStep == "key generation") {
        errorContext += " (key generation failed)"
      } else if (keyPair != null && csr == null) {
        errorContext += " (CSR signing failed)"
      }
      throw Exception(errorContext + ": " + e.message, e)
    }
  }

  @Throws(Exception::class)
  private fun generateHardwareKeyPair(privateKeyAlias: String, keystoreCurve: String): KeyPair? {
    Log.d(MODULE_NAME, "Generating hardware-backed key pair")

    var hasStrongBox = false
    var useStrongBox = false

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

      if (BuildConfig.DEBUG) {
        Log.d(MODULE_NAME, "Device StrongBox support: $hasStrongBox")
      }
    }

    // Decide whether to use StrongBox or TEE
    if (hasStrongBox) {
      if (keystoreCurve == "secp256r1") {
        useStrongBox = true
        Log.d(MODULE_NAME, "Using StrongBox-backed key generation (P-256)")
      } else {
        Log.w(MODULE_NAME, "StrongBox only supports P-256. Requested curve: $keystoreCurve. Using TEE instead.")
      }
    } else {
      Log.d(MODULE_NAME, "Using hardware-backed (TEE) key generation")
    }

    val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

    // Add clarifying comment about purpose flags
    // Note: canUseHardwareKeysForTLS() guarantees Android 12+, but we check again
    // for defense-in-depth in case this method is called directly
    var purposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      purposes = purposes or KeyProperties.PURPOSE_AGREE_KEY
    }

    val specBuilder = KeyGenParameterSpec.Builder(privateKeyAlias, purposes)
      .setAlgorithmParameterSpec(ECGenParameterSpec(keystoreCurve))
      .setDigests(
        KeyProperties.DIGEST_SHA256,
        KeyProperties.DIGEST_SHA384,
        KeyProperties.DIGEST_SHA512)
      .setUserAuthenticationRequired(false)

    if (useStrongBox) {
      specBuilder.setIsStrongBoxBacked(true)
    }

    keyPairGenerator.initialize(specBuilder.build())

    try {
      val keyPair = keyPairGenerator.generateKeyPair()
      Log.d(MODULE_NAME, "Hardware key pair generated successfully" + (if (useStrongBox) " (StrongBox)" else " (TEE)"))
      return keyPair
    } catch (e: StrongBoxUnavailableException) {
      // StrongBox advertised but transiently unavailable - fall back to TEE once
      if (useStrongBox) {
        Log.w(MODULE_NAME, "StrongBox unavailable, falling back to TEE: " + e.message)
        specBuilder.setIsStrongBoxBacked(false)
        keyPairGenerator.initialize(specBuilder.build())
        try {
          val keyPair = keyPairGenerator.generateKeyPair()
          Log.d(MODULE_NAME, "Hardware key pair generated successfully (TEE fallback)")
          return keyPair
        } catch (retryException: Exception) {
          Log.e(MODULE_NAME, "TEE fallback also failed: " + retryException.message)
          throw Exception("Hardware key generation failed in both StrongBox and TEE. Error: " + retryException.message, retryException)
        }
      } else {
        // Not using StrongBox originally, so don't retry
        throw Exception("Hardware key generation failed: " + e.message, e)
      }
    } catch (e: Exception) {
      Log.e(MODULE_NAME, "Hardware key generation failed: " + e.message)
      throw Exception("Hardware key generation failed. Device may not support hardware-backed keys for curve " +
        keystoreCurve + ". Error: " + e.message, e)
    }
  }

  @Throws(Exception::class)
  private fun generateSoftwareKeyPair(privateKeyAlias: String, keystoreCurve: String): KeyPair? {
    Log.d(MODULE_NAME, "Generating software key pair")

    ensureBouncyCastleProvider()

    if (BuildConfig.DEBUG) {
      Log.d(MODULE_NAME, "Using full BouncyCastle provider version: " + FULL_BC_PROVIDER.version)
      Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.javaClass.name)
    }

    // Generate EC key pair
    val keyPairGenerator: KeyPairGenerator
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("EC", FULL_BC_PROVIDER)
      if (BuildConfig.DEBUG) {
        Log.d(MODULE_NAME, "EC algorithm supported, provider: " + keyPairGenerator.provider.name)
      }
    } catch (e: NoSuchAlgorithmException) {
      Log.e(MODULE_NAME, "EC algorithm NOT supported by BouncyCastle provider!", e)
      if (BuildConfig.DEBUG) {
        Log.e(MODULE_NAME, "BC Provider info: " + FULL_BC_PROVIDER.info)
        Log.e(MODULE_NAME, "Available algorithms in BC:")
        for (service in FULL_BC_PROVIDER.services) {
          if (service.type == "KeyPairGenerator") {
            Log.e(MODULE_NAME, "  - " + service.algorithm)
          }
        }
      }
      throw Exception("BouncyCastle provider does not support EC algorithm. Provider may be corrupted or stripped by ProGuard/R8.", e)
    }

    val ecSpec = ECGenParameterSpec(keystoreCurve)
    keyPairGenerator.initialize(ecSpec, SecureRandom())
    val keyPair = keyPairGenerator.generateKeyPair()
    Log.d(MODULE_NAME, "Software key pair generated successfully")

    // Thread-safe keystore file operations
    // Prevents race conditions when multiple threads call generateCSR simultaneously
    // All read-modify-write operations on the PKCS12 file must be atomic to prevent corruption
    synchronized(SOFTWARE_KEYSTORE_LOCK) {
      storeSoftwareKey(privateKeyAlias, keyPair, keystoreCurve)
    }

    return keyPair
  }

  @Throws(Exception::class)
  private fun storeSoftwareKey(privateKeyAlias: String, keyPair: KeyPair, keystoreCurve: String) {
    val softwareKeyStore = loadSoftwareKeyStore()

    val tempSubject = "CN=Temp-$privateKeyAlias"
    val selfSignedCert = createSelfSignedCertificate(keyPair, tempSubject, keystoreCurve)

    softwareKeyStore.setKeyEntry(
      privateKeyAlias,
      keyPair.private,
      KEYSTORE_PASSWORD,
      arrayOf<Certificate>(selfSignedCert),
    )

    saveSoftwareKeyStore(softwareKeyStore)
  }

  fun deleteKey(privateKeyAlias: String?, promise: Reply) {
    try {
      var deleted = false

      // Try hardware keystore first
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (keyStore.containsAlias(privateKeyAlias)) {
          keyStore.deleteEntry(privateKeyAlias)
          deleted = true
          Log.d(MODULE_NAME, "Deleted hardware key: $privateKeyAlias")
        }
      } catch (e: Exception) {
        // Continue to software keystore
      }

      // Synchronize software keystore access
      synchronized(SOFTWARE_KEYSTORE_LOCK) {
        try {
          val softwareKeyStore = loadSoftwareKeyStore()

          if (softwareKeyStore.containsAlias(privateKeyAlias)) {
            softwareKeyStore.deleteEntry(privateKeyAlias)
            saveSoftwareKeyStore(softwareKeyStore)
            deleted = true
            Log.d(MODULE_NAME, "Deleted software key: $privateKeyAlias")
          }
        } catch (e: KeystoreLocationException) {
          // A delete that could not even reach the keystore must not resolve true/false:
          // either answer tells the app the alias is clear when a software key may still
          // hold it. Rejecting stays correct when the hardware key above was already
          // deleted - the software key is the one that would collide later - so the
          // partial success is reported in the message rather than swallowed.
          if (!deleted) {
            throw e
          }
          throw KeystoreLocationException(
            "hardware key was deleted, but the software keystore was unreachable: " + e.message, e)
        } catch (e: Exception) {
          Log.w(MODULE_NAME, "Error accessing software keystore: " + e.message)
        }
      }

      promise.resolve(deleted)
    } catch (e: Exception) {
      Log.e(MODULE_NAME, "Failed to delete key", e)
      promise.reject("DELETE_KEY_ERROR", "Failed to delete key: " + e.message, e)
    }
  }

  fun getHardwareKeystoreCapabilities(promise: Reply) {
    try {
      val result = getHardwareKeystoreCapabilitiesInternal()

      val capabilities = HashMap<String, Any?>()
      capabilities["tlsCompatible"] = result.tlsCompatible
      capabilities["androidSdkVersion"] = result.androidSdkVersion
      capabilities["hasStrongBox"] = result.hasStrongBox
      capabilities["manufacturer"] = result.manufacturer
      capabilities["model"] = result.model
      capabilities["device"] = result.device

      promise.resolve(capabilities)
    } catch (e: Exception) {
      promise.reject("CAPABILITY_CHECK_ERROR", "Failed to check capabilities: " + e.message, e)
    }
  }

  /** Core capability-check logic, separated from [getHardwareKeystoreCapabilities] for tests. */
  fun getHardwareKeystoreCapabilitiesInternal(): HardwareCapabilities {
    var hasStrongBox = false
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }

    return HardwareCapabilities(
      tlsCompatible = canUseHardwareKeysForTLS(),
      androidSdkVersion = Build.VERSION.SDK_INT,
      hasStrongBox = hasStrongBox,
      manufacturer = Build.MANUFACTURER,
      model = Build.MODEL,
      device = Build.DEVICE,
    )
  }

  fun keyExists(privateKeyAlias: String?, promise: Reply) {
    try {
      // Check hardware keystore
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (keyStore.containsAlias(privateKeyAlias)) {
          promise.resolve(true)
          return
        }
      } catch (e: Exception) {
        // Continue to software keystore
      }

      // Synchronize software keystore access
      synchronized(SOFTWARE_KEYSTORE_LOCK) {
        try {
          val softwareKeyStore = loadSoftwareKeyStore()
          promise.resolve(softwareKeyStore.containsAlias(privateKeyAlias))
        } catch (e: KeystoreLocationException) {
          throw e // "storage is broken" must not be reported as "key does not exist"
        } catch (e: Exception) {
          // loadSoftwareKeyStore() handles corruption internally; unexpected errors return false
          Log.w(MODULE_NAME, "Error checking software keystore: " + e.message)
          promise.resolve(false)
        }
      }
    } catch (e: Exception) {
      promise.reject("KEY_EXISTS_ERROR", "Failed to check key existence: " + e.message, e)
    }
  }

  fun getPublicKey(privateKeyAlias: String?, promise: Reply) {
    try {
      // Try hardware keystore first
      try {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(privateKeyAlias)) {
          val entry = keyStore.getEntry(privateKeyAlias, null)
          if (entry is KeyStore.PrivateKeyEntry) {
            val publicKey = entry.certificate.publicKey
            promise.resolve(Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP))
            return
          }
        }
      } catch (e: Exception) {
        // Continue to software keystore
      }

      // Synchronize software keystore access
      synchronized(SOFTWARE_KEYSTORE_LOCK) {
        try {
          val softwareKeyStore = loadSoftwareKeyStore()

          if (softwareKeyStore.containsAlias(privateKeyAlias)) {
            val entry = softwareKeyStore.getEntry(
              privateKeyAlias,
              KeyStore.PasswordProtection(KEYSTORE_PASSWORD),
            )
            if (entry is KeyStore.PrivateKeyEntry) {
              val publicKey = entry.certificate.publicKey
              promise.resolve(Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP))
              return
            }
          }
        } catch (e: KeystoreLocationException) {
          throw e // "storage is broken" must not be reported as "key does not exist"
        } catch (e: Exception) {
          // loadSoftwareKeyStore() handles corruption internally, so what reaches here is a key that
          // is present but unreadable (e.g. UnrecoverableEntryException). KEY_NOT_FOUND would invite
          // the app to re-enrol over a key that still exists, so report it as a retrieval failure.
          Log.w(MODULE_NAME, "Error retrieving key from software keystore: " + e.message)
          promise.reject("GET_PUBLIC_KEY_ERROR", "Failed to read key with alias '$privateKeyAlias': " + e.message, e)
          return
        }
      }

      promise.reject("KEY_NOT_FOUND", "Key with alias '$privateKeyAlias' not found")
    } catch (e: Exception) {
      promise.reject("GET_PUBLIC_KEY_ERROR", "Failed to get public key: " + e.message, e)
    }
  }

  private fun isHardwareBacked(privateKeyAlias: String): Boolean {
    return try {
      val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
      keyStore.load(null)

      val entry = keyStore.getEntry(privateKeyAlias, null)
      if (entry is KeyStore.PrivateKeyEntry) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          val factory = KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
          val keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
          return keyInfo.isInsideSecureHardware
        }
        true
      } else {
        false
      }
    } catch (e: Exception) {
      false
    }
  }

  // Helper method to delete hardware key if it exists
  @Throws(Exception::class)
  private fun deleteHardwareKeyIfExists(privateKeyAlias: String) {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
    keyStore.load(null)
    if (keyStore.containsAlias(privateKeyAlias)) {
      keyStore.deleteEntry(privateKeyAlias)
      Log.d(MODULE_NAME, "Deleted stale hardware key: $privateKeyAlias")
    }
  }

  // Helper method to delete software key if it exists
  @Throws(Exception::class)
  private fun deleteSoftwareKeyIfExists(privateKeyAlias: String) {
    synchronized(SOFTWARE_KEYSTORE_LOCK) {
      try {
        val softwareKeyStore = loadSoftwareKeyStore()

        if (softwareKeyStore.containsAlias(privateKeyAlias)) {
          softwareKeyStore.deleteEntry(privateKeyAlias)
          saveSoftwareKeyStore(softwareKeyStore)
          Log.d(MODULE_NAME, "Deleted stale software key: $privateKeyAlias")
        }
      } catch (e: KeystoreLocationException) {
        // Same reason the three keystore-reading entry points rethrow: "storage is broken" must
        // not look like "no stale key here". This method exists to stop a stale software key
        // from colliding with a new hardware key under the same alias, and it cannot know
        // whether one is there if it never reached the keystore.
        throw e
      } catch (e: Exception) {
        // loadSoftwareKeyStore() handles corruption internally; log unexpected errors
        Log.w(MODULE_NAME, "Error deleting stale software key: " + e.message)
      }
    }
  }

  /**
   * Clean up old quarantined keystores to prevent unbounded accumulation.
   * Keeps only the most recent 3 for forensics.
   *
   * Recency is read from the filename, not from lastModified(). The quarantine name embeds a
   * fixed-width zero-padded "yyyyMMdd_HHmmssSSS" stamp after a constant prefix, so a descending
   * lexicographic sort is exactly a descending chronological sort - and unlike lastModified() it
   * does not degrade on filesystems that report modification times at one- or two-second
   * resolution, where the ranking of files quarantined within the same second would be arbitrary.
   *
   * @param directory The keystore_forensics directory containing the quarantined files
   * @param baseFileName The base filename (e.g., "software_keys.p12")
   * @param infix [CORRUPTED_INFIX] or [SUPERSEDED_INFIX]. The two are capped
   *        independently: they record different events, so a run of corruptions should not evict
   *        the record of a superseded key or vice versa.
   */
  private fun cleanupQuarantinedFiles(directory: File, baseFileName: String, infix: String) {
    try {
      // Find all quarantined files of this kind for this keystore
      val quarantined = directory.listFiles { _, name -> name.startsWith(baseFileName + infix) }

      if (quarantined == null || quarantined.size <= 3) {
        return // Nothing to clean up
      }

      // Sort by embedded timestamp, newest first
      quarantined.sortByDescending { it.name }

      // Delete all but the 3 most recent
      var deleted = 0
      for (i in 3 until quarantined.size) {
        if (quarantined[i].delete()) {
          deleted++
        }
      }

      if (deleted > 0) {
        Log.d(MODULE_NAME, "Cleaned up $deleted old quarantined keystore file(s)")
      }
    } catch (e: Exception) {
      // Non-critical operation - log but don't throw
      Log.w(MODULE_NAME, "Error cleaning up old corrupted files: " + e.message)
    }
  }

  companion object {
    /** Log tag. Kept as the pre-Expo module name so existing logcat filters keep working. */
    private const val MODULE_NAME = "CSRModule"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /** Visible for the same reason as [CORRUPTED_INFIX]. */
    const val SOFTWARE_KEYSTORE_FILE = "software_keys.p12"
    private const val TEMP_SUFFIX = ".tmp"

    /**
     * Filename infix marking a quarantined copy of a corrupt keystore. The full name is
     * "<keystore>.corrupted.<yyyyMMdd_HHmmssSSS>", which sorts lexicographically in chronological
     * order - see [cleanupQuarantinedFiles].
     *
     * Visible so tests can stage and assert on quarantine filenames through the same constant
     * production uses, instead of a copy that can drift out of step with it.
     */
    const val CORRUPTED_INFIX = ".corrupted."

    /**
     * Filename infix marking a keystore that lost a newer-copy comparison during migration - see
     * [quarantineSupersededKeystore]. Same timestamp format and retention rules as
     * [CORRUPTED_INFIX], but a distinct infix so a forensic reader can tell "this keystore
     * would not parse" from "a newer copy of this keystore turned up in the legacy location".
     */
    const val SUPERSEDED_INFIX = ".superseded."

    /**
     * Subdirectory for quarantined corrupt keystore files. Keeps timestamped
     * ".corrupted.<timestamp>" copies grouped in one place instead of scattered alongside the live
     * keystore. It lives inside the no-backup directory (see [getKeystoreDir]), so
     * quarantined copies of the private key are excluded from backups on the same terms as the
     * live keystore.
     *
     * Releases before this directory existed wrote quarantined copies flat into getFilesDir()
     * alongside the live keystore; [migrateLegacyKeystoreIfNeeded] relocates those too.
     */
    private const val CORRUPTED_KEYSTORE_DIR = "keystore_forensics"

    /**
     * PKCS12 keystore password - intentionally empty for app-private storage.
     *
     * SECURITY RATIONALE (for code reviewers):
     *
     * 1. **Defense in depth through OS-level protection:**
     *    - File stored in app-private no-backup directory (/data/data/com.app/no_backup/)
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
     *    - THREAT: Backup extraction → key lives in getNoBackupFilesDir(), which Android never backs up
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
    private val KEYSTORE_PASSWORD: CharArray = "".toCharArray()

    // Align defaults with documentation (Generac-specific values)
    private const val DEFAULT_COUNTRY = "US"
    private const val DEFAULT_STATE = "Wisconsin"
    private const val DEFAULT_LOCALITY = "Waukesha"
    private const val DEFAULT_ORGANIZATION = "Generac Power Systems"
    private const val DEFAULT_ORGANIZATIONAL_UNIT = "Field Pro"
    private const val DEFAULT_IP_ADDRESS = "10.10.10.10"
    private const val DEFAULT_ECC_CURVE = "secp384r1"

    // Keep a direct reference to our full BouncyCastle provider instance
    // to avoid getting the system's stripped-down BC provider
    private val FULL_BC_PROVIDER: Provider = BouncyCastleProvider()

    // Thread-safe provider initialization
    @Volatile
    private var providerInitialized = false
    private val providerLock = Any()

    // Race condition protection for software keystore file access
    private val SOFTWARE_KEYSTORE_LOCK = Any()

    // Simplified BC provider initialization logic
    private fun ensureBouncyCastleProvider() {
      // Fast path - if already initialized, return immediately
      if (providerInitialized) {
        return
      }

      // Slow path - synchronize and initialize
      synchronized(providerLock) {
        // Double-check after acquiring lock
        if (providerInitialized) {
          return
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
        Security.removeProvider("BC")

        // Insert our full provider at position 1 (highest priority)
        Security.insertProviderAt(FULL_BC_PROVIDER, 1)

        providerInitialized = true

        // Only log details in debug builds
        if (BuildConfig.DEBUG) {
          Log.d(MODULE_NAME, "BouncyCastle provider registered successfully")
          Log.d(MODULE_NAME, "BC Provider version: " + FULL_BC_PROVIDER.version)
          Log.d(MODULE_NAME, "BC Provider class: " + FULL_BC_PROVIDER.javaClass.name)

          Log.d(MODULE_NAME, "All registered security providers:")
          for (provider in Security.getProviders()) {
            Log.d(MODULE_NAME, "  - " + provider.name + " v" + provider.version +
              " (" + provider.javaClass.name + ")")
          }
        } else {
          Log.i(MODULE_NAME, "BouncyCastle provider registered (v" + FULL_BC_PROVIDER.version + ")")
        }
      }
    }

    /**
     * Reads an optional string param. A key that is present keeps its value even when that value is
     * null, and a non-string value throws ClassCastException - both match what ReadableMap's
     * `hasKey ? getString : default` did before the Expo migration, so malformed input still
     * fails in the same step with the same code. JS `undefined` values are stripped in
     * src/index.ts before they get here, as the old bridge did, so they still read as absent.
     */
    private fun optString(params: Map<String, *>, key: String, fallback: String?): String? {
      return if (params.containsKey(key)) params[key] as String? else fallback
    }

    /** Boolean counterpart of [optString]; a present null throws, as getBoolean did. */
    private fun optBoolean(params: Map<String, *>, key: String, fallback: Boolean): Boolean {
      return if (params.containsKey(key)) params[key] as Boolean else fallback
    }

    /** Timestamp for a quarantine filename; see [CORRUPTED_INFIX] for the format contract. */
    private fun quarantineTimestamp(): String {
      return SimpleDateFormat("yyyyMMdd_HHmmssSSS", Locale.US).format(Date())
    }
  }
}
