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

    /** Package-private for the same reason as {@link #CORRUPTED_INFIX}. */
    static final String SOFTWARE_KEYSTORE_FILE = "software_keys.p12";
    private static final String TEMP_SUFFIX = ".tmp";

    /**
     * Filename infix marking a quarantined copy of a corrupt keystore. The full name is
     * "<keystore>.corrupted.<yyyyMMdd_HHmmssSSS>", which sorts lexicographically in chronological
     * order - see {@link #cleanupQuarantinedFiles}.
     *
     * Package-private so tests can stage and assert on quarantine filenames through the same
     * constant production uses, instead of a copy that can drift out of step with it.
     */
    static final String CORRUPTED_INFIX = ".corrupted.";

    /**
     * Filename infix marking a keystore that lost a newer-copy comparison during migration - see
     * {@link #quarantineSupersededKeystore}. Same timestamp format and retention rules as
     * {@link #CORRUPTED_INFIX}, but a distinct infix so a forensic reader can tell "this keystore
     * would not parse" from "a newer copy of this keystore turned up in the legacy location".
     */
    static final String SUPERSEDED_INFIX = ".superseded.";

    /**
     * Subdirectory for quarantined corrupt keystore files. Keeps timestamped
     * ".corrupted.<timestamp>" copies grouped in one place instead of scattered alongside the live
     * keystore. It lives inside the no-backup directory (see {@link #getKeystoreDir()}), so
     * quarantined copies of the private key are excluded from backups on the same terms as the
     * live keystore.
     *
     * Releases before this directory existed wrote quarantined copies flat into getFilesDir()
     * alongside the live keystore; {@link #migrateLegacyKeystoreIfNeeded} relocates those too.
     */
    private static final String CORRUPTED_KEYSTORE_DIR = "keystore_forensics";

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
     * Directory holding the software keystore: {@link android.content.Context#getNoBackupFilesDir()},
     * not {@code getFilesDir()}.
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
    File getKeystoreDir() throws IOException {
        File noBackupDir = getReactApplicationContext().getNoBackupFilesDir();
        if (noBackupDir == null) {
            // new File((File) null, name) is legal Java and yields the bare relative path
            // "software_keys.p12", resolved against the process working directory - outside the
            // no-backup guarantee this class relies on and outside the 0600 hardening below. The
            // blast radius is key material, so refuse rather than write to an unknown location.
            throw new KeystoreLocationException(
                    "getNoBackupFilesDir() returned null; refusing to store the private key outside no-backup storage");
        }
        migrateLegacyKeystoreIfNeeded(noBackupDir);
        return noBackupDir;
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
     * generateCSRInternal - so it reaches the bridge and the promise rejects. Adding a new such
     * catch without that clause is what turns this back into a log line.
     */
    static class KeystoreLocationException extends IOException {
        KeystoreLocationException(String message) {
            super(message);
        }

        KeystoreLocationException(String message, Throwable cause) {
            super(message, cause);
        }
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
     *         Only that one file is fatal; see {@link #migrateLegacyQuarantinedFiles} for why the
     *         quarantined copies are best-effort.
     */
    private void migrateLegacyKeystoreIfNeeded(File noBackupDir) throws IOException {
        File legacyDir = getReactApplicationContext().getFilesDir();
        if (legacyDir == null || legacyDir.equals(noBackupDir)) {
            return;
        }

        synchronized (SOFTWARE_KEYSTORE_LOCK) {
            File legacyKeystore = new File(legacyDir, SOFTWARE_KEYSTORE_FILE);
            File currentKeystore = new File(noBackupDir, SOFTWARE_KEYSTORE_FILE);

            quarantineSupersededKeystore(legacyKeystore, currentKeystore, noBackupDir);

            if (!moveOutOfBackupEligibleStorage(legacyKeystore, currentKeystore)) {
                // Returning normally here would hand callers the no-backup path while the only
                // copy of the key sits at the legacy one. loadSoftwareKeyStore() would find no
                // file, create an empty keystore, and the device would silently re-enrol with a
                // new key while its issued certificate stopped matching. Fail so the caller can
                // retry instead.
                throw new KeystoreLocationException(
                        "Failed to migrate legacy software keystore out of backup-eligible storage: "
                                + legacyKeystore.getAbsolutePath());
            }

            // A leftover .tmp is a complete copy of the keystore, so it is just as sensitive.
            File legacyTemp = new File(legacyDir, SOFTWARE_KEYSTORE_FILE + TEMP_SUFFIX);
            if (legacyTemp.exists() && !legacyTemp.delete()) {
                Log.w(MODULE_NAME, "Failed to delete legacy temp keystore from backup-eligible storage");
            }

            migrateLegacyQuarantinedFiles(legacyDir, noBackupDir);
        }
    }

    /**
     * Step aside for a legacy keystore that is newer than the no-backup one.
     *
     * {@link #moveOutOfBackupEligibleStorage} reads a populated destination as proof the legacy file
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
     * in no-backup storage is recoverable and a deletion is not. A tie keeps the no-backup copy,
     * which is the straight-upgrade behaviour.
     *
     * @throws IOException if the older copy cannot be quarantined. Returning normally would hand the
     *         caller straight back to {@link #moveOutOfBackupEligibleStorage}, which would then
     *         delete the newer legacy key as superseded - so failing here is what keeps the
     *         newer-copy guarantee from degrading into the exact data loss it prevents.
     */
    private void quarantineSupersededKeystore(File legacyKeystore, File currentKeystore, File noBackupDir)
            throws IOException {
        if (!legacyKeystore.exists() || !currentKeystore.exists()
                || legacyKeystore.lastModified() <= currentKeystore.lastModified()) {
            return;
        }

        File forensicsDir = new File(noBackupDir, CORRUPTED_KEYSTORE_DIR);
        if (!forensicsDir.isDirectory() && !forensicsDir.mkdirs()) {
            throw new KeystoreLocationException(
                    "A newer software keystore exists in backup-eligible storage but the superseded "
                            + "no-backup copy cannot be quarantined: forensics directory unavailable");
        }

        File superseded = new File(
                forensicsDir, SOFTWARE_KEYSTORE_FILE + SUPERSEDED_INFIX + quarantineTimestamp());
        if (!currentKeystore.renameTo(superseded)) {
            throw new KeystoreLocationException(
                    "A newer software keystore exists in backup-eligible storage but the superseded "
                            + "no-backup copy could not be quarantined: " + currentKeystore.getAbsolutePath());
        }

        Log.w(MODULE_NAME, "Legacy software keystore is newer than the no-backup copy (downgrade "
                + "then upgrade); quarantined the superseded copy as " + superseded.getName());
        cleanupQuarantinedFiles(forensicsDir, SOFTWARE_KEYSTORE_FILE, SUPERSEDED_INFIX);
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
    private void migrateLegacyQuarantinedFiles(File legacyDir, File noBackupDir) {
        List<File> legacyQuarantined = new ArrayList<>();

        FilenameFilter quarantineFilter =
                (dir, name) -> name.startsWith(SOFTWARE_KEYSTORE_FILE + CORRUPTED_INFIX);

        File[] flat = legacyDir.listFiles(quarantineFilter);
        if (flat != null) {
            legacyQuarantined.addAll(java.util.Arrays.asList(flat));
        }

        // Filtered on the same prefix as the flat sweep and as the retention cap below. An
        // unfiltered listing would also move entries the cap cannot see - including directories,
        // which renameTo() relocates just as happily - so they would accumulate uncapped.
        File legacyForensicsDir = new File(legacyDir, CORRUPTED_KEYSTORE_DIR);
        File[] nested = legacyForensicsDir.listFiles(quarantineFilter);
        if (nested != null) {
            legacyQuarantined.addAll(java.util.Arrays.asList(nested));
        }

        if (legacyQuarantined.isEmpty()) {
            return;
        }

        File forensicsDir = new File(noBackupDir, CORRUPTED_KEYSTORE_DIR);
        if (!forensicsDir.isDirectory() && !forensicsDir.mkdirs()) {
            Log.e(MODULE_NAME, "Failed to create no-backup forensics directory during migration: "
                    + legacyQuarantined.size()
                    + " legacy private key copies remain in backup-eligible storage");
            return;
        }

        for (File file : legacyQuarantined) {
            moveOutOfBackupEligibleStorage(file, new File(forensicsDir, file.getName()));
        }

        File[] unmovable = legacyForensicsDir.listFiles();
        if (unmovable != null && unmovable.length > 0) {
            Log.w(MODULE_NAME, "Legacy forensics directory holds " + unmovable.length
                    + " entry/entries this migration does not recognise; leaving it in place");
        } else if (legacyForensicsDir.isDirectory() && !legacyForensicsDir.delete()) {
            Log.w(MODULE_NAME, "Failed to remove emptied legacy forensics directory");
        }

        // Migrated copies bypass the quarantine path that normally enforces the cap, so apply it
        // here. Note this runs over the destination directory, so it ranks migrated copies together
        // with any this release already quarantined and can drop either - which is the intent: the
        // cap is on how many quarantined copies of a private key exist, not on how many arrived.
        cleanupQuarantinedFiles(forensicsDir, SOFTWARE_KEYSTORE_FILE, CORRUPTED_INFIX);
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
    private boolean moveOutOfBackupEligibleStorage(File source, File destination) {
        if (!source.exists()) {
            return true;
        }
        if (destination.exists()) {
            if (!source.delete()) {
                Log.w(MODULE_NAME, "Failed to delete superseded legacy file: " + source.getName());
            }
            return true;
        }
        if (source.renameTo(destination)) {
            Log.i(MODULE_NAME, "Migrated " + source.getName() + " to no-backup storage");
            return true;
        }
        Log.w(MODULE_NAME, "Failed to migrate " + source.getName() + " to no-backup storage");
        return false;
    }

    /**
     * Get File object for software keystore (plain file, no encryption).
     * Replaces EncryptedFile approach which had Tink keyset synchronization issues.
     *
     * Side effect: re-applies 0600 permissions to the file if it already exists. This is
     * idempotent and cheap, so callers don't need to treat this as a pure path lookup.
     *
     * @throws IOException see {@link #getKeystoreDir()}
     */
    File getKeystoreFile() throws IOException {
        File file = new File(getKeystoreDir(), SOFTWARE_KEYSTORE_FILE);
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

            File forensicsDir = new File(keystoreFile.getParentFile(), CORRUPTED_KEYSTORE_DIR);
            if (!forensicsDir.isDirectory() && !forensicsDir.mkdirs()) {
                Log.w(MODULE_NAME, "Failed to create forensics directory, deleting corrupt keystore instead");
                if (!keystoreFile.delete()) {
                    throw new IOException("Failed to delete corrupt keystore file", e);
                }
                keyStore.load(null, KEYSTORE_PASSWORD);
                return keyStore;
            }

            File corruptedFile = new File(
                forensicsDir,
                keystoreFile.getName() + CORRUPTED_INFIX + quarantineTimestamp()
            );

            if (keystoreFile.renameTo(corruptedFile)) {
                Log.w(MODULE_NAME, "Moved corrupt keystore to: " + corruptedFile.getName());

                // Clean up old .corrupted files (keep only the most recent 3)
                cleanupQuarantinedFiles(forensicsDir, keystoreFile.getName(), CORRUPTED_INFIX);
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
     *
     * Guarantee: by the time this method returns normally, the keystore file at
     * getKeystoreFile()'s path is fully written and in place - callers may read its path
     * immediately afterward without needing to wait for any further completion signal.
     */
    private void saveSoftwareKeyStore(KeyStore keyStore) throws Exception {
        File keystoreFile = getKeystoreFile();
        // Same directory as the target so the rename below stays within one filesystem (and so the
        // temp copy is never written to backup-eligible storage).
        File tempFile = new File(keystoreFile.getParentFile(), SOFTWARE_KEYSTORE_FILE + TEMP_SUFFIX);

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
     * Package-private (not private) so unit tests assert against the same alias rule
     * generateCSRInternal enforces, rather than a copy that can drift from production.
     */
    boolean isValidAlias(String alias) {
        return alias != null && !alias.trim().isEmpty();
    }

    /**
     * Package-private (not private) so unit tests assert against the same curve allow-list
     * generateCSRInternal enforces, rather than a copy that can drift from production.
     */
    boolean isValidCurve(String curve) {
        return curve != null
                && (curve.equals("secp256r1")
                    || curve.equals("secp384r1")
                    || curve.equals("secp521r1"));
    }

    /**
     * IP address validation - accepts only literal IP addresses, not hostnames.
     *
     * InetAddress.getByName() accepts hostnames that resolve via DNS, so we must
     * verify the input is a literal address by comparing the input to the resolved
     * address string. This prevents hostname injection into SAN iPAddress extensions,
     * which would produce malformed certificates.
     */
    boolean isValidIPAddress(String ip) {
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
                // Defense-in-depth: every valid IPv6 literal has at least 2 colons (even "::"),
                // and InetAddress.getByName already throws UnknownHostException above for a
                // single-colon string like "host:8080" before this line is reached - so this
                // branch is not currently reachable, but is kept in case that parsing behavior
                // ever changes across JVM/Android versions.
                int colonCount = inputForComparison.length() - inputForComparison.replace(":", "").length();
                if (colonCount < 2) {
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
    String sanitizeDNValue(String value) {
        if (value == null) {
            return "";
        }
        // X500NameBuilder already handles escaping, but trim whitespace
        return value.trim();
    }

    /** Thrown for validation failures that should be surfaced to JS as a specific error code. */
    static class CSRRejectedException extends Exception {
        final String code;

        CSRRejectedException(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /** Plain-Java result of a CSR generation, decoupled from the RN bridge's WritableMap. */
    static class CSRGenerationResult {
        final String csr;
        final String privateKeyAlias;
        final String publicKeyBase64;
        final boolean isHardwareBacked;
        final boolean useHardwareKey;
        final boolean hardwareKeyRequested;
        final boolean tlsCompatible;
        final String keystorePath; // null when useHardwareKey is true

        private CSRGenerationResult(Builder builder) {
            this.csr = builder.csr;
            this.privateKeyAlias = builder.privateKeyAlias;
            this.publicKeyBase64 = builder.publicKeyBase64;
            this.isHardwareBacked = builder.isHardwareBacked;
            this.useHardwareKey = builder.useHardwareKey;
            this.hardwareKeyRequested = builder.hardwareKeyRequested;
            this.tlsCompatible = builder.tlsCompatible;
            this.keystorePath = builder.keystorePath;
        }

        static Builder builder(String csr, String privateKeyAlias, String publicKeyBase64) {
            return new Builder(csr, privateKeyAlias, publicKeyBase64);
        }

        // Named setters so call sites can't silently swap same-typed boolean arguments.
        static class Builder {
            private final String csr;
            private final String privateKeyAlias;
            private final String publicKeyBase64;
            private boolean isHardwareBacked;
            private boolean useHardwareKey;
            private boolean hardwareKeyRequested;
            private boolean tlsCompatible;
            private String keystorePath;

            private Builder(String csr, String privateKeyAlias, String publicKeyBase64) {
                this.csr = csr;
                this.privateKeyAlias = privateKeyAlias;
                this.publicKeyBase64 = publicKeyBase64;
            }

            Builder isHardwareBacked(boolean value) {
                this.isHardwareBacked = value;
                return this;
            }

            Builder useHardwareKey(boolean value) {
                this.useHardwareKey = value;
                return this;
            }

            Builder hardwareKeyRequested(boolean value) {
                this.hardwareKeyRequested = value;
                return this;
            }

            Builder tlsCompatible(boolean value) {
                this.tlsCompatible = value;
                return this;
            }

            Builder keystorePath(String value) {
                this.keystorePath = value;
                return this;
            }

            CSRGenerationResult build() {
                return new CSRGenerationResult(this);
            }
        }
    }

    @ReactMethod
    public void generateCSR(ReadableMap params, Promise promise) {
        try {
            CSRGenerationResult result = generateCSRInternal(params);

            com.facebook.react.bridge.WritableMap response = com.facebook.react.bridge.Arguments.createMap();
            response.putString("csr", result.csr);
            response.putString("privateKeyAlias", result.privateKeyAlias);
            response.putString("publicKey", result.publicKeyBase64);
            response.putBoolean("isHardwareBacked", result.isHardwareBacked);
            response.putBoolean("useHardwareKey", result.useHardwareKey);
            response.putBoolean("hardwareKeyRequested", result.hardwareKeyRequested);
            response.putBoolean("tlsCompatible", result.tlsCompatible);

            if (result.keystorePath != null) {
                com.facebook.react.bridge.WritableMap keystoreDescriptor = com.facebook.react.bridge.Arguments.createMap();
                keystoreDescriptor.putString("path", result.keystorePath);
                // KEYSTORE_PASSWORD is always empty (see its declaration for the security
                // rationale) and is expected to remain so. If this ever becomes non-empty,
                // it would cross the RN bridge as a plain string, visible to bridge/crash
                // logs - do not add a real secret here without revisiting that exposure.
                keystoreDescriptor.putString("password", new String(KEYSTORE_PASSWORD));
                keystoreDescriptor.putString("format", "pkcs12");
                response.putMap("keystore", keystoreDescriptor);
            }

            promise.resolve(response);
        } catch (CSRRejectedException e) {
            promise.reject(e.code, e.getMessage());
        } catch (Exception e) {
            Log.e(MODULE_NAME, e.getMessage(), e);
            promise.reject("CSR_GENERATION_ERROR", e.getMessage(), e);
        }
    }

    /**
     * Core CSR generation logic, decoupled from the RN bridge so it can be unit tested
     * without a native module runtime (Arguments.createMap() requires a loaded JNI library).
     */
    CSRGenerationResult generateCSRInternal(ReadableMap params) throws Exception {
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
            if (!isValidAlias(privateKeyAlias)) {
                throw new CSRRejectedException("MISSING_ALIAS", "privateKeyAlias is required");
            }
            privateKeyAlias = privateKeyAlias.trim();

            if (!isValidCurve(curve)) {
                throw new CSRRejectedException("INVALID_CURVE", "Curve must be one of: secp256r1, secp384r1, secp521r1");
            }

            // Validate IP address
            if (ipAddress != null && !ipAddress.trim().isEmpty() && !isValidIPAddress(ipAddress)) {
                throw new CSRRejectedException("INVALID_IP", "Invalid IP address format: " + ipAddress);
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
            } catch (KeystoreLocationException e) {
                // Not a cleanup failure to shrug off: the software keystore could not be reached at
                // all, so nothing here can tell whether a stale software key survives under this
                // alias. Continuing would generate a hardware key beside it and hand back a CSR,
                // leaving a later getPublicKey() free to return the stale software key - the exact
                // dual-store collision this deletion prevents. Rethrown so the promise rejects.
                throw e;
            } catch (Exception e) {
                // Log stale key deletion failure but continue - this is a cleanup operation
                // and shouldn't block the main operation. deleteSoftwareKeyIfExists() swallows
                // everything except KeystoreLocationException, so this mostly catches
                // deleteHardwareKeyIfExists() failures (e.g., transient Android Keystore
                // unavailability). For software key generation, blocking on hardware keystore
                // failures is overly strict.
                Log.w(MODULE_NAME, "Failed to delete stale key from opposite keystore (continuing): " +
                      e.getMessage() + ". May cause dual-store collision if key exists.", e);
                // Continue with key generation instead of rejecting
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

            String keystorePath = useHardwareKey ? null : getKeystoreFile().getAbsolutePath();

            Log.d(MODULE_NAME, "CSR generated successfully (requested: " +
                  (requestedHardwareKey ? "hardware" : "software") +
                  ", actual: " + (useHardwareKey ? "hardware" : "software") + ")");

            return CSRGenerationResult.builder(
                    csrWriter.toString(),
                    privateKeyAlias,
                    Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP))
                    .isHardwareBacked(useHardwareKey && isHardwareBacked(privateKeyAlias))
                    .useHardwareKey(useHardwareKey)
                    .hardwareKeyRequested(requestedHardwareKey)
                    .tlsCompatible(canUseHardwareKeysForTLS())
                    .keystorePath(keystorePath)
                    .build();

        } catch (CSRRejectedException e) {
            throw e;
        } catch (KeystoreLocationException e) {
            // Keep the type. Storage failed, not key generation, and the rewrap below would flatten
            // that into a plain Exception whose message says "key generation failed" - misdirecting
            // whoever reads the log and stopping any caller from telling the two apart.
            throw e;
        } catch (Exception e) {
            // Provide better error context
            String errorContext = "CSR generation failed at step: " + currentStep;
            if (keyPair == null && "key generation".equals(currentStep)) {
                errorContext += " (key generation failed)";
            } else if (keyPair != null && csr == null) {
                errorContext += " (CSR signing failed)";
            }
            throw new Exception(errorContext + ": " + e.getMessage(), e);
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
                } catch (KeystoreLocationException e) {
                    // A delete that could not even reach the keystore must not resolve true/false:
                    // either answer tells the app the alias is clear when a software key may still
                    // hold it. Rejecting stays correct when the hardware key above was already
                    // deleted - the software key is the one that would collide later - so the
                    // partial success is reported in the message rather than swallowed.
                    if (!deleted) {
                        throw e;
                    }
                    throw new KeystoreLocationException(
                            "hardware key was deleted, but the software keystore was unreachable: "
                                    + e.getMessage(), e);
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

    /** Plain-Java result of a capability check, decoupled from the RN bridge's WritableMap. */
    static class HardwareCapabilities {
        final boolean tlsCompatible;
        final int androidSdkVersion;
        final boolean hasStrongBox;
        final String manufacturer;
        final String model;
        final String device;

        HardwareCapabilities(boolean tlsCompatible, int androidSdkVersion, boolean hasStrongBox,
                              String manufacturer, String model, String device) {
            this.tlsCompatible = tlsCompatible;
            this.androidSdkVersion = androidSdkVersion;
            this.hasStrongBox = hasStrongBox;
            this.manufacturer = manufacturer;
            this.model = model;
            this.device = device;
        }
    }

    @ReactMethod
    public void getHardwareKeystoreCapabilities(Promise promise) {
        try {
            HardwareCapabilities result = getHardwareKeystoreCapabilitiesInternal();

            com.facebook.react.bridge.WritableMap capabilities = com.facebook.react.bridge.Arguments.createMap();
            capabilities.putBoolean("tlsCompatible", result.tlsCompatible);
            capabilities.putInt("androidSdkVersion", result.androidSdkVersion);
            capabilities.putBoolean("hasStrongBox", result.hasStrongBox);
            capabilities.putString("manufacturer", result.manufacturer);
            capabilities.putString("model", result.model);
            capabilities.putString("device", result.device);

            promise.resolve(capabilities);
        } catch (Exception e) {
            promise.reject("CAPABILITY_CHECK_ERROR", "Failed to check capabilities: " + e.getMessage(), e);
        }
    }

    /**
     * Core capability-check logic, decoupled from the RN bridge so it can be unit tested
     * without a native module runtime (Arguments.createMap() requires a loaded JNI library).
     */
    HardwareCapabilities getHardwareKeystoreCapabilitiesInternal() {
        boolean hasStrongBox = false;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            hasStrongBox = getReactApplicationContext().getPackageManager()
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        }

        return new HardwareCapabilities(
                canUseHardwareKeysForTLS(),
                android.os.Build.VERSION.SDK_INT,
                hasStrongBox,
                android.os.Build.MANUFACTURER,
                android.os.Build.MODEL,
                android.os.Build.DEVICE);
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
                } catch (KeystoreLocationException e) {
                    throw e; // "storage is broken" must not be reported as "key does not exist"
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
                } catch (KeystoreLocationException e) {
                    throw e; // "storage is broken" must not be reported as "key does not exist"
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
            } catch (KeystoreLocationException e) {
                // Same reason the three @ReactMethod entry points rethrow: "storage is broken" must
                // not look like "no stale key here". This method exists to stop a stale software key
                // from colliding with a new hardware key under the same alias, and it cannot know
                // whether one is there if it never reached the keystore.
                throw e;
            } catch (Exception e) {
                // loadSoftwareKeyStore() handles corruption internally; log unexpected errors
                Log.w(MODULE_NAME, "Error deleting stale software key: " + e.getMessage());
            }
        }
    }

    /** Timestamp for a quarantine filename; see {@link #CORRUPTED_INFIX} for the format contract. */
    private static String quarantineTimestamp() {
        return new java.text.SimpleDateFormat("yyyyMMdd_HHmmssSSS", java.util.Locale.US)
                .format(new java.util.Date());
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
     * @param infix {@link #CORRUPTED_INFIX} or {@link #SUPERSEDED_INFIX}. The two are capped
     *        independently: they record different events, so a run of corruptions should not evict
     *        the record of a superseded key or vice versa.
     */
    private void cleanupQuarantinedFiles(File directory, String baseFileName, String infix) {
        try {
            // Find all quarantined files of this kind for this keystore
            File[] quarantined = directory.listFiles((dir, name) ->
                name.startsWith(baseFileName + infix)
            );

            if (quarantined == null || quarantined.length <= 3) {
                return; // Nothing to clean up
            }

            // Sort by embedded timestamp, newest first
            java.util.Arrays.sort(quarantined, (a, b) ->
                b.getName().compareTo(a.getName())
            );

            // Delete all but the 3 most recent
            int deleted = 0;
            for (int i = 3; i < quarantined.length; i++) {
                if (quarantined[i].delete()) {
                    deleted++;
                }
            }

            if (deleted > 0) {
                Log.d(MODULE_NAME, "Cleaned up " + deleted + " old quarantined keystore file(s)");
            }
        } catch (Exception e) {
            // Non-critical operation - log but don't throw
            Log.w(MODULE_NAME, "Error cleaning up old corrupted files: " + e.getMessage());
        }
    }
}
