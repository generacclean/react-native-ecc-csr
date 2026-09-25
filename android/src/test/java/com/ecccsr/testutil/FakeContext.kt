package com.ecccsr.testutil

import android.content.Context
import android.content.ContextWrapper
import java.io.File

/**
 * Context for unit tests. Delegates everything (getFilesDir, getPackageManager, etc.) to the real
 * Robolectric application context, with hooks to make no-backup storage unavailable or unwritable.
 */
class FakeContext(base: Context) : ContextWrapper(base) {

  /**
   * Simulate a platform that returns no no-backup directory. Lets tests assert that CSRCore
   * refuses to fall back to an unprotected path rather than silently writing the private key
   * relative to the process working directory.
   */
  var noBackupFilesDirUnavailable = false

  /**
   * Point CSRCore at a different no-backup directory.
   *
   * Exists so a test can make writes into that directory fail deterministically - pass a path
   * whose parent is a regular file and every create/rename under it fails on any filesystem and
   * for any user, including root. The alternative, chmod-ing the real directory, is a silent no-op
   * as root and therefore skips rather than asserts on containerised CI runners.
   *
   * Set to null to restore the real directory.
   */
  var noBackupFilesDirOverride: File? = null

  override fun getNoBackupFilesDir(): File? =
    if (noBackupFilesDirUnavailable) null else noBackupFilesDirOverride ?: super.getNoBackupFilesDir()
}
