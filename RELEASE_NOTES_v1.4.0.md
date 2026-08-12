# Release Notes v1.4.0

**Release Date:** August 12, 2026
**Ships with:** react-native-mqtt-mtls 1.4.0+ (required — see Upgrade Checklist)

---

## 🎯 Overview

Version 1.4.0 is about one thing: making the software private key genuinely un-backed-up, and
making every failure to guarantee that **loud**. The key file moves from `files/` to
`Context.getNoBackupFilesDir()`, the backup-exclusion XML files this library used to ship are
removed, and the four public methods that touch the software keystore now reject instead of
answering "no key here" when storage cannot be reached.

Existing installs migrate automatically on first keystore access. No app code changes are
required, but if your manifest or Expo config references this package's `@xml/backup_rules` or
`@xml/data_extraction_rules`, you **must** remove those references — see Breaking Changes.

---

## 💥 Breaking Changes

### 1. `backup_rules.xml` and `data_extraction_rules.xml` are removed

The v1.2.0/v1.3.0 approach asked the consuming app to point
`android:fullBackupContent` / `android:dataExtractionRules` at resources shipped by this library.
That could not be made reliable: each attribute accepts exactly **one** resource reference and
nothing merges them, so any other dependency that claimed either attribute (`expo-secure-store`,
for example) silently deactivated this module's exclusions — with no build error and no runtime
warning.

**Action required:** delete any manifest attribute or config-plugin entry referencing
`@xml/backup_rules` or `@xml/data_extraction_rules` from this package. Both resources are gone, so
a stale reference fails resource resolution at build time. Do not replace them with anything;
`no_backup/` is excluded by the OS unconditionally, regardless of `android:allowBackup`.

### 2. The software keystore path changed

`files/software_keys.p12` → `no_backup/software_keys.p12`.

If your app persists the `keystorePath` returned by `generateCSR`, re-read it after upgrading
rather than trusting a cached value.

### 3. Storage failures now reject instead of resolving

Previously, a software keystore that could not be reached was indistinguishable from a keystore
with no matching alias. Both produced `false` / `KEY_NOT_FOUND`, which invites the caller to
re-enrol — generating a *second* key while the first one is still on disk and still the one the
issued certificate matches.

| Method | Before | Now |
| --- | --- | --- |
| `keyExists` | resolves `false` | rejects `KEY_EXISTS_ERROR` |
| `getPublicKey` | rejects `KEY_NOT_FOUND` | rejects `GET_PUBLIC_KEY_ERROR` |
| `deleteKey` | resolves `false` | rejects `DELETE_KEY_ERROR` |
| `generateCSR` | generated a key anyway | rejects `CSR_GENERATION_ERROR` |

"Cannot be reached" means the platform returned no no-backup directory, the directory could not be
created, or a pending legacy migration could not complete. A corrupt keystore file is *not* in this
category — that is still recovered from, as in v1.3.0.

Callers that treated `keyExists === false` as "safe to enrol" should now also handle the rejection,
and treat it as "unknown — retry", not as "no key".

---

## 🚀 What's New

### Private key stored outside backup-eligible storage

- Live keystore: `no_backup/software_keys.p12`, mode 0600
- Quarantined copies: `no_backup/keystore_forensics/`, retention capped at 3 per infix
- Nothing in `files/` holds private key material after migration

### Automatic migration from earlier installs

On first keystore access the module relocates, then deletes the backup-eligible originals:

| Legacy location | New location |
| --- | --- |
| `files/software_keys.p12` | `no_backup/software_keys.p12` |
| `files/software_keys.p12.tmp` | deleted (a complete copy of the key, so not merely abandoned) |
| `files/software_keys.p12.corrupted.<timestamp>` | `no_backup/keystore_forensics/` |
| `files/keystore_forensics/software_keys.p12.corrupted.<timestamp>` | `no_backup/keystore_forensics/` |

If the live keystore cannot be relocated, the call fails rather than returning the new path. The
alternative — returning a path with no file at it — would make the module build an empty keystore
and the device re-enrol with a new key while its issued certificate silently stopped matching, and
would leave the old key backup-eligible.

### Downgrade-then-upgrade is handled

A populated destination normally proves the legacy file is a stale leftover, because migration
renames rather than copies. That inference breaks on one path: a device that ran a post-migration
build, downgraded to a pre-migration build, and re-enrolled wrote a **newer** key into `files/`.

The newer file now wins on modification time, and the copy it supersedes is quarantined as
`no_backup/keystore_forensics/software_keys.p12.superseded.<timestamp>` rather than deleted — it is
a complete private key, and if the mtime comparison is ever wrong a forensic copy is recoverable
where a deletion is not. **Equal modification times quarantine as well**, because the two files on
this path are written within the same second and a filesystem that reports mtime at one- or
two-second resolution cannot rank them; treating a tie as "the no-backup copy wins" would delete the
newer key and reactivate the older one. Keeping both is the only answer the filesystem supports. If
the quarantine cannot be performed, migration fails instead of deleting either key. Only reachable
on sideload/enterprise/dev channels; the Play Store refuses to install a lower version.

### `deleteKey` reports partial success

When the hardware key was deleted but the software keystore was unreachable, the rejection message
says so explicitly (`"hardware key was deleted, but the software keystore was unreachable: ..."`)
instead of swallowing half the outcome.

### `keystore` descriptor on `CSRResult`

```typescript
keystore?: {
  path: string;        // absolute path to the PKCS12 file
  password?: string;   // see below
  format: 'pkcs12';
}
```

Present on Android when `useHardwareKey` is `false`; absent for hardware-backed keys (they have no
keystore file) and always absent on iOS (Keychain, not a file).

`password` is declared optional so a future release can populate it without a breaking type change.
**In this release the field is always present and always `""`** — the module never omits it. Treat
an absent password as the empty one if you are coding defensively, but do not expect to encounter
one.

---

## 🧪 Testing

71 JVM unit tests (Robolectric, API 33), no emulator required:

- `keyExists`, `getPublicKey`, `deleteKey` and `generateCSR` each asserted separately for the
  reject-not-resolve behaviour — each has its own broad `catch` that the location failure has to
  escape, so one shared test would not prove the others
- Legacy migration of the keystore, `.tmp`, and quarantined copies in both flat and
  `keystore_forensics/` layouts
- Migration failure leaves the only copy of the key intact for the next attempt
- Newer-legacy-keystore-wins, and quarantine-failure-aborts-migration
- Equal modification times keep both keys, staged as an exact tie rather than the minute-apart
  stamps the other downgrade tests use — otherwise the suite only covers filesystems whose mtime
  resolution can rank the two files in the first place

Storage failures are injected by pointing the module at a directory whose parent is a regular file,
so every write beneath it fails for any user including root. `File.setWritable(false)` was
deliberately not used: it is a silent no-op as root, so those tests would pass without exercising
the failure path on a containerised CI runner. See `android/src/test/README.md`.

---

## 📖 Documentation

- `README.md` — no-backup storage rationale, migration notes, removal of the backup XML files
- `android/src/test/README.md` — new test coverage, failure-injection technique, naming convention
- `.github/ai-review/*.md` — review prompts no longer ask for `EncryptedFile` and
  `backup_rules.xml`, which were removed in v1.3.0/v1.4.0 and would now be flagged as regressions
  against correct code

---

## 🔄 Upgrade Checklist

1. Remove any reference to `@xml/backup_rules` / `@xml/data_extraction_rules` from this package
2. Re-read `keystorePath` instead of using a cached value
3. Handle rejections from `keyExists` / `deleteKey` as "unknown, retry" rather than "no key"
4. Verify on device: `adb shell run-as <your.package> ls -l no_backup/` shows the keystore, and
   `ls -l files/` shows no `software_keys.p12*`
5. **Upgrade `react-native-mqtt-mtls` to 1.4.0 or later in the same release.** This version returns
   an absolute `no_backup/` keystore path, and mtls 1.3.x accepts absolute paths only inside
   `getFilesDir()` — `no_backup/` is a sibling of `files/`, not a child, so the pair ecc-csr 1.4.0 +
   mtls ≤1.3.x rejects the path with `Keystore path must be inside app-private storage` and every
   mTLS connection fails. A consumer that passes no `keystorePath` at all fares no better: mtls 1.3.x
   defaults to `files/software_keys.p12`, which this release migrates away. mtls 1.4.0 accepts both
   roots, so if the two land in separate releases, ship mtls first. Nothing enforces the pairing at
   the package-manager level — `package.json` here declares only `react-native` as a peer dependency.

---

## ⚠️ Known Limitations

- Hardware-backed key generation and StrongBox remain verified on real devices only; the JVM suite
  cannot exercise the Android Keystore
- The software keystore password is still empty by design — the file is protected by app-private
  no-backup storage and mode 0600, and PKCS12's HMAC still provides integrity. See the SECURITY
  RATIONALE comment on `KEYSTORE_PASSWORD` in `CSRModule.java` for why application-layer encryption
  (`EncryptedFile` + Tink, v1.2.0) was removed
- The downgrade-then-upgrade path picks a winner by modification time, which is an inference, not a
  proof; that is why the loser is quarantined rather than deleted. The inference cannot be repaired:
  the no-backup keystore carries no embedded timestamp, so the filename-based recency scheme used for
  quarantined copies does not transfer, and on a coarse-resolution filesystem the two stamps can be
  equal. A tie is therefore treated as unrankable and both copies are kept — one live, one forensic —
  rather than resolved in either direction

---

## 👥 Contributors

- Ved Yedla (@vedgenerac)
- Review feedback from @benjaminkomen, @jordanjkelly12, and automated reviewers
