# Release Notes v2.0.0-beta.1

**Release Date:** TBD (beta)
**Ships with:** Expo SDK 55+ (required — see Breaking Changes)

---

## 🎯 Overview

Version 2.0.0 moves the library from the React Native bridge to
[Expo Modules](https://docs.expo.dev/modules/overview/), and rewrites the native core in Kotlin
(from Java) and Swift (from Objective-C).

The JS API, error codes, key aliases and key storage locations are unchanged. Keys created by 1.x
are found after upgrading and no re-enrolment is needed. What changes is how the module is linked,
and the minimum platform versions.

This is a beta. It has been verified on a physical Android device and the iOS simulator, but not
yet on a physical iPhone.

---

## 💥 Breaking Changes

### 1. The host app must use Expo Modules

The module is now linked by Expo autolinking. `react-native.config.js` and `CSRPackage` are gone, so
React Native CLI autolinking no longer finds it.

- **Expo apps:** nothing to add. Run `npx expo prebuild --clean` after upgrading so the native
  projects pick up the new module.
- **Bare React Native apps:** [install `expo`](https://docs.expo.dev/bare/installing-expo-modules/)
  first. Without it the package fails at import.

### 2. Minimum versions raised

| | 1.x | 2.0.0 |
| --- | --- | --- |
| Expo SDK | not required | >= 55 |
| React Native | >= 0.60 | >= 0.83 |
| iOS deployment target | 12.0 | **15.1** |
| Android minSdk | 23 | 23 (unchanged) |

iOS 15.1 is the floor of the Expo SDK this module targets. Apps that still support iOS 12.0–15.0
must stay on 1.x.

### 3. A missing native module fails at import, not at first call

`NativeModules.CSRModule` used to be `undefined` when the module was not linked, and the app only
failed on its first call. `requireNativeModule('CSRModule')` throws as soon as the package is
imported, so a linking problem shows up at startup.

### 4. Smaller rejection differences

These do not affect callers that pass a string alias and handle the existing codes:

- **New `NATIVE_ERROR` code.** Both platforms reject with it for an unexpected native error that the
  core does not map to a specific code (for example a missing BouncyCastle class on Android).
  Previously such an error was not turned into a rejection; the Expo adapter now guarantees
  every call settles.
- **Alias must be a string.** Passing `null`/`undefined` as `privateKeyAlias` to `keyExists`,
  `deleteKey` or `getPublicKey` is now rejected by Expo's argument validation, with Expo's error
  code, before the library runs.
- **iOS:** `KEY_EXISTS_ERROR`, `DELETE_KEY_ERROR` and `CAPABILITIES_ERROR` are no longer produced.
  They were only raised from `@catch (NSException *)` blocks around Keychain calls that report
  failure through `OSStatus` and never throw, so they were unreachable. Android still produces all
  of its codes, `KEY_EXISTS_ERROR` included.
- **iOS:** rejections no longer attach the underlying `NSError`. Codes and messages are unchanged.

---

## 🚀 What's New

### Adapter + core split

Each platform now has two layers:

```
JS (src/index.ts)
   │  requireNativeModule('CSRModule')
   ▼
CSRModule.kt / CSRModule.swift   ← thin Expo adapter, no logic
   ▼
CSRCore.kt / CSRCore.swift       ← all behaviour, no React Native or Expo dependency
```

The adapter converts arguments, runs each call on a dedicated serial queue/executor, and turns
results and errors into promise resolutions/rejections. `CSRCore` holds all crypto and key storage
logic and can be tested without an app.

### Kotlin and Swift ports

`CSRCore` was ported from Java to Kotlin and from Objective-C to Swift, keeping the same behaviour:

- **iOS Keychain:** the lookup is unchanged: `kSecClassKey`, the same application tag bytes,
  `kSecAttrKeyTypeECSECPrimeRandom`, and no new attributes that would narrow the match.
- **Android software keystore:** unchanged: `no_backup/software_keys.p12`, PKCS12, empty
  password, mode 0600, same legacy migration and quarantine rules.
- **CSR encoding** (subject order, extensions, SAN, signature, PEM formatting) and BouncyCastle
  provider handling are unchanged.
- Java `String.trim()` semantics are kept explicitly on Android (`trimJava()`), because Kotlin's
  `trim()` strips a different set of characters.

### `undefined` params keep their defaults

The RN bridge dropped `undefined` properties, so the native side applied its defaults. Expo passes
them through as `null`, which Android would have treated as a real value (an undefined `curve` was
rejected, undefined subject fields went into the CSR empty). `generateCSR` now strips `undefined`
keys before calling native, which keeps the 1.x behaviour on both platforms. An explicit `null` is
still passed through as before.

### Podspec moved to `ios/`

`react-native-ecc-csr.podspec` now lives in `ios/` alongside the sources, as Expo modules expect.

---

## 🧪 Testing

73 JVM unit tests (Robolectric), no emulator required. The suite now calls `CSRCore` directly
(`CSRModuleTest` → `CSRCoreTest`), so it needs neither React Native nor Expo, and the CI job runs it
standalone. `CSRModule.kt` is excluded from the standalone build because `expo-modules-core` only
exists inside a consuming app.

Manual verification (installer-app):

- Pixel (physical) and iPhone simulator, both commits: fresh enrolment, CSR issued, MQTT connected

---

## 🔄 Upgrade Checklist

1. Make sure the app uses Expo SDK 55+ and React Native 0.83+, and targets iOS 15.1+
2. Point the dependency at the new version, then run `yarn install` and `npx expo prebuild --clean`
3. Remove any manual linking of this package (`react-native.config.js` overrides, `Podfile` entries,
   `MainApplication` package registration) if the app added one
4. If you match on `error.code`, see Breaking Changes §4
5. Verify on device: install the 1.x build and enrol, then install this build over it without
   uninstalling. `keyExists` should return `true` and the existing certificate should still connect

---

## ⚠️ Known Limitations

- Not yet verified on a physical iPhone. The consuming app uses software keys only
  (`useHardwareKey: false`), and the module sets no Keychain access group, so the simulator runs the
  same Keychain code path as a device
- iOS still has no automated tests; the Swift port is verified manually
- The Expo adapter (`CSRModule.kt` / `CSRModule.swift`) is not covered by unit tests
- Behaviour kept from 1.x: iOS falls back to P-384 for an unrecognised curve and does not reject a
  malformed SAN IP, while Android rejects both (`INVALID_CURVE` / `INVALID_IP`)

---

## 👥 Contributors

- Ved Yedla (@vedgenerac)
- Review feedback from @benjaminkomen and automated reviewers
