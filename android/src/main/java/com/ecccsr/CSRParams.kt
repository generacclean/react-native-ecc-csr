package com.ecccsr

import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record

/**
 * The argument of `generateCSR`, mirroring `CSRParams` in src/index.ts.
 *
 * Every field is nullable with a null default, and [CSRCore] applies the real defaults. That way
 * an absent property, an `undefined` one (which Expo skips) and an explicit `null` all mean
 * "not provided", on Android and iOS alike. A wrongly-typed value is rejected by Expo's converter
 * before CSRCore runs.
 *
 * `curve` stays a String rather than an Enumerable: Expo would reject an unknown value with
 * ERR_ENUM_NO_SUCH_VALUE before CSRCore runs, and callers match on INVALID_CURVE.
 */
class CSRParams : Record {
  @Field var country: String? = null
  @Field var state: String? = null
  @Field var locality: String? = null
  @Field var organization: String? = null
  @Field var organizationalUnit: String? = null
  @Field var commonName: String? = null
  @Field var serialNumber: String? = null
  @Field var ipAddress: String? = null
  @Field var dnsName: String? = null
  @Field var curve: String? = null
  @Field var privateKeyAlias: String? = null
  @Field var phoneInfo: String? = null
  @Field var useHardwareKey: Boolean? = null
}
