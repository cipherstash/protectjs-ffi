// Hand-written barrel over the vendored (generated) EQL v3 payload types in
// src/eql-v3-types/. Assembles the public unions and renames the few types
// whose names would clash with the v2 exports in index.cts (`Identifier`,
// `SteVecEntry`) or shadow a global (`Date`).

import type { Bool } from './eql-v3-types/Bool.js'
import type { Date as EqlV3Date } from './eql-v3-types/Date.js'
import type { DateEq } from './eql-v3-types/DateEq.js'
import type { DateOrd } from './eql-v3-types/DateOrd.js'
import type { DateOrdOpe } from './eql-v3-types/DateOrdOpe.js'
import type { DateOrdOre } from './eql-v3-types/DateOrdOre.js'
import type { Float4 } from './eql-v3-types/Float4.js'
import type { Float4Eq } from './eql-v3-types/Float4Eq.js'
import type { Float4Ord } from './eql-v3-types/Float4Ord.js'
import type { Float4OrdOpe } from './eql-v3-types/Float4OrdOpe.js'
import type { Float4OrdOre } from './eql-v3-types/Float4OrdOre.js'
import type { Float8 } from './eql-v3-types/Float8.js'
import type { Float8Eq } from './eql-v3-types/Float8Eq.js'
import type { Float8Ord } from './eql-v3-types/Float8Ord.js'
import type { Float8OrdOpe } from './eql-v3-types/Float8OrdOpe.js'
import type { Float8OrdOre } from './eql-v3-types/Float8OrdOre.js'
import type { Int2 } from './eql-v3-types/Int2.js'
import type { Int2Eq } from './eql-v3-types/Int2Eq.js'
import type { Int2Ord } from './eql-v3-types/Int2Ord.js'
import type { Int2OrdOpe } from './eql-v3-types/Int2OrdOpe.js'
import type { Int2OrdOre } from './eql-v3-types/Int2OrdOre.js'
import type { Int4 } from './eql-v3-types/Int4.js'
import type { Int4Eq } from './eql-v3-types/Int4Eq.js'
import type { Int4Ord } from './eql-v3-types/Int4Ord.js'
import type { Int4OrdOpe } from './eql-v3-types/Int4OrdOpe.js'
import type { Int4OrdOre } from './eql-v3-types/Int4OrdOre.js'
import type { Int8 } from './eql-v3-types/Int8.js'
import type { Int8Eq } from './eql-v3-types/Int8Eq.js'
import type { Int8Ord } from './eql-v3-types/Int8Ord.js'
import type { Int8OrdOpe } from './eql-v3-types/Int8OrdOpe.js'
import type { Int8OrdOre } from './eql-v3-types/Int8OrdOre.js'
import type { Numeric } from './eql-v3-types/Numeric.js'
import type { NumericEq } from './eql-v3-types/NumericEq.js'
import type { NumericOrd } from './eql-v3-types/NumericOrd.js'
import type { NumericOrdOpe } from './eql-v3-types/NumericOrdOpe.js'
import type { NumericOrdOre } from './eql-v3-types/NumericOrdOre.js'
import type { SteVecDocument } from './eql-v3-types/SteVecDocument.js'
import type { SteVecQuery } from './eql-v3-types/SteVecQuery.js'
import type { Text } from './eql-v3-types/Text.js'
import type { TextEq } from './eql-v3-types/TextEq.js'
import type { TextMatch } from './eql-v3-types/TextMatch.js'
import type { TextOrd } from './eql-v3-types/TextOrd.js'
import type { TextOrdOpe } from './eql-v3-types/TextOrdOpe.js'
import type { TextOrdOre } from './eql-v3-types/TextOrdOre.js'
import type { TextSearch } from './eql-v3-types/TextSearch.js'
import type { Timestamp } from './eql-v3-types/Timestamp.js'
import type { TimestampEq } from './eql-v3-types/TimestampEq.js'
import type { TimestampOrd } from './eql-v3-types/TimestampOrd.js'
import type { TimestampOrdOpe } from './eql-v3-types/TimestampOrdOpe.js'
import type { TimestampOrdOre } from './eql-v3-types/TimestampOrdOre.js'

// Wire-field newtypes and shared envelope pieces.
export type { BloomFilter } from './eql-v3-types/BloomFilter.js'
export type { Ciphertext } from './eql-v3-types/Ciphertext.js'
export type { Hmac256 } from './eql-v3-types/Hmac256.js'
export type { Identifier as EqlV3Identifier } from './eql-v3-types/Identifier.js'
export type { OpeCllw } from './eql-v3-types/OpeCllw.js'
export type { OreBlock256 } from './eql-v3-types/OreBlock256.js'
export type { OreCllw } from './eql-v3-types/OreCllw.js'
export type { SchemaVersion } from './eql-v3-types/SchemaVersion.js'
export type { Selector } from './eql-v3-types/Selector.js'

// SteVec (encrypted JSONB) shapes.
export type { SteVecDocument } from './eql-v3-types/SteVecDocument.js'
export type { SteVecEntry as EqlV3SteVecEntry } from './eql-v3-types/SteVecEntry.js'
export type { SteVecForm } from './eql-v3-types/SteVecForm.js'
export type { SteVecQuery } from './eql-v3-types/SteVecQuery.js'
export type { SteVecQueryEntry } from './eql-v3-types/SteVecQueryEntry.js'
export type { SteVecTerm } from './eql-v3-types/SteVecTerm.js'

// Scalar domain payloads.
export type {
  Bool,
  EqlV3Date,
  DateEq,
  DateOrd,
  DateOrdOpe,
  DateOrdOre,
  Float4,
  Float4Eq,
  Float4Ord,
  Float4OrdOpe,
  Float4OrdOre,
  Float8,
  Float8Eq,
  Float8Ord,
  Float8OrdOpe,
  Float8OrdOre,
  Int2,
  Int2Eq,
  Int2Ord,
  Int2OrdOpe,
  Int2OrdOre,
  Int4,
  Int4Eq,
  Int4Ord,
  Int4OrdOpe,
  Int4OrdOre,
  Int8,
  Int8Eq,
  Int8Ord,
  Int8OrdOpe,
  Int8OrdOre,
  Numeric,
  NumericEq,
  NumericOrd,
  NumericOrdOpe,
  NumericOrdOre,
  Text,
  TextEq,
  TextMatch,
  TextOrd,
  TextOrdOpe,
  TextOrdOre,
  TextSearch,
  Timestamp,
  TimestampEq,
  TimestampOrd,
  TimestampOrdOpe,
  TimestampOrdOre,
}

/**
 * Every flat scalar EQL v3 storage payload (`{v: 3, i, c, <terms>}`, one
 * struct per `eql_v3` scalar domain).
 */
export type EncryptedV3Scalar =
  | Bool
  | EqlV3Date
  | DateEq
  | DateOrd
  | DateOrdOpe
  | DateOrdOre
  | Float4
  | Float4Eq
  | Float4Ord
  | Float4OrdOpe
  | Float4OrdOre
  | Float8
  | Float8Eq
  | Float8Ord
  | Float8OrdOpe
  | Float8OrdOre
  | Int2
  | Int2Eq
  | Int2Ord
  | Int2OrdOpe
  | Int2OrdOre
  | Int4
  | Int4Eq
  | Int4Ord
  | Int4OrdOpe
  | Int4OrdOre
  | Int8
  | Int8Eq
  | Int8Ord
  | Int8OrdOpe
  | Int8OrdOre
  | Numeric
  | NumericEq
  | NumericOrd
  | NumericOrdOpe
  | NumericOrdOre
  | Text
  | TextEq
  | TextMatch
  | TextOrd
  | TextOrdOpe
  | TextOrdOre
  | TextSearch
  | Timestamp
  | TimestampEq
  | TimestampOrd
  | TimestampOrdOpe
  | TimestampOrdOre

/**
 * EQL v3 **storage** payload — returned by `encrypt` / `encryptBulk` when the
 * client was created with `eqlVersion: 3`.
 *
 * Scalars carry no `k` discriminator: they are flat
 * (`{v: 3, i, c, <terms>}`, terms depending on the column's `eql_v3` domain).
 * Encrypted JSONB is a {@link SteVecDocument}, which keeps the `k: "sv"`
 * form discriminator (`{v: 3, k: "sv", i, sv: [...]}`).
 * The record ciphertext lives at `c` on scalars and at `sv[0].c` on SteVec
 * documents (`sv[0]` is always the decryption root).
 */
export type EncryptedV3 = EncryptedV3Scalar | SteVecDocument

/**
 * EQL v3 **query** payload — returned by `encryptQuery` / `encryptQueryBulk`
 * under `eqlVersion: 3`. Only JSONB containment queries are supported (the
 * `eql_v3.jsonb_query` needle); scalar and selector query encryption throws
 * until a v3 scalar query wire shape exists.
 */
export type EncryptedV3Query = SteVecQuery
