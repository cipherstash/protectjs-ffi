// Hand-written barrel over the vendored (generated) EQL v3 payload types in
// src/eql-v3-types/. Assembles the public unions and renames the few types
// whose names would clash with the v2 exports in index.cts (`Identifier`,
// `SteVecEntry`) or shadow a global (`Boolean`, `Date`).

import type { Bigint } from './eql-v3-types/Bigint.js'
import type { BigintEq } from './eql-v3-types/BigintEq.js'
import type { BigintOrd } from './eql-v3-types/BigintOrd.js'
import type { BigintOrdOpe } from './eql-v3-types/BigintOrdOpe.js'
import type { BigintOrdOre } from './eql-v3-types/BigintOrdOre.js'
import type { Boolean as EqlV3Boolean } from './eql-v3-types/Boolean.js'
import type { Date as EqlV3Date } from './eql-v3-types/Date.js'
import type { DateEq } from './eql-v3-types/DateEq.js'
import type { DateOrd } from './eql-v3-types/DateOrd.js'
import type { DateOrdOpe } from './eql-v3-types/DateOrdOpe.js'
import type { DateOrdOre } from './eql-v3-types/DateOrdOre.js'
import type { Double } from './eql-v3-types/Double.js'
import type { DoubleEq } from './eql-v3-types/DoubleEq.js'
import type { DoubleOrd } from './eql-v3-types/DoubleOrd.js'
import type { DoubleOrdOpe } from './eql-v3-types/DoubleOrdOpe.js'
import type { DoubleOrdOre } from './eql-v3-types/DoubleOrdOre.js'
import type { Integer } from './eql-v3-types/Integer.js'
import type { IntegerEq } from './eql-v3-types/IntegerEq.js'
import type { IntegerOrd } from './eql-v3-types/IntegerOrd.js'
import type { IntegerOrdOpe } from './eql-v3-types/IntegerOrdOpe.js'
import type { IntegerOrdOre } from './eql-v3-types/IntegerOrdOre.js'
import type { Numeric } from './eql-v3-types/Numeric.js'
import type { NumericEq } from './eql-v3-types/NumericEq.js'
import type { NumericOrd } from './eql-v3-types/NumericOrd.js'
import type { NumericOrdOpe } from './eql-v3-types/NumericOrdOpe.js'
import type { NumericOrdOre } from './eql-v3-types/NumericOrdOre.js'
import type { Real } from './eql-v3-types/Real.js'
import type { RealEq } from './eql-v3-types/RealEq.js'
import type { RealOrd } from './eql-v3-types/RealOrd.js'
import type { RealOrdOpe } from './eql-v3-types/RealOrdOpe.js'
import type { RealOrdOre } from './eql-v3-types/RealOrdOre.js'
import type { Smallint } from './eql-v3-types/Smallint.js'
import type { SmallintEq } from './eql-v3-types/SmallintEq.js'
import type { SmallintOrd } from './eql-v3-types/SmallintOrd.js'
import type { SmallintOrdOpe } from './eql-v3-types/SmallintOrdOpe.js'
import type { SmallintOrdOre } from './eql-v3-types/SmallintOrdOre.js'
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
  Bigint,
  BigintEq,
  BigintOrd,
  BigintOrdOpe,
  BigintOrdOre,
  EqlV3Boolean,
  EqlV3Date,
  DateEq,
  DateOrd,
  DateOrdOpe,
  DateOrdOre,
  Double,
  DoubleEq,
  DoubleOrd,
  DoubleOrdOpe,
  DoubleOrdOre,
  Integer,
  IntegerEq,
  IntegerOrd,
  IntegerOrdOpe,
  IntegerOrdOre,
  Numeric,
  NumericEq,
  NumericOrd,
  NumericOrdOpe,
  NumericOrdOre,
  Real,
  RealEq,
  RealOrd,
  RealOrdOpe,
  RealOrdOre,
  Smallint,
  SmallintEq,
  SmallintOrd,
  SmallintOrdOpe,
  SmallintOrdOre,
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
  | Bigint
  | BigintEq
  | BigintOrd
  | BigintOrdOpe
  | BigintOrdOre
  | EqlV3Boolean
  | EqlV3Date
  | DateEq
  | DateOrd
  | DateOrdOpe
  | DateOrdOre
  | Double
  | DoubleEq
  | DoubleOrd
  | DoubleOrdOpe
  | DoubleOrdOre
  | Integer
  | IntegerEq
  | IntegerOrd
  | IntegerOrdOpe
  | IntegerOrdOre
  | Numeric
  | NumericEq
  | NumericOrd
  | NumericOrdOpe
  | NumericOrdOre
  | Real
  | RealEq
  | RealOrd
  | RealOrdOpe
  | RealOrdOre
  | Smallint
  | SmallintEq
  | SmallintOrd
  | SmallintOrdOpe
  | SmallintOrdOre
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
