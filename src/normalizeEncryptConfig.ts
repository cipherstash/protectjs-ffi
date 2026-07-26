// Imports from `./types.js`, not `./index.cjs`. Both work, but index.cts
// imports THIS module, so going through it was a circular import — and the
// canonical types now have to be reachable from the wasm `.d.ts`, which must
// not resolve the Neon entry.
import type {
  CanonicalCastAs,
  CanonicalColumn,
  CanonicalEncryptConfig,
  CastAs,
  Column,
  EncryptConfig,
} from './types.js'

/**
 * @deprecated Renamed to {@link CanonicalCastAs} and moved to `./types.js`,
 * where both entries can reach it. "Canonical" over "Native" because the wasm
 * build accepts this vocabulary too — it is the Rust core's, not the Node
 * addon's.
 */
export type NativeCastAs = CanonicalCastAs

/**
 * The Rust core uses a different `cast_as` vocabulary than the public JS API.
 * These three JS values have no direct equivalent and are remapped to their
 * canonical names.
 */
const CAST_AS_REMAP: Record<'string' | 'number' | 'bigint', CanonicalCastAs> = {
  string: 'text',
  number: 'float',
  bigint: 'big_int',
}

/** @deprecated Renamed to {@link CanonicalColumn} in `./types.js`. */
export type NativeColumn = CanonicalColumn

/** @deprecated Renamed to {@link CanonicalEncryptConfig} in `./types.js`. */
export type NativeEncryptConfig = CanonicalEncryptConfig

/**
 * Translate a public `EncryptConfig` into the vocabulary the native addon
 * expects:
 *
 * - `cast_as` values `string`/`number`/`bigint` become `text`/`float`/`big_int`.
 * - `ste_vec` indexes without an explicit `array_index_mode` default to
 *   `'none'` — the library would otherwise default to `'all'`.
 *
 * `mode` is intentionally left untouched: an omitted `mode` follows the
 * library default (`compat` since cipherstash-config 0.40.0). The input
 * config is never mutated.
 */
export function normalizeEncryptConfig(
  config: EncryptConfig,
): NativeEncryptConfig {
  const tables: Record<string, Record<string, NativeColumn>> = {}
  for (const [tableName, columns] of Object.entries(config.tables)) {
    const normalizedColumns: Record<string, NativeColumn> = {}
    for (const [columnName, column] of Object.entries(columns)) {
      normalizedColumns[columnName] = normalizeColumn(column)
    }
    tables[tableName] = normalizedColumns
  }
  return { ...config, tables }
}

function normalizeColumn(column: Column): NativeColumn {
  const { cast_as, indexes, ...rest } = column
  const normalized: NativeColumn = { ...rest }

  if (cast_as !== undefined) {
    normalized.cast_as = remapCastAs(cast_as)
  }

  const steVec = indexes?.ste_vec
  if (indexes !== undefined) {
    normalized.indexes = indexes
  }
  if (steVec !== undefined && steVec.array_index_mode === undefined) {
    normalized.indexes = {
      ...indexes,
      ste_vec: { ...steVec, array_index_mode: 'none' },
    }
  }

  return normalized
}

function remapCastAs(value: CastAs): NativeCastAs {
  if (value in CAST_AS_REMAP) {
    return CAST_AS_REMAP[value as keyof typeof CAST_AS_REMAP]
  }
  // The remaining `CastAs` members are already canonical `NativeCastAs` values.
  return value as NativeCastAs
}
