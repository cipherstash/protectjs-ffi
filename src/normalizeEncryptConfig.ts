import type { CastAs, Column, EncryptConfig } from './index.cjs'

/**
 * The `cast_as` vocabulary the native addon (cipherstash-config's
 * `CanonicalEncryptionConfig`) accepts. The public `CastAs` union contains
 * three JS-only members (`string`, `number`, `bigint`) that are remapped to
 * their canonical equivalents (`text`, `float`, `big_int`) before being
 * handed to the native side.
 */
export type NativeCastAs =
  | 'text'
  | 'float'
  | 'big_int'
  | 'boolean'
  | 'date'
  | 'json'
  | 'timestamp'

/**
 * The native addon uses a different `cast_as` vocabulary than the public JS
 * API. These three JS values have no direct equivalent and are remapped to
 * their canonical names.
 */
const CAST_AS_REMAP: Record<'string' | 'number' | 'bigint', NativeCastAs> = {
  string: 'text',
  number: 'float',
  bigint: 'big_int',
}

/** A column after normalization — `cast_as` is in the canonical vocabulary. */
export type NativeColumn = Omit<Column, 'cast_as'> & { cast_as?: NativeCastAs }

/** An encrypt config in the vocabulary the native addon expects. */
export type NativeEncryptConfig = Omit<EncryptConfig, 'tables'> & {
  tables: Record<string, Record<string, NativeColumn>>
}

/**
 * Translate a public `EncryptConfig` into the vocabulary the native addon
 * expects:
 *
 * - `cast_as` values `string`/`number`/`bigint` become `text`/`float`/`big_int`.
 * - `ste_vec` indexes without an explicit `array_index_mode` default to
 *   `'none'` — the library would otherwise default to `'all'`.
 *
 * `mode` is intentionally left untouched: an omitted `mode` follows the
 * library default (`standard`). The input config is never mutated.
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
