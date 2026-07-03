import { describe, expect, it } from 'vitest'
import type {
  EncryptQueryOptions,
  IndexTypeName,
  Indexes,
  QueryPayload,
} from './index.cjs'

// Every index that can be configured via `Indexes` must also be targetable
// from `encryptQuery` / `encryptQueryBulk` via `IndexTypeName`. The native
// side accepts all of these (see find_index_for_type in
// crates/protect-ffi/src/lib.rs).
type ConfigurableIndexName = keyof Indexes

describe('IndexTypeName', () => {
  it('covers every configurable index, including ope', () => {
    // Type-level assertion: the two unions must be identical. If a name is
    // added to `Indexes` without being queryable (or vice versa), this fails
    // to typecheck (enforced by `npm run test:typecheck`).
    const configurableIsQueryable: IndexTypeName =
      null as unknown as ConfigurableIndexName
    const queryableIsConfigurable: ConfigurableIndexName =
      null as unknown as IndexTypeName

    const names: IndexTypeName[] = ['ste_vec', 'match', 'ore', 'ope', 'unique']
    expect(names).toContain('ope')
    expect(configurableIsQueryable).toBeNull()
    expect(queryableIsConfigurable).toBeNull()
  })

  it('allows encryptQuery / encryptQueryBulk opts to target an ope index', () => {
    const opts: EncryptQueryOptions = {
      plaintext: 42,
      column: 'salary',
      table: 'employees',
      indexType: 'ope',
    }
    const payload: QueryPayload = {
      plaintext: 42,
      column: 'salary',
      table: 'employees',
      indexType: 'ope',
    }
    expect(opts.indexType).toBe('ope')
    expect(payload.indexType).toBe('ope')
  })
})
