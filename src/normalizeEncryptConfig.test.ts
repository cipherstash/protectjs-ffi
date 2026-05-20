import { describe, expect, it } from 'vitest'
import type { EncryptConfig } from './index.cjs'
import { normalizeEncryptConfig } from './normalizeEncryptConfig.js'

describe('normalizeEncryptConfig', () => {
  it.each([
    ['string', 'text'],
    ['number', 'float'],
    ['bigint', 'big_int'],
  ] as const)('remaps cast_as %s -> %s', (input, expected) => {
    const config: EncryptConfig = {
      v: 1,
      tables: { t: { c: { cast_as: input } } },
    }
    expect(normalizeEncryptConfig(config).tables.t.c.cast_as).toBe(expected)
  })

  it.each(['text', 'json', 'boolean', 'date', 'timestamp'] as const)(
    'leaves canonical cast_as %s unchanged',
    (value) => {
      const input: EncryptConfig = {
        v: 1,
        tables: { t: { c: { cast_as: value } } },
      }
      expect(normalizeEncryptConfig(input).tables.t.c.cast_as).toBe(value)
    },
  )

  it('leaves omitted cast_as omitted', () => {
    const input: EncryptConfig = { v: 1, tables: { t: { c: {} } } }
    expect(normalizeEncryptConfig(input).tables.t.c.cast_as).toBeUndefined()
  })

  it('injects array_index_mode "none" when ste_vec omits it', () => {
    const input: EncryptConfig = {
      v: 1,
      tables: {
        t: { c: { cast_as: 'json', indexes: { ste_vec: { prefix: 't/c' } } } },
      },
    }
    expect(
      normalizeEncryptConfig(input).tables.t.c.indexes?.ste_vec
        ?.array_index_mode,
    ).toBe('none')
  })

  it('preserves an explicit array_index_mode', () => {
    const input: EncryptConfig = {
      v: 1,
      tables: {
        t: {
          c: {
            cast_as: 'json',
            indexes: { ste_vec: { prefix: 't/c', array_index_mode: 'all' } },
          },
        },
      },
    }
    expect(
      normalizeEncryptConfig(input).tables.t.c.indexes?.ste_vec
        ?.array_index_mode,
    ).toBe('all')
  })

  it('leaves ste_vec mode untouched', () => {
    const input: EncryptConfig = {
      v: 1,
      tables: {
        t: { c: { cast_as: 'json', indexes: { ste_vec: { prefix: 't/c' } } } },
      },
    }
    expect(
      normalizeEncryptConfig(input).tables.t.c.indexes?.ste_vec?.mode,
    ).toBeUndefined()
  })

  it('preserves sibling indexes when injecting ste_vec defaults', () => {
    const input: EncryptConfig = {
      v: 1,
      tables: {
        t: {
          c: {
            cast_as: 'json',
            indexes: {
              ore: {},
              unique: { token_filters: [{ kind: 'downcase' }] },
              ste_vec: { prefix: 't/c' },
            },
          },
        },
      },
    }
    const indexes = normalizeEncryptConfig(input).tables.t.c.indexes
    expect(indexes?.ore).toEqual({})
    expect(indexes?.unique).toEqual({ token_filters: [{ kind: 'downcase' }] })
    expect(indexes?.ste_vec?.array_index_mode).toBe('none')
  })

  it('does not mutate the input config', () => {
    const input: EncryptConfig = {
      v: 1,
      tables: {
        t: {
          c: { cast_as: 'string', indexes: { ste_vec: { prefix: 't/c' } } },
        },
      },
    }
    const snapshot = JSON.parse(JSON.stringify(input))
    normalizeEncryptConfig(input)
    expect(input).toEqual(snapshot)
  })

  it('handles multiple tables and columns', () => {
    const input: EncryptConfig = {
      v: 1,
      tables: {
        users: { name: { cast_as: 'string' }, age: { cast_as: 'number' } },
        events: { data: { cast_as: 'json' } },
      },
    }
    const out = normalizeEncryptConfig(input)
    expect(out.tables.users.name.cast_as).toBe('text')
    expect(out.tables.users.age.cast_as).toBe('float')
    expect(out.tables.events.data.cast_as).toBe('json')
  })
})
