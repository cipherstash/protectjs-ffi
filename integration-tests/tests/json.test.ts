import 'dotenv/config'
import { describe, expect, test } from 'vitest'
import {
  decrypt,
  encrypt,
  type Identifier,
  newClient,
} from '@cipherstash/protect-ffi'

// Import shared encryptConfig from common.js
import { assertSteVec, jsonOpaque, jsonSteVec } from './common.js'

type UserColumn = Identifier<typeof jsonOpaque>

const userProfile: UserColumn = {
  table: 'users',
  column: 'profile',
}

// There are 2 ways we might want to handle JSON data:
// 1. As an opaque blob - we don't care about the structure of the data, we just
//    want to store and retrieve it as-is.
// 2. As a structured object - we want to be able to query and index the data,
//    so we need to know the structure of the data.
//
// In this test suite, we'll test both options.
describe.each([
  { encryptConfig: jsonOpaque, description: 'opaque' },
  { encryptConfig: jsonSteVec, description: 'ste_vec' },
])(
  'Can round-trip encrypt & decrypt JSON',
  ({ encryptConfig, description }) => {
    describe(`using ${description} config`, () => {
      test('object', async ({ annotate }) => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: 123 }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('array', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = [1, 2, 3]

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('nested array within object', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: [1, 2, 3] }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('nested object within object', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: { qux: 'quux' } }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('nested object within array', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: [{ qux: 'quux' }] }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })
    })
  },
)

describe('SteVec output structure', () => {
  test('encrypted output has expected fields', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const ciphertext = await encrypt(client, {
      plaintext: { foo: 'bar' },
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(ciphertext).toHaveProperty('sv')
    expect(ciphertext).toHaveProperty('i')
    expect(ciphertext).toHaveProperty('v')
    // EQL v2.3 places the root ciphertext at sv[0].c — not at the root.
    expect(ciphertext).not.toHaveProperty('c')

    // Validate entry structure uses new field names
    expect(Array.isArray(ciphertext.sv)).toBe(true)
    expect(ciphertext.sv?.length ?? 0).toBeGreaterThan(0)

    const entry = ciphertext.sv?.[0]
    expect(entry).toHaveProperty('c') // Entry ciphertext (new format)
    expect(entry).toHaveProperty('s') // Tokenized selector

    // Old field names should NOT exist
    expect(entry).not.toHaveProperty('tokenized_selector')
    expect(entry).not.toHaveProperty('term')
    expect(entry).not.toHaveProperty('record')
    expect(entry).not.toHaveProperty('parent_is_array')
  })
})

describe('SteVec index field generation', () => {
  describe('selector field (s)', () => {
    test('should include selector field for entries', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test' },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      // At least one entry should have a selector
      const entriesWithSelector = sv.filter((e) => e.s !== undefined)
      expect(entriesWithSelector.length).toBeGreaterThan(0)

      // Selector should be hex encoded
      for (const entry of entriesWithSelector) {
        expect(entry.s).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })

  describe('array flag (a)', () => {
    test('should not set array flag when array_index_mode is default (NONE)', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { items: ['apple', 'banana', 'cherry'] },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      // With default ArrayIndexMode (NONE), array items should not have a: true
      const arrayEntries = sv.filter((e) => e.a === true)
      expect(arrayEntries.length).toBe(0)
    })

    test('should not set array flag for non-array elements', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test', count: 42 },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()

      // Non-array items should not have a: true
      for (const entry of ciphertext.sv ?? []) {
        expect(entry.a).not.toBe(true)
      }
    })
  })

  // Under SteVec Standard mode (the cipherstash-client 0.34.1-alpha.7
  // default), numeric and string values share a single orderable field `oc`
  // — the old `ocf`/`ocv` split has been collapsed via tagged-plaintext
  // encoding. Non-orderable values (booleans, null, arrays, objects) carry
  // an `hm` HMAC field instead.
  describe('ORE index field (oc)', () => {
    test('should include ORE field (oc) for numeric values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { count: 42, price: 99.99 },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      const entriesWithOre = sv.filter((e) => e.oc !== undefined)
      expect(entriesWithOre.length).toBeGreaterThan(0)

      for (const entry of entriesWithOre) {
        expect(entry.oc).toMatch(/^[0-9a-f]+$/i)
      }
    })

    test('should include ORE field (oc) for string values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'alice', city: 'london' },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      const entriesWithOre = sv.filter((e) => e.oc !== undefined)
      expect(entriesWithOre.length).toBeGreaterThan(0)

      for (const entry of entriesWithOre) {
        expect(entry.oc).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })

  describe('HMAC index field (hm)', () => {
    test('should include HMAC entry for the root object', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      // The root object (and any nested object, array, boolean, or null)
      // produces an HMAC entry under Standard mode.
      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test', email: 'test@example.com' },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      const entriesWithHm = sv.filter((e) => e.hm !== undefined)
      expect(entriesWithHm.length).toBeGreaterThan(0)

      for (const entry of entriesWithHm) {
        expect(entry.hm).toMatch(/^[0-9a-f]+$/i)
      }
    })

    test('should include HMAC entries for boolean values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { active: true, verified: false },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      const entriesWithHm = sv.filter((e) => e.hm !== undefined)
      expect(entriesWithHm.length).toBeGreaterThan(0)

      for (const entry of entriesWithHm) {
        expect(entry.hm).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })
})

describe('deeply nested JSON encryption', () => {
  test('should handle 4 levels of object nesting', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const deepNested = {
      level1: {
        level2: {
          level3: {
            level4: 'deep value',
          },
        },
      },
    }

    const ciphertext = await encrypt(client, {
      plaintext: deepNested,
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(Array.isArray(ciphertext.sv)).toBe(true)
    expect(ciphertext.sv?.length).toBeGreaterThan(0)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(deepNested)
  })

  test('should handle arrays nested within objects within arrays', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const complexNested = {
      items: [{ tags: ['tag1', 'tag2'] }, { tags: ['tag3', 'tag4', 'tag5'] }],
    }

    const ciphertext = await encrypt(client, {
      plaintext: complexNested,
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(Array.isArray(ciphertext.sv)).toBe(true)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(complexNested)
  })

  test('should handle mixed deep nesting with various types', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const mixedDeep = {
      user: {
        profile: {
          settings: {
            notifications: true,
            theme: 'dark',
            limits: [10, 20, 30],
          },
        },
        scores: [100, 200, 300],
      },
      metadata: {
        version: 1,
      },
    }

    const ciphertext = await encrypt(client, {
      plaintext: mixedDeep,
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(Array.isArray(ciphertext.sv)).toBe(true)
    expect(ciphertext.sv?.length).toBeGreaterThan(0)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(mixedDeep)
  })
})

// JSON plaintexts follow JSON.stringify semantics at the boundary on BOTH
// platforms: on Neon because neon's `Json` extractor stringifies the
// options object, on wasm because the boundary canonicalizes plaintexts
// through JSON.stringify → JSON.parse explicitly (see the wasm suite's
// counterpart test in wasm-round-trip.test.ts). This block pins the Neon
// half of that contract.
describe('json plaintext boundary', () => {
  test('rejects a bigint nested inside a json plaintext with a TypeError', async () => {
    const client = await newClient({ encryptConfig: jsonOpaque })

    // JSON has no bigint — JSON.stringify throws, and the error reaches
    // the caller as the engine's own TypeError (normalizeError passes
    // unknown error classes through untouched).
    await expect(
      encrypt(client, {
        plaintext: { count: 2n ** 60n + 1n },
        ...userProfile,
      }),
    ).rejects.toThrow(TypeError)
  })
})
