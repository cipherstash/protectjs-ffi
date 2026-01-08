import 'dotenv/config'
import { describe, expect, test } from 'vitest'
import {
  decrypt,
  encrypt,
  type Identifier,
  newClient,
} from '@cipherstash/protect-ffi'

// Import shared encryptConfig from common.js
import { jsonOpaque, jsonSteVec } from './common.js'

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
  async ({ encryptConfig, description }) => {
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

    // SteVec variant must have these fields
    expect(ciphertext.sv).toBeDefined()
    expect(ciphertext).toHaveProperty('c') // Root ciphertext
    expect(ciphertext).toHaveProperty('sv')
    expect(ciphertext).toHaveProperty('i')
    expect(ciphertext).toHaveProperty('v')

    // Validate entry structure uses new field names
    const encrypted = ciphertext as { sv: unknown[] }
    expect(Array.isArray(encrypted.sv)).toBe(true)
    expect(encrypted.sv.length).toBeGreaterThan(0)

    const entry = encrypted.sv[0] as Record<string, unknown>
    expect(entry).toHaveProperty('c') // Entry ciphertext (new format)

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

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ s?: string; c: string }> }

      // At least one entry should have a selector
      const entriesWithSelector = encrypted.sv.filter((e) => e.s !== undefined)
      expect(entriesWithSelector.length).toBeGreaterThan(0)

      // Selector should be hex encoded
      for (const entry of entriesWithSelector) {
        expect(entry.s).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })

  describe('array flag (a)', () => {
    test('should set array flag for array elements', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { items: ['apple', 'banana', 'cherry'] },
        table: 'users',
        column: 'profile',
      })

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ a?: boolean; c: string }> }

      // Array items should have a: true
      const arrayEntries = encrypted.sv.filter((e) => e.a === true)
      expect(arrayEntries.length).toBeGreaterThan(0)
    })

    test('should not set array flag for non-array elements', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test', count: 42 },
        table: 'users',
        column: 'profile',
      })

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ a?: boolean; c: string }> }

      // Non-array items should not have a: true
      for (const entry of encrypted.sv) {
        expect(entry.a).not.toBe(true)
      }
    })
  })

  describe('ORE index fields (ocf/ocv)', () => {
    test('should include ORE fixed field (ocf) for numeric values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      // SteVec automatically generates ORE fields for numeric values
      const ciphertext = await encrypt(client, {
        plaintext: { count: 42, price: 99.99 },
        table: 'users',
        column: 'profile',
      })

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ ocf?: string; ocv?: string; c: string }> }

      // Numeric entries should have ORE fixed field
      const entriesWithOreFixed = encrypted.sv.filter((e) => e.ocf !== undefined)
      expect(entriesWithOreFixed.length).toBeGreaterThan(0)

      // ORE fields should be hex encoded
      for (const entry of entriesWithOreFixed) {
        expect(entry.ocf).toMatch(/^[0-9a-f]+$/i)
      }
    })

    test('should include ORE variable field (ocv) for string values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      // SteVec automatically generates ORE variable fields for string values
      const ciphertext = await encrypt(client, {
        plaintext: { name: 'alice', city: 'london' },
        table: 'users',
        column: 'profile',
      })

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ ocf?: string; ocv?: string; c: string }> }

      // String entries should have ORE variable field
      const entriesWithOreVariable = encrypted.sv.filter((e) => e.ocv !== undefined)
      expect(entriesWithOreVariable.length).toBeGreaterThan(0)

      // ORE fields should be hex encoded
      for (const entry of entriesWithOreVariable) {
        expect(entry.ocv).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })

  describe('unique index field (b3)', () => {
    test('should include blake3 hash for string values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      // SteVec automatically generates blake3 hash for string values
      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test', email: 'test@example.com' },
        table: 'users',
        column: 'profile',
      })

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ b3?: string; c: string }> }

      // String entries should have blake3 hash
      const entriesWithB3 = encrypted.sv.filter((e) => e.b3 !== undefined)
      expect(entriesWithB3.length).toBeGreaterThan(0)

      // b3 should be hex encoded
      for (const entry of entriesWithB3) {
        expect(entry.b3).toMatch(/^[0-9a-f]+$/i)
      }
    })

    test('should include blake3 hash for numeric values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      // SteVec also generates blake3 hash for numeric values for exact match lookups
      const ciphertext = await encrypt(client, {
        plaintext: { count: 42, price: 99.99 },
        table: 'users',
        column: 'profile',
      })

      expect(ciphertext.sv).toBeDefined()
      const encrypted = ciphertext as { sv: Array<{ b3?: string; c: string }> }

      // Numeric entries should also have blake3 hash for exact matching
      const entriesWithB3 = encrypted.sv.filter((e) => e.b3 !== undefined)
      expect(entriesWithB3.length).toBeGreaterThan(0)

      // b3 should be hex encoded
      for (const entry of entriesWithB3) {
        expect(entry.b3).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })
})
