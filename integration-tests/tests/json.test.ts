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
    expect(ciphertext.k).toBe('sv')
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
