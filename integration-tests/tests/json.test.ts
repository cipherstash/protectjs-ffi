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
      test('object', async () => {
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
