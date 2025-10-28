import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decrypt,
  encrypt,
  type Identifier,
  newClient,
  isEncrypted,
} from '@cipherstash/protect-ffi'

// Import a shared encryptConfig from common.js
import { encryptConfig } from './common.js'

type UserColumn = Identifier<typeof encryptConfig>

const stringColumn: UserColumn = {
  table: 'users',
  column: 'email',
}

const intColumn: UserColumn = {
  table: 'users',
  column: 'score',
}

const cases: { identifier: UserColumn; plaintext: string | number }[] = [
  { identifier: stringColumn, plaintext: 'abc' },
  { identifier: intColumn, plaintext: 123 },
]

describe.each(cases)(
  'encrypt and decrypt',
  async ({ identifier, plaintext }) => {
    describe(`using column ${identifier.column} with ${typeof plaintext} value`, () => {
      test('can round-trip encrypt and decrypt a string', async () => {
        const client = await newClient({ encryptConfig })
        const ciphertext = await encrypt(client, {
          plaintext,
          ...identifier,
        })

        expect(isEncrypted(ciphertext)).toBe(true)

        const decrypted = await decrypt(client, { ciphertext })
        expect(decrypted).toBe(plaintext)
      })

      test('can explicitly pass in undefined for optional fields', async () => {
        const client = await newClient({ encryptConfig })

        const ciphertext = await encrypt(client, {
          plaintext,
          serviceToken: undefined,
          lockContext: undefined,
          unverifiedContext: undefined,
          ...identifier,
        })

        const decrypted = await decrypt(client, {
          ciphertext,
          lockContext: undefined,
          serviceToken: undefined,
          unverifiedContext: undefined,
        })

        expect(decrypted).toBe(plaintext)
      })
    })
  },
)
