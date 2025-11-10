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

const cases: { identifier: UserColumn; plaintext: string | number }[] = [
  { identifier: stringColumn, plaintext: 'abc' },
]

describe.each(cases)(
  'encrypt and decrypt',
  async ({ identifier, plaintext }) => {
    describe(`using column ${identifier.column} with ${typeof plaintext} value`, () => {
      test('can round-trip encrypt and decrypt a string', async () => {
        const client = await newClient({
          encryptConfig,
          clientOpts: {
            keysetName: 'Test',
          },
        })
        const ciphertext = await encrypt(client, {
          plaintext,
          ...identifier,
        })

        expect(isEncrypted(ciphertext)).toBe(true)

        const decrypted = await decrypt(client, { ciphertext })
        expect(decrypted).toBe(plaintext)
      })
    })
  },
)
