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

test('can round-trip encrypt and decrypt a string using keyset', async () => {
  const client = await newClient({
    encryptConfig,
    clientOpts: {
      keyset: { Name: 'default' },
    },
  })

  const identifier = stringColumn
  const plaintext = 'abc'

  const ciphertext = await encrypt(client, {
    plaintext,
    ...identifier,
  })

  expect(isEncrypted(ciphertext)).toBe(true)

  const decrypted = await decrypt(client, { ciphertext })
  expect(decrypted).toBe(plaintext)
})
