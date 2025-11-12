import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decrypt,
  encrypt,
  type Identifier,
  newClient,
  isEncrypted,
} from '@cipherstash/protect-ffi'

import { encryptConfig } from './common.js'
type UserColumn = Identifier<typeof encryptConfig>

const stringColumn: UserColumn = {
  table: 'users',
  column: 'email',
}

describe('keyset tests', () => {
  test('can round-trip encrypt and decrypt a string using keyset name', async () => {
    const client = await newClient({
      encryptConfig,
      clientOpts: {
        keyset: { Name: 'Test' },
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

  test('can round-trip encrypt and decrypt a string using keyset uuid', async () => {
    const client = await newClient({
      encryptConfig,
      clientOpts: {
        keyset: { Uuid: '4152449b-505a-4186-93b6-d3d87eba7a47' },
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

  test('throws an error when using an invalid keyset', async () => {
    try {
      await newClient({
        encryptConfig,
        clientOpts: {
          keyset: { Name: 'invalid' },
        },
      })
    } catch (error: unknown) {
      expect((error as Error).message.includes('Failed to load keyset')).toBe(
        true,
      )
    }
  }, 10000)
})
