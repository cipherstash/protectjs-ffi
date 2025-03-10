import { expect, test } from 'vitest'

import { decrypt, encrypt, newClient } from '@cipherstash/protect-ffi'

test('can round-trip encrypt and decrypt', async () => {
  const client = await newClient(encryptConfig())
  const originalPlaintext = 'abc'

  const ciphertext = await encrypt(client, {
    plaintext: originalPlaintext,
    column: 'email',
    table: 'users',
  })

  const decrypted = await decrypt(client, JSON.parse(ciphertext).c)

  expect(decrypted).toBe(originalPlaintext)
})

test('can pass in undefined for ctsToken', async () => {
  const client = await newClient(encryptConfig())
  const originalPlaintext = 'abc'

  const ciphertext = await encrypt(
    client,
    {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    },
    undefined,
  )

  const decrypted = await decrypt(client, JSON.parse(ciphertext).c, undefined)

  expect(decrypted).toBe(originalPlaintext)
})

function encryptConfig() {
  return JSON.stringify({
    v: 1,
    tables: {
      users: {
        email: {
          indexes: {
            ore: {},
            match: {},
            unique: {},
          },
        },
      },
    },
  })
}
