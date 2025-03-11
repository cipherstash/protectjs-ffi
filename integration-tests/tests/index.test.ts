import { describe, expect, test } from 'vitest'

import {
  decrypt,
  decryptBulk,
  encrypt,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'

describe('encrypt and decrypt', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient(encryptConfig())
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    const decrypted = await decrypt(client, ciphertext.c)

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

    const decrypted = await decrypt(client, ciphertext.c, undefined)

    expect(decrypted).toBe(originalPlaintext)
  })
})

describe('encryptBulk and decryptBulk', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient(encryptConfig())
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(client, [
      {
        plaintext: plaintextOne,
        column: 'email',
        table: 'users',
      },
      {
        plaintext: plaintextTwo,
        column: 'email',
        table: 'users',
      },
    ])

    const decrypted = await decryptBulk(
      client,
      ciphertexts.map(({ c }) => ({ ciphertext: c })),
    )

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })

  test('can pass in undefined for ctsToken', async () => {
    const client = await newClient(encryptConfig())
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(
      client,
      [
        {
          plaintext: plaintextOne,
          column: 'email',
          table: 'users',
        },
        {
          plaintext: plaintextTwo,
          column: 'email',
          table: 'users',
        },
      ],
      undefined,
    )

    const decrypted = await decryptBulk(
      client,
      ciphertexts.map(({ c }) => ({ ciphertext: c })),
      undefined,
    )

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })
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
