import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decrypt,
  decryptBulk,
  decryptBulkFallible,
  encrypt,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'

describe('encrypt and decrypt', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient()
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, originalPlaintext, 'email')

    const decrypted = await decrypt(client, ciphertext)

    expect(decrypted).toBe(originalPlaintext)
  })

  test('can pass in undefined for ctsToken', async () => {
    const client = await newClient()
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(
      client,
      originalPlaintext,
      'email',
      undefined,
      undefined,
    )

    const decrypted = await decrypt(client, ciphertext, undefined)

    expect(decrypted).toBe(originalPlaintext)
  })
})

describe('encryptBulk and decryptBulk', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient()
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(client, [
      {
        plaintext: plaintextOne,
        column: 'email',
      },
      {
        plaintext: plaintextTwo,
        column: 'email',
      },
    ])

    const decrypted = await decryptBulk(
      client,
      ciphertexts.map((c) => ({ ciphertext: c })),
    )

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })

  test('can pass in undefined for ctsToken and lockContext', async () => {
    const client = await newClient()
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(
      client,
      [
        {
          plaintext: plaintextOne,
          column: 'email',
          lockContext: undefined,
        },
        {
          plaintext: plaintextTwo,
          column: 'email',
          lockContext: undefined,
        },
      ],
      undefined,
    )

    const decrypted = await decryptBulk(
      client,
      ciphertexts.map((c) => ({ ciphertext: c })),
      undefined,
    )

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })

  test('can use decryptBulkFallible', async () => {
    const client = await newClient()
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(client, [
      {
        plaintext: plaintextOne,
        column: 'email',
      },
      {
        plaintext: plaintextTwo,
        column: 'email',
      },
    ])

    const decrypted = await decryptBulkFallible(
      client,
      ciphertexts.map((c) => ({ ciphertext: c })),
    )

    expect(decrypted).toEqual([{ data: plaintextOne }, { data: plaintextTwo }])
  })
})
