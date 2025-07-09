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

const encryptConfig = JSON.stringify({
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

describe('encrypt and decrypt', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient(encryptConfig)
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
    const client = await newClient(encryptConfig)
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

  test('can pass in primary key', async () => {
    const client = await newClient(encryptConfig)
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
      primaryKey: ['123'],
    })

    const decrypted = await decrypt(client, ciphertext.c, undefined)

    expect(decrypted).toBe(originalPlaintext)
  })

  test('can pass in composite primary key', async () => {
    const client = await newClient(encryptConfig)
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
      primaryKey: ['keyOne', 'keyTwo'],
    })

    const decrypted = await decrypt(client, ciphertext.c, undefined)

    expect(decrypted).toBe(originalPlaintext)
  })
})

describe('encryptBulk and decryptBulk', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient(encryptConfig)
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
    const client = await newClient(encryptConfig)
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

  test('can use decryptBulkFallible', async () => {
    const client = await newClient(encryptConfig)
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

    const decrypted = await decryptBulkFallible(
      client,
      ciphertexts.map((c) => ({ ciphertext: c.c })),
    )

    expect(decrypted).toEqual([{ data: plaintextOne }, { data: plaintextTwo }])
  })

  test('can pass primary key', async () => {
    const client = await newClient(encryptConfig)
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'
    const plaintextThree = 'ghi'

    const ciphertexts = await encryptBulk(
      client,
      [
        // single primary key
        {
          plaintext: plaintextOne,
          column: 'email',
          table: 'users',
          primaryKey: ['pk1'],
        },
        // composite primary key
        {
          plaintext: plaintextTwo,
          column: 'email',
          table: 'users',
          primaryKey: ['pk2-1', 'pk2-2'],
        },
        // primary key not specified
        {
          plaintext: plaintextThree,
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

    expect(decrypted).toEqual([plaintextOne, plaintextTwo, plaintextThree])
  })
})
