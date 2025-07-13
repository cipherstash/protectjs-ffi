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
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

    expect(decrypted).toBe(originalPlaintext)
  })

  test('can explicitly pass in undefined for optional fields', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
      serviceToken: undefined,
      lockContext: undefined,
    })

    const decrypted = await decrypt(client, {
      ciphertext: ciphertext.c,
      lockContext: undefined,
      serviceToken: undefined,
    })

    expect(decrypted).toBe(originalPlaintext)
  })

  test('encrypt throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    await expect(async () => {
      await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'email',
        table: 'users',
        lockContext: {
          identityClaim: ['sub'],
        },
      })
    }).rejects.toThrowError(/Failed to send request/)
  })

  test('decrypt throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    await expect(async () => {
      await decrypt(client, {
        ciphertext: ciphertext.c,
        lockContext: {
          identityClaim: ['sub'],
        },
      })
    }).rejects.toThrowError(/Failed to send request/)
  })
})

describe('encryptBulk and decryptBulk', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient({ encryptConfig })
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
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
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map(({ c }) => ({ ciphertext: c })),
    })

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })

  test('can pass in undefined for optional fields', async () => {
    const client = await newClient({ encryptConfig })
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
        {
          plaintext: plaintextOne,
          column: 'email',
          table: 'users',
          lockContext: undefined,
        },
        {
          plaintext: plaintextTwo,
          column: 'email',
          table: 'users',
        },
      ],
      serviceToken: undefined,
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map(({ c }) => ({
        ciphertext: c,
        lockContext: undefined,
      })),
      serviceToken: undefined,
    })

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })

  test('can use decryptBulkFallible', async () => {
    const client = await newClient({ encryptConfig })
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'

    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
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
    })

    const decrypted = await decryptBulkFallible(client, {
      ciphertexts: ciphertexts.map((c) => ({ ciphertext: c.c })),
    })

    expect(decrypted).toEqual([{ data: plaintextOne }, { data: plaintextTwo }])
  })

  test('encryptBulk throws an errow when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })

    await expect(async () => {
      await encryptBulk(client, {
        plaintexts: [
          {
            plaintext: 'abc',
            column: 'email',
            table: 'users',
            lockContext: {
              identityClaim: ['sub'],
            },
          },
        ],
      })
    }).rejects.toThrowError(/Failed to send request/)
  })

  test('decryptBulk throws an errow when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
        {
          plaintext: 'abc',
          column: 'email',
          table: 'users',
        },
      ],
    })

    await expect(async () => {
      await decryptBulk(client, {
        ciphertexts: ciphertexts.map(({ c }) => ({
          ciphertext: c,
          lockContext: {
            identityClaim: ['sub'],
          },
        })),
      })
    }).rejects.toThrowError(/Failed to send request/)
  })
})
