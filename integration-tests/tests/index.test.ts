import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type CastAs,
  decrypt,
  decryptBulk,
  decryptBulkFallible,
  encrypt,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'

const encryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'text' as CastAs, // FIXME: do we need the as ?
        indexes: {
          ore: {},
          match: {},
          unique: {},
        },
      },
      score: {
        cast_as: 'double' as CastAs,
        indexes: {}, // TODO: add ore index options here when we support them
      },
      profile: {
        cast_as: 'jsonb' as CastAs,
        indexes: {}, // TODO: add an index here
      },
    },
  },
}

describe('encrypt and decrypt', async () => {
  test('can round-trip encrypt and decrypt a string', async () => {
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

  test('can round-trip encrypt and decrypt a number', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 123.456

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'score',
      table: 'users',
    })

    const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

    expect(decrypted).toBe(originalPlaintext)
  })

  describe('Can round-trip encrypt & decrypt JSON', async () => {
    test('object', async () => {
      const client = await newClient({ encryptConfig })
      const originalPlaintext = { foo: 'bar', baz: 123 }

      const ciphertext = await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'profile',
        table: 'users',
      })

      const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

      expect(decrypted).toEqual(originalPlaintext)
    })

    test('array', async () => {
      const client = await newClient({ encryptConfig })
      const originalPlaintext = [1, 2, 3]

      const ciphertext = await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'profile',
        table: 'users',
      })

      const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

      expect(decrypted).toEqual(originalPlaintext)
    })

    test('nested array within object', async () => {
      const client = await newClient({ encryptConfig })
      const originalPlaintext = { foo: 'bar', baz: [1, 2, 3] }

      const ciphertext = await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'profile',
        table: 'users',
      })

      const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

      expect(decrypted).toEqual(originalPlaintext)
    })

    test('nested object within object', async () => {
      const client = await newClient({ encryptConfig })
      const originalPlaintext = { foo: 'bar', baz: { qux: 'quux' } }

      const ciphertext = await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'profile',
        table: 'users',
      })

      const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

      expect(decrypted).toEqual(originalPlaintext)
    })

    test('nested object within array', async () => {
      const client = await newClient({ encryptConfig })
      const originalPlaintext = { foo: 'bar', baz: [{ qux: 'quux' }] }

      const ciphertext = await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'profile',
        table: 'users',
      })

      const decrypted = await decrypt(client, { ciphertext: ciphertext.c })

      expect(decrypted).toEqual(originalPlaintext)
    })
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
      unverifiedContext: undefined,
    })

    const decrypted = await decrypt(client, {
      ciphertext: ciphertext.c,
      lockContext: undefined,
      serviceToken: undefined,
      unverifiedContext: undefined,
    })

    expect(decrypted).toBe(originalPlaintext)
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
      unverifiedContext: undefined,
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map(({ c }) => ({
        ciphertext: c,
        lockContext: undefined,
      })),
      serviceToken: undefined,
      unverifiedContext: undefined,
    })

    expect(decrypted).toEqual([plaintextOne, plaintextTwo])
  })

  test('can pass in unverified context', async () => {
    const client = await newClient({ encryptConfig })
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'
    const unverifiedContext = {
      sub: 'sub-bulk',
    }

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
      unverifiedContext,
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map(({ c }) => ({ ciphertext: c })),
      unverifiedContext,
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

  test('can use unverified context with decryptBulkFallible', async () => {
    const client = await newClient({ encryptConfig })
    const plaintextOne = 'abc'
    const plaintextTwo = 'def'
    const unverifiedContext = {
      sub: 'sub-bulk-fallible',
    }

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
      unverifiedContext,
    })

    const decrypted = await decryptBulkFallible(client, {
      ciphertexts: ciphertexts.map((c) => ({ ciphertext: c.c })),
      unverifiedContext,
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
  }, 10000)

  test('decryptBulk throws an error when identityClaim is used without a service token', async () => {
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
  }, 10000)
})
