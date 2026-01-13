import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decryptBulk,
  decryptBulkFallible,
  encryptBulk,
  type EncryptPayload,
  type Identifier,
  newClient,
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

const numberColumn: UserColumn = {
  table: 'users',
  column: 'score_float',
}

const payloads: EncryptPayload[] = [
  { ...stringColumn, plaintext: 'abc' },
  { ...intColumn, plaintext: 123 },
  { ...numberColumn, plaintext: 123.456 },
]

describe('encryptBulk and decryptBulk', async () => {
  test('can round-trip encrypt and decrypt', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertexts = await encryptBulk(client, { plaintexts: payloads })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })

    expect(decrypted).toEqual(payloads.map((p) => p.plaintext))
  })

  test('can pass in undefined for optional fields', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertexts = await encryptBulk(client, {
      plaintexts: payloads,
      serviceToken: undefined,
      unverifiedContext: undefined,
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({
        ciphertext,
        lockContext: undefined,
      })),
      serviceToken: undefined,
      unverifiedContext: undefined,
    })

    expect(decrypted).toEqual(payloads.map((p) => p.plaintext))
  })

  test('can pass in unverified context', async () => {
    const client = await newClient({ encryptConfig })
    const unverifiedContext = {
      sub: 'sub-bulk',
    }

    const ciphertexts = await encryptBulk(client, {
      plaintexts: payloads,
      unverifiedContext,
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
      unverifiedContext,
    })

    expect(decrypted).toEqual(payloads.map((p) => p.plaintext))
  })

  test('can use decryptBulkFallible', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertexts = await encryptBulk(client, {
      plaintexts: payloads,
    })

    const decrypted = await decryptBulkFallible(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })

    expect(decrypted).toEqual(payloads.map((p) => ({ data: p.plaintext })))
  })

  test('can use unverified context with decryptBulkFallible', async () => {
    const client = await newClient({ encryptConfig })
    const unverifiedContext = {
      sub: 'sub-bulk-fallible',
    }

    const ciphertexts = await encryptBulk(client, {
      plaintexts: payloads,
      unverifiedContext,
    })

    const decrypted = await decryptBulkFallible(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
      unverifiedContext,
    })

    expect(decrypted).toEqual(payloads.map((p) => ({ data: p.plaintext })))
  })

  test('encryptBulk throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })

    await expect(async () => {
      await encryptBulk(client, {
        plaintexts: payloads.map((p) => ({
          ...p,
          lockContext: {
            identityClaim: ['sub'],
          },
        })),
      })
    }).rejects.toThrowError(/Request forbidden/)
  }, 10000)

  test('decryptBulk throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertexts = await encryptBulk(client, {
      plaintexts: payloads,
    })

    await expect(async () => {
      await decryptBulk(client, {
        ciphertexts: ciphertexts.map((ciphertext) => ({
          ciphertext,
          lockContext: {
            identityClaim: ['sub'],
          },
        })),
      })
    }).rejects.toThrowError(/Request forbidden/)
  }, 10000)
})

describe('bulk encryption order preservation', async () => {
  test('should preserve order with mixed column types', async () => {
    const client = await newClient({ encryptConfig })

    // Create payloads with different column types that may be grouped internally
    const payloads: EncryptPayload[] = [
      { ...stringColumn, plaintext: 'string-1' },
      { ...intColumn, plaintext: 100 },
      { ...stringColumn, plaintext: 'string-2' },
      { ...numberColumn, plaintext: 99.99 },
      { ...stringColumn, plaintext: 'string-3' },
    ]

    const ciphertexts = await encryptBulk(client, { plaintexts: payloads })
    expect(ciphertexts).toHaveLength(5)

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })

    expect(decrypted).toEqual(['string-1', 100, 'string-2', 99.99, 'string-3'])
  })

  test('should handle large batch with interleaved types', async () => {
    const client = await newClient({ encryptConfig })

    // Create a larger batch to stress test order preservation
    const payloads: EncryptPayload[] = []
    for (let i = 0; i < 20; i++) {
      payloads.push({ ...stringColumn, plaintext: `string-${i}` })
      payloads.push({ ...intColumn, plaintext: i })
    }

    const ciphertexts = await encryptBulk(client, { plaintexts: payloads })
    expect(ciphertexts).toHaveLength(40)

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })

    // Verify interleaved order preserved
    for (let i = 0; i < 20; i++) {
      expect(decrypted[i * 2]).toBe(`string-${i}`)
      expect(decrypted[i * 2 + 1]).toBe(i)
    }
  })

  test('should preserve order with repeated values', async () => {
    const client = await newClient({ encryptConfig })

    // Same plaintext values at different positions
    const payloads: EncryptPayload[] = [
      { ...stringColumn, plaintext: 'duplicate' },
      { ...intColumn, plaintext: 42 },
      { ...stringColumn, plaintext: 'duplicate' },
      { ...intColumn, plaintext: 42 },
      { ...stringColumn, plaintext: 'unique' },
    ]

    const ciphertexts = await encryptBulk(client, { plaintexts: payloads })
    expect(ciphertexts).toHaveLength(5)

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })

    expect(decrypted).toEqual(['duplicate', 42, 'duplicate', 42, 'unique'])
  })
})
