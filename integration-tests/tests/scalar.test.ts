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

const intColumn: UserColumn = {
  table: 'users',
  column: 'score',
}

const numberColumn: UserColumn = {
  table: 'users',
  column: 'score_float',
}

const cases: { identifier: UserColumn; plaintext: string | number }[] = [
  { identifier: stringColumn, plaintext: 'abc' },
  { identifier: intColumn, plaintext: 123 },
  { identifier: numberColumn, plaintext: 123.456 },
]

describe.each(cases)(
  'encrypt and decrypt',
  async ({ identifier, plaintext }) => {
    describe(`using column ${identifier.column} with ${typeof plaintext} value`, () => {
      test('can round-trip encrypt and decrypt a string', async () => {
        const client = await newClient({ encryptConfig })
        const ciphertext = await encrypt(client, {
          plaintext,
          ...identifier,
        })

        expect(isEncrypted(ciphertext)).toBe(true)

        const decrypted = await decrypt(client, { ciphertext })
        expect(decrypted).toBe(plaintext)
      })

      test('can explicitly pass in undefined for optional fields', async () => {
        const client = await newClient({ encryptConfig })

        const ciphertext = await encrypt(client, {
          plaintext,
          serviceToken: undefined,
          lockContext: undefined,
          unverifiedContext: undefined,
          ...identifier,
        })

        const decrypted = await decrypt(client, {
          ciphertext,
          lockContext: undefined,
          serviceToken: undefined,
          unverifiedContext: undefined,
        })

        expect(decrypted).toBe(plaintext)
      })
    })
  },
)

describe('coercion', async () => {
  test('encrypting a float as an integer will truncate the value', async () => {
    const client = await newClient({ encryptConfig })

    const floatValue = 123.987
    const expectedTruncatedValue = 123

    const ciphertext = await encrypt(client, {
      plaintext: floatValue,
      table: 'users',
      column: 'score',
    })

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toBe(expectedTruncatedValue)
  })

  test('encrypting an integer as a float will preserve the value', async () => {
    const client = await newClient({ encryptConfig })

    const intValue = 123
    const expectedFloatValue = 123.0

    const ciphertext = await encrypt(client, {
      plaintext: intValue,
      table: 'users',
      column: 'score_float',
    })

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toBe(expectedFloatValue)
  })

  test('encrypting a string as an integer will error', async () => {
    const client = await newClient({ encryptConfig })

    const stringValue = 'not-a-number'

    await expect(
      encrypt(client, {
        plaintext: stringValue,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError()
  })

  test('encrypting a string as a float will error', async () => {
    const client = await newClient({ encryptConfig })

    const stringValue = 'not-a-number'

    await expect(
      encrypt(client, {
        plaintext: stringValue,
        table: 'users',
        column: 'score_float',
      }),
    ).rejects.toThrowError()
  })
})

describe('isEncrypted validation', () => {
  test('should reject old format with k discriminant tag', () => {
    // Old format used "k": "ct" discriminant for ciphertext variant
    // New format omits the k field - serde validates structure without it
    const oldFormatCiphertext = {
      k: 'ct',
      c: 'somebase85data',
      i: { t: 'users', c: 'email' },
      v: 1,
    }

    expect(isEncrypted(oldFormatCiphertext as any)).toBe(false)
  })

  test('should return false when v field is missing', () => {
    const missingVersion = {
      i: { t: 'users', c: 'email' },
      c: 'somedata',
    }

    expect(isEncrypted(missingVersion as any)).toBe(false)
  })

  test('should return false when i field is missing', () => {
    const missingIdentifier = {
      v: 1,
      c: 'somedata',
    }

    expect(isEncrypted(missingIdentifier as any)).toBe(false)
  })
})

describe('encrypted output SEM fields', () => {
  test('should include hm field when unique index configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email', // has unique: {} index
    })

    // hm = HMAC for exact match queries
    expect(ciphertext.hm).toBeDefined()
    expect(typeof ciphertext.hm).toBe('string')
    expect(ciphertext.hm!.length).toBeGreaterThan(0)
  })

  test('should include ob field when ore index configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 100,
      table: 'users',
      column: 'score', // has ore: {} index
    })

    // ob = ORE blocks for range queries
    expect(ciphertext.ob).toBeDefined()
    expect(Array.isArray(ciphertext.ob)).toBe(true)
    expect(ciphertext.ob!.length).toBeGreaterThan(0)
  })

  test('should include bf field when match index configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email', // has match: {} index
    })

    // bf = bloom filter for fuzzy/substring match queries
    expect(ciphertext.bf).toBeDefined()
    expect(Array.isArray(ciphertext.bf)).toBe(true)
    expect(ciphertext.bf!.length).toBeGreaterThan(0)
  })

  test('should include multiple SEM fields when multiple indexes configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email', // has ore, match, and unique indexes
    })

    // email column has all three index types
    expect(ciphertext.hm).toBeDefined() // unique
    expect(ciphertext.ob).toBeDefined() // ore
    expect(ciphertext.bf).toBeDefined() // match
  })
})
