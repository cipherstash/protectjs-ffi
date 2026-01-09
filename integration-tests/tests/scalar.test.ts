import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decrypt,
  encrypt,
  type Encrypted,
  type Identifier,
  newClient,
  isEncrypted,
} from '@cipherstash/protect-ffi'

// Import shared configs from common.js
import { encryptConfig, jsonSteVec } from './common.js'

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
  test('should return false when v field is missing', () => {
    const missingVersion = {
      i: { t: 'users', c: 'email' },
      c: 'somedata',
    }

    // biome-ignore lint/suspicious/noExplicitAny: Testing invalid data intentionally
    expect(isEncrypted(missingVersion as any)).toBe(false)
  })

  test('should return false when i field is missing', () => {
    const missingIdentifier = {
      v: 1,
      c: 'somedata',
    }

    // biome-ignore lint/suspicious/noExplicitAny: Testing invalid data intentionally
    expect(isEncrypted(missingIdentifier as any)).toBe(false)
  })
})

describe('old format backwards compatibility', () => {
  test('should decrypt old format data with k: ct discriminant field', async () => {
    const client = await newClient({ encryptConfig })
    const plaintext = 'test@example.com'

    // Encrypt to get valid ciphertext
    const ciphertext = await encrypt(client, {
      plaintext,
      table: 'users',
      column: 'email',
    })

    // Simulate old format by adding "k" field (old discriminant for ciphertext variant)
    const oldFormat = { ...ciphertext, k: 'ct' }

    // Should still be recognized as encrypted (serde ignores unknown fields)
    expect(isEncrypted(oldFormat)).toBe(true)

    // Should decrypt correctly
    const decrypted = await decrypt(client, { ciphertext: oldFormat as Encrypted })
    expect(decrypted).toBe(plaintext)
  })

  test('should decrypt old SteVec format with k: sv discriminant', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })
    const plaintext = { name: 'test' }

    const ciphertext = await encrypt(client, {
      plaintext,
      table: 'users',
      column: 'profile',
    })

    // Simulate old SteVec format
    const oldFormat = { ...ciphertext, k: 'sv' }

    expect(isEncrypted(oldFormat)).toBe(true)
    const decrypted = await decrypt(client, { ciphertext: oldFormat as Encrypted })
    expect(decrypted).toEqual(plaintext)
  })
})

describe('new format validation', () => {
  test('encrypted output should not contain k field', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email',
    })

    // New format must NOT have the "k" discriminant
    expect(ciphertext).not.toHaveProperty('k')

    // Verify required fields are present
    expect(ciphertext).toHaveProperty('c')
    expect(ciphertext).toHaveProperty('i')
    expect(ciphertext).toHaveProperty('v')
  })

  test('encrypted JSON output should not contain k field', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const ciphertext = await encrypt(client, {
      plaintext: { foo: 'bar' },
      table: 'users',
      column: 'profile',
    })

    expect(ciphertext).not.toHaveProperty('k')
    expect(ciphertext).toHaveProperty('sv') // SteVec field
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
    expect(ciphertext.hm?.length).toBeGreaterThan(0)
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
    expect(ciphertext.ob?.length).toBeGreaterThan(0)
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
    expect(ciphertext.bf?.length).toBeGreaterThan(0)
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
