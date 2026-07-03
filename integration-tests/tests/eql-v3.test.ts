import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decrypt,
  decryptBulk,
  decryptBulkFallible,
  encrypt,
  encryptBulk,
  encryptQuery,
  isEncrypted,
  newClient,
  ProtectError,
  type EncryptConfig,
  type EncryptedV3,
  type SteVecDocument,
  type SteVecQuery,
} from '@cipherstash/protect-ffi'

// Every EQL v3 scalar family reachable from the JS cast_as vocabulary, plus
// bool (storage-only) and json (SteVec).
const v3Config: EncryptConfig = {
  v: 1,
  tables: {
    v3users: {
      // text_search: unique + ore + match -> hm + ob + bf
      email: {
        cast_as: 'text',
        indexes: { unique: {}, ore: {}, match: {} },
      },
      // text_eq: unique only -> hm
      name: {
        cast_as: 'text',
        indexes: { unique: {} },
      },
      // int2_ord_ore
      age: {
        cast_as: 'small_int',
        indexes: { ore: {} },
      },
      // int4_ord_ore
      count: {
        cast_as: 'int',
        indexes: { ore: {} },
      },
      // int8_eq
      score: {
        cast_as: 'bigint',
        indexes: { unique: {} },
      },
      // float8_ord_ore
      weight: {
        cast_as: 'number',
        indexes: { ore: {} },
      },
      // numeric_ord_ore
      price: {
        cast_as: 'decimal',
        indexes: { ore: {} },
      },
      // date_ord_ore
      dob: {
        cast_as: 'date',
        indexes: { ore: {} },
      },
      // timestamp_ord_ore
      created_at: {
        cast_as: 'timestamp',
        indexes: { ore: {} },
      },
      // bool (storage-only)
      active: {
        cast_as: 'boolean',
      },
      // json (SteVec document)
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'v3users/profile' } },
      },
    },
  },
}

function expectV3Scalar(payload: unknown): Record<string, unknown> {
  const p = payload as Record<string, unknown>
  expect(p.v).toBe(3)
  expect(p.k).toBeUndefined()
  expect(p.i).toBeTypeOf('object')
  expect(p.c).toBeTypeOf('string')
  return p
}

function expectV3SteVec(payload: unknown): SteVecDocument {
  const p = payload as Record<string, unknown>
  expect(p.v).toBe(3)
  // Unlike v3 scalars, SteVec documents keep the k form discriminator.
  expect(p.k).toBe('sv')
  expect(p.i).toBeTypeOf('object')
  expect(Array.isArray(p.sv)).toBe(true)
  return payload as SteVecDocument
}

describe('eql v3 scalar round-trips', async () => {
  const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  type ScalarCase = {
    column: string
    plaintext: string | number | boolean
    /** term keys the selected domain requires (beyond v/i/c) */
    terms: string[]
    /** keys that must NOT be present (dropped by the domain) */
    absent?: string[]
  }

  const cases: ScalarCase[] = [
    // text_search carries all three terms
    { column: 'email', plaintext: 'v3@example.com', terms: ['hm', 'ob', 'bf'] },
    // text_eq carries hm only
    { column: 'name', plaintext: 'Ada', terms: ['hm'], absent: ['ob', 'bf'] },
    // non-text _ord_ore domains carry ob only
    { column: 'age', plaintext: 42, terms: ['ob'], absent: ['hm', 'bf'] },
    { column: 'count', plaintext: 123456, terms: ['ob'], absent: ['hm', 'bf'] },
    {
      column: 'score',
      plaintext: 9007199254740,
      terms: ['hm'],
      absent: ['ob', 'bf'],
    },
    { column: 'weight', plaintext: 72.5, terms: ['ob'], absent: ['hm', 'bf'] },
    { column: 'price', plaintext: 19.99, terms: ['ob'], absent: ['hm', 'bf'] },
    // bool is storage-only
    {
      column: 'active',
      plaintext: true,
      terms: [],
      absent: ['hm', 'ob', 'bf'],
    },
  ]

  test.each(cases)(
    'round-trips $column with required terms',
    async ({ column, plaintext, terms, absent }) => {
      const ciphertext = await encrypt(client, {
        plaintext,
        column,
        table: 'v3users',
      })

      const payload = expectV3Scalar(ciphertext)
      for (const term of terms) {
        expect(payload[term], `term ${term} required`).toBeDefined()
      }
      for (const term of absent ?? []) {
        expect(payload[term], `term ${term} must be dropped`).toBeUndefined()
      }

      const decrypted = await decrypt(client, { ciphertext })
      if (typeof plaintext === 'number' && !Number.isInteger(plaintext)) {
        // decimal decrypts to a string representation
        expect(Number(decrypted)).toBeCloseTo(plaintext)
      } else {
        expect(decrypted).toBe(plaintext)
      }
    },
  )

  test('round-trips a date column', async () => {
    const d = new Date('2024-03-01T00:00:00.000Z')
    const ciphertext = await encrypt(client, {
      plaintext: d.toISOString(),
      column: 'dob',
      table: 'v3users',
    })

    expect(expectV3Scalar(ciphertext).ob).toBeDefined()

    const decrypted = await decrypt(client, { ciphertext })
    expect(new Date(decrypted as string).toISOString().slice(0, 10)).toBe(
      '2024-03-01',
    )
  })

  test('round-trips a timestamp column', async () => {
    const d = new Date('2024-03-01T12:34:56.000Z')
    const ciphertext = await encrypt(client, {
      plaintext: d.toISOString(),
      column: 'created_at',
      table: 'v3users',
    })

    expect(expectV3Scalar(ciphertext).ob).toBeDefined()

    const decrypted = await decrypt(client, { ciphertext })
    expect(new Date(decrypted as string).toISOString()).toBe(d.toISOString())
  })

  test('match-indexed text emits bf as signed 16-bit numbers', async () => {
    const ciphertext = await encrypt(client, {
      plaintext: 'the quick brown fox jumps over the lazy dog',
      column: 'email',
      table: 'v3users',
    })

    const bf = expectV3Scalar(ciphertext).bf as number[]
    expect(Array.isArray(bf)).toBe(true)
    expect(bf.length).toBeGreaterThan(0)
    for (const bit of bf) {
      expect(typeof bit).toBe('number')
      expect(Number.isInteger(bit)).toBe(true)
      expect(bit).toBeGreaterThanOrEqual(-32768)
      expect(bit).toBeLessThanOrEqual(32767)
    }
  })

  test('encryptBulk returns v3 payloads and decryptBulk round-trips them', async () => {
    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
        { plaintext: 'bulk@example.com', column: 'email', table: 'v3users' },
        { plaintext: 7, column: 'count', table: 'v3users' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expectV3Scalar(ciphertext)
    }

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })
    expect(decrypted).toEqual(['bulk@example.com', 7])
  })

  test('decryptBulkFallible reports a bad payload without failing the batch', async () => {
    const good = await encrypt(client, {
      plaintext: 'fallible@example.com',
      column: 'email',
      table: 'v3users',
    })

    const results = await decryptBulkFallible(client, {
      ciphertexts: [
        { ciphertext: good },
        // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid payload
        { ciphertext: { random: 'data' } as any },
      ],
    })

    expect(results[0]).toEqual({ data: 'fallible@example.com' })
    expect(results[1]).toHaveProperty('error')
  })
})

describe('eql v3 ste_vec round-trip', async () => {
  const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('encrypts json to a SteVecDocument and decrypts sv[0].c back', async () => {
    const profile = { role: 'admin', level: 3, tags: ['a', 'b'] }

    const ciphertext = await encrypt(client, {
      plaintext: profile,
      column: 'profile',
      table: 'v3users',
    })

    const doc = expectV3SteVec(ciphertext)
    expect(doc.sv.length).toBeGreaterThan(0)
    for (const entry of doc.sv) {
      expect(entry.s).toBeTypeOf('string')
      expect(entry.c).toBeTypeOf('string')
      const term = entry as unknown as Record<string, unknown>
      expect(
        ('hm' in term && term.hm !== undefined) !==
          ('oc' in term && term.oc !== undefined),
        'exactly one of hm/oc per entry',
      ).toBe(true)
    }

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(profile)
  })
})

describe('eql v3 query encryption', async () => {
  const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('containment query returns the jsonb_query needle', async () => {
    const result = (await encryptQuery(client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_term',
    })) as SteVecQuery & Record<string, unknown>

    // The needle has no envelope and no per-entry ciphertexts.
    expect(result.v).toBeUndefined()
    expect(result.i).toBeUndefined()
    expect(result.k).toBeUndefined()
    expect(Array.isArray(result.sv)).toBe(true)
    for (const entry of result.sv) {
      expect(entry.s).toBeTypeOf('string')
      const e = entry as unknown as Record<string, unknown>
      expect(e.c).toBeUndefined()
      expect(e.hm !== undefined || e.oc !== undefined).toBe(true)
    }
  })

  test('containment query via default queryOp with an object also converts', async () => {
    const result = (await encryptQuery(client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
    })) as Record<string, unknown>

    expect(result.v).toBeUndefined()
    expect(Array.isArray(result.sv)).toBe(true)
  })

  test('scalar query returns a typed error', async () => {
    const attempt = encryptQuery(client, {
      plaintext: 'v3@example.com',
      column: 'email',
      table: 'v3users',
      indexType: 'unique',
    })

    await expect(attempt).rejects.toThrowError(ProtectError)
    await expect(attempt).rejects.toMatchObject({
      code: 'EQL_V3_QUERY_UNSUPPORTED',
    })
    await expect(attempt).rejects.toThrowError(/eqlVersion 2/)
  })

  test('selector query returns a typed error', async () => {
    const attempt = encryptQuery(client, {
      plaintext: '$.role',
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector',
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'EQL_V3_QUERY_UNSUPPORTED',
    })
  })
})

describe('isEncrypted', async () => {
  const v2Client = await newClient({ encryptConfig: v3Config })
  const v3Client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('recognises v2 payloads', async () => {
    const ciphertext = await encrypt(v2Client, {
      plaintext: 'v2@example.com',
      column: 'email',
      table: 'v3users',
    })
    expect(isEncrypted(ciphertext)).toBe(true)
  })

  test('recognises v3 payloads', async () => {
    const scalar = await encrypt(v3Client, {
      plaintext: 'v3@example.com',
      column: 'email',
      table: 'v3users',
    })
    const steVec = await encrypt(v3Client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
    })
    expect(isEncrypted(scalar)).toBe(true)
    expect(isEncrypted(steVec)).toBe(true)
  })

  test('rejects plaintext and garbage', () => {
    expect(isEncrypted('some plaintext')).toBe(false)
    expect(isEncrypted(42)).toBe(false)
    expect(isEncrypted(null)).toBe(false)
    expect(isEncrypted({ random: 'data' })).toBe(false)
    expect(isEncrypted({ v: 2, i: { t: 'users', c: 'email' } })).toBe(false)
  })
})

describe('mixed-version decrypt (data migration)', async () => {
  const v2Client = await newClient({ encryptConfig: v3Config })
  const v3Client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('a v3 client decrypts v2 payloads', async () => {
    const ciphertext = await encrypt(v2Client, {
      plaintext: 'migrate-me',
      column: 'email',
      table: 'v3users',
    })
    expect((ciphertext as Record<string, unknown>).k).toBe('ct')

    const decrypted = await decrypt(v3Client, { ciphertext })
    expect(decrypted).toBe('migrate-me')
  })

  test('a v2 client decrypts v3 payloads', async () => {
    const ciphertext = await encrypt(v3Client, {
      plaintext: 'migrate-me-back',
      column: 'email',
      table: 'v3users',
    })
    expect((ciphertext as Record<string, unknown>).v).toBe(3)

    const decrypted = await decrypt(v2Client, { ciphertext })
    expect(decrypted).toBe('migrate-me-back')
  })

  test('a v2 client decrypts v3 SteVec documents', async () => {
    const profile = { migrated: true }
    const ciphertext = await encrypt(v3Client, {
      plaintext: profile,
      column: 'profile',
      table: 'v3users',
    })

    const decrypted = await decrypt(v2Client, { ciphertext })
    expect(decrypted).toEqual(profile)
  })

  test('decryptBulk round-trips a mixed v2 + v3 batch', async () => {
    const v2Ciphertext = await encrypt(v2Client, {
      plaintext: 'still-v2',
      column: 'email',
      table: 'v3users',
    })
    const v3Ciphertext = await encrypt(v3Client, {
      plaintext: 'already-v3',
      column: 'email',
      table: 'v3users',
    })
    expect((v2Ciphertext as Record<string, unknown>).k).toBe('ct')
    expect((v3Ciphertext as Record<string, unknown>).v).toBe(3)

    const decrypted = await decryptBulk(v3Client, {
      ciphertexts: [{ ciphertext: v2Ciphertext }, { ciphertext: v3Ciphertext }],
    })
    expect(decrypted).toEqual(['still-v2', 'already-v3'])
  })

  test('decryptBulkFallible round-trips a mixed v3 + v2 batch', async () => {
    const v3Ciphertext = await encrypt(v3Client, {
      plaintext: 'fallible-v3',
      column: 'email',
      table: 'v3users',
    })
    const v2Ciphertext = await encrypt(v2Client, {
      plaintext: 'fallible-v2',
      column: 'email',
      table: 'v3users',
    })

    const results = await decryptBulkFallible(v2Client, {
      ciphertexts: [{ ciphertext: v3Ciphertext }, { ciphertext: v2Ciphertext }],
    })
    expect(results).toEqual([{ data: 'fallible-v3' }, { data: 'fallible-v2' }])
  })
})

describe('eql v3 configuration errors', () => {
  test('newClient rejects an invalid eqlVersion', async () => {
    const attempt = newClient({
      encryptConfig: v3Config,
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid
      eqlVersion: 4 as any,
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'INVALID_EQL_VERSION',
    })
  })

  test('encrypting an indexed boolean under v3 fails with a hint', async () => {
    const config: EncryptConfig = {
      v: 1,
      tables: {
        v3users: {
          flagged: { cast_as: 'boolean', indexes: { unique: {} } },
        },
      },
    }
    const client = await newClient({ encryptConfig: config, eqlVersion: 3 })

    const attempt = encrypt(client, {
      plaintext: true,
      column: 'flagged',
      table: 'v3users',
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'EQL_V3_UNSUPPORTED_COLUMN',
    })
    await expect(attempt).rejects.toThrowError(/storage-only/)
  })

  test('encrypting ordered-only text under v3 fails with a hint', async () => {
    const config: EncryptConfig = {
      v: 1,
      tables: {
        v3users: {
          ranked: { cast_as: 'text', indexes: { ore: {} } },
        },
      },
    }
    const client = await newClient({ encryptConfig: config, eqlVersion: 3 })

    const attempt = encrypt(client, {
      plaintext: 'zzz',
      column: 'ranked',
      table: 'v3users',
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'EQL_V3_UNSUPPORTED_COLUMN',
    })
    await expect(attempt).rejects.toThrowError(/unique/)
  })

  // Typed as EncryptedV3 so tsc verifies the exported union is usable.
  test('the EncryptedV3 union types v3 payloads', async () => {
    const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })
    const ciphertext = (await encrypt(client, {
      plaintext: 'typed',
      column: 'name',
      table: 'v3users',
    })) as EncryptedV3

    expect(ciphertext.v).toBe(3)
  })
})
