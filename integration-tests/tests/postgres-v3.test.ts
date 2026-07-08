import 'dotenv/config'
import { beforeAll, beforeEach, describe, expect, test } from 'vitest'
import {
  decrypt,
  decryptBulk,
  encrypt,
  encryptBulk,
  newClient,
  type EncryptConfig,
  type EncryptedPayload,
  type IntegerOrdOpe,
  type IntegerOrdOre,
  type TextEq,
} from '@cipherstash/protect-ffi'
import { Client, type QueryResult } from 'pg'
import { v3WireKeys } from './common'

// Requires the eql_v3 schema: `mise run eql:v3:install` (part of `mise
// setup`) installs the committed snapshot sql/cipherstash-encrypt-v3.sql.
// There is no v3 release artifact yet — refresh the snapshot from a sibling
// encrypt-query-language checkout with `mise run eql:v3:build`.
//
// The config -> eql_v3 domain mapping is asserted, not assumed: each
// payload's exact key set is checked against the vendored domain type
// before INSERT (below), and the live domain CHECK on the eql_v3.text_eq /
// eql_v3.integer_ord_ore / eql_v3.integer_ord_ope columns validates the
// required keys on INSERT.
const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    v3pg: {
      email: {
        cast_as: 'text',
        indexes: { unique: {} },
      },
      score: {
        cast_as: 'int',
        indexes: { ore: {} },
      },
      rank: {
        cast_as: 'int',
        indexes: { ope: {} },
      },
    },
  },
}

// Exact wire key sets, compile-time-checked against the vendored eql_v3
// domain types (see v3WireKeys).
const textEqKeys = v3WireKeys<TextEq>()('v', 'i', 'c', 'hm')
const integerOrdOreKeys = v3WireKeys<IntegerOrdOre>()('v', 'i', 'c', 'ob')
const integerOrdOpeKeys = v3WireKeys<IntegerOrdOpe>()('v', 'i', 'c', 'op')

describe('postgres eql_v3', () => {
  // Vitest does not await the `describe` callback, so an `async describe` with
  // top-level `await`s can finish collection before they resolve — leaving the
  // hooks and tests below unregistered. Client + connection setup therefore
  // lives in `beforeAll` (an async lifecycle hook), with teardown returned
  // from it (Vitest runs the returned fn as `afterAll`).
  const pg = new Client()
  let protectClient: Awaited<ReturnType<typeof newClient>>

  beforeAll(async () => {
    protectClient = await newClient({ encryptConfig, eqlVersion: 3 })
    await pg.connect()

    await pg.query('DROP TABLE IF EXISTS encrypted_v3')

    await pg.query(`
      CREATE TABLE encrypted_v3 (
        id SERIAL PRIMARY KEY,
        email eql_v3.text_eq,
        score eql_v3.integer_ord_ore,
        rank eql_v3.integer_ord_ope
      )
    `)

    return async () => {
      await pg.query('DROP TABLE encrypted_v3')
      await pg.end()
    }
  })

  beforeEach(async () => {
    await pg.query('BEGIN')
    return async () => {
      await pg.query('ROLLBACK')
    }
  })

  test('the domain CHECK accepts protect-ffi v3 output', async () => {
    const email = await encrypt(protectClient, {
      plaintext: 'check@example.com',
      column: 'email',
      table: 'v3pg',
    })
    const score = await encrypt(protectClient, {
      plaintext: 10,
      column: 'score',
      table: 'v3pg',
    })

    // The INSERT below proves the domain CHECKs accept the payloads (the
    // required keys are present); these exact-set assertions additionally
    // prove nothing extra was provisioned — a CHECK does not reject a
    // payload that selected a richer domain than the config asked for.
    expect(Object.keys(email).sort()).toEqual(textEqKeys)
    expect(Object.keys(score).sort()).toEqual(integerOrdOreKeys)

    await pg.query(
      'INSERT INTO encrypted_v3 (email, score) VALUES ($1::jsonb, $2::jsonb)',
      [email, score],
    )

    const res: QueryResult<{
      email: EncryptedPayload
      score: EncryptedPayload
    }> = await pg.query('SELECT email::jsonb, score::jsonb FROM encrypted_v3')

    expect(res.rowCount).toBe(1)
    expect(
      await decrypt(protectClient, { ciphertext: res.rows[0].email }),
    ).toBe('check@example.com')
    expect(
      await decrypt(protectClient, { ciphertext: res.rows[0].score }),
    ).toBe(10)
  })

  test('the domain CHECK rejects a v2 payload', async () => {
    const v2Client = await newClient({ encryptConfig })
    const v2Email = await encrypt(v2Client, {
      plaintext: 'v2@example.com',
      column: 'email',
      table: 'v3pg',
    })

    await expect(
      pg.query('INSERT INTO encrypted_v3 (email) VALUES ($1::jsonb)', [
        v2Email,
      ]),
    ).rejects.toThrowError()
    // The failed INSERT aborts the wrapping transaction; reset it so the
    // beforeEach ROLLBACK still succeeds.
    await pg.query('ROLLBACK')
    await pg.query('BEGIN')
  })

  test('ORDER BY the ord extractor sorts by plaintext order', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 30, column: 'score', table: 'v3pg' },
        { plaintext: 10, column: 'score', table: 'v3pg' },
        { plaintext: 20, column: 'score', table: 'v3pg' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expect(Object.keys(ciphertext).sort()).toEqual(integerOrdOreKeys)
    }

    await pg.query(
      'INSERT INTO encrypted_v3 (score) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ score: EncryptedPayload }> = await pg.query(`
      SELECT score::jsonb FROM encrypted_v3
      ORDER BY eql_v3.ord_term(score) ASC
    `)

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.score })),
    })
    expect(decrypted).toEqual([10, 20, 30])
  })

  test('equality via the hm extractor finds the matching row', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 'a@example.com', column: 'email', table: 'v3pg' },
        { plaintext: 'b@example.com', column: 'email', table: 'v3pg' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expect(Object.keys(ciphertext).sort()).toEqual(textEqKeys)
    }

    await pg.query(
      'INSERT INTO encrypted_v3 (email) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const needle = await encrypt(protectClient, {
      plaintext: 'b@example.com',
      column: 'email',
      table: 'v3pg',
    })

    const res: QueryResult<{ email: EncryptedPayload }> = await pg.query(
      `
      SELECT email::jsonb FROM encrypted_v3
      WHERE eql_v3.eq_term(email) = eql_v3.eq_term($1::jsonb::eql_v3.text_eq)
      `,
      [needle],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.email })),
    })
    expect(decrypted).toEqual(['b@example.com'])
  })

  // Real-ciphertext _ord_ope coverage (CIP-3348): cipherstash-client 0.38.1
  // emits the scalar `op` (CLLW-OPE) term, so an `ope`-indexed column can be
  // produced end-to-end (0.38.0 dropped the term at encrypt time).
  test('ORDER BY the ord_ope extractor sorts by plaintext order', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 30, column: 'rank', table: 'v3pg' },
        { plaintext: 10, column: 'rank', table: 'v3pg' },
        { plaintext: 20, column: 'rank', table: 'v3pg' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expect(Object.keys(ciphertext).sort()).toEqual(integerOrdOpeKeys)
    }

    await pg.query(
      'INSERT INTO encrypted_v3 (rank) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ rank: EncryptedPayload }> = await pg.query(`
      SELECT rank::jsonb FROM encrypted_v3
      ORDER BY eql_v3.ord_ope_term(rank) ASC
    `)

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.rank })),
    })
    expect(decrypted).toEqual([10, 20, 30])
  })
})
