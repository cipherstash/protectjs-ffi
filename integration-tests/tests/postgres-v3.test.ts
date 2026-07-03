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
} from '@cipherstash/protect-ffi'
import { Client, type QueryResult } from 'pg'

// Requires the eql_v3 schema: `mise run eql:v3:install` (part of `mise
// setup`) installs the committed snapshot sql/cipherstash-encrypt-v3.sql.
// There is no v3 release artifact yet — refresh the snapshot from a sibling
// encrypt-query-language checkout with `mise run eql:v3:build`.
const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    v3pg: {
      // eql_v3.text_eq (hm)
      email: {
        cast_as: 'text',
        indexes: { unique: {} },
      },
      // eql_v3.int4_ord_ore (ob)
      score: {
        cast_as: 'int',
        indexes: { ore: {} },
      },
    },
  },
}

describe('postgres eql_v3', async () => {
  const protectClient = await newClient({ encryptConfig, eqlVersion: 3 })
  const pg = new Client()
  await pg.connect()

  beforeAll(async () => {
    await pg.query('DROP TABLE IF EXISTS encrypted_v3')

    await pg.query(`
      CREATE TABLE encrypted_v3 (
        id SERIAL PRIMARY KEY,
        email eql_v3.text_eq,
        score eql_v3.int4_ord_ore
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

  // cipherstash-client 0.38.0 does not emit the `op` (CLLW-OPE) term —
  // CIP-3280 is unreleased — so an `ope`-indexed column fails at encrypt
  // time with a MissingTerm error and no _ord_ope payload can be produced
  // end-to-end yet.
  test.skip('ORDER BY on an eql_v3.int4_ord_ope column (blocked on CIP-3280: client 0.38.0 does not emit op)', () => {})
})
