import 'dotenv/config'
import { describe, expect, test, beforeAll, beforeEach } from 'vitest'
import {
  decrypt,
  encrypt,
  newClient,
  encryptBulk,
  decryptBulk,
} from '@cipherstash/protect-ffi'
import { Client } from 'pg'

describe('postgres', async () => {
  const protectClient = await newClient(encryptConfig())
  const pg = new Client()
  await pg.connect()

  beforeAll(async () => {
    await pg.query('DROP TABLE IF EXISTS encrypted')

    // called once before all tests run
    await pg.query(`
      CREATE TABLE encrypted (
        id SERIAL PRIMARY KEY,
        encrypted_text eql_v2_encrypted
      )
    `)

    // clean up function, called once after all tests run
    return async () => {
      await pg.query('DROP TABLE ENCRYPTED')
      await pg.end()
    }
  })

  beforeEach(async () => {
    // called once before each test run
    await pg.query('BEGIN')

    // clean up function, called once after each test run
    return async () => {
      await pg.query('ROLLBACK')
    }
  })

  test('can round-trip encrypt and decrypt', async () => {
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(protectClient, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb::eql_v2_encrypted)',
      [ciphertext],
    )

    const res = await pg.query('SELECT encrypted_text::jsonb FROM encrypted')

    expect(res.rowCount).toBe(1)

    console.log('res.rows[0].encrypted_text', res.rows[0])

    const decrypted = await decrypt(
      protectClient,
      res.rows[0].encrypted_text.data.c,
    )

    expect(decrypted).toBe(originalPlaintext)
  })

  test('can order by an ORE index', async () => {
    const ciphertexts = await encryptBulk(protectClient, [
      {
        plaintext: 'ccc',
        column: 'email',
        table: 'users',
      },
      {
        plaintext: 'aaa',
        column: 'email',
        table: 'users',
      },
      {
        plaintext: 'bbb',
        column: 'email',
        table: 'users',
      },
    ])

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb::eql_v2_encrypted), ($2::jsonb::eql_v2_encrypted), ($3::jsonb::eql_v2_encrypted)',
      ciphertexts,
    )

    const res = await pg.query(`
      SELECT encrypted_text FROM encrypted
      ORDER BY eql_v2.order_by(encrypted_text) ASC
    `)

    const decrypted = await decryptBulk(
      protectClient,
      res.rows.map((row) => ({ ciphertext: row.encrypted_text.data.c })),
    )

    expect(decrypted).toEqual(['aaa', 'bbb', 'ccc'])
  })

  test('can use a match query', async () => {
    const ciphertexts = await encryptBulk(protectClient, [
      {
        plaintext: 'aaa bbb',
        column: 'email',
        table: 'users',
      },
      {
        plaintext: 'aaa ccc',
        column: 'email',
        table: 'users',
      },
    ])

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb::eql_v2_encrypted), ($2::jsonb::eql_v2_encrypted)',
      ciphertexts,
    )

    const search = await encrypt(protectClient, {
      plaintext: 'ccc',
      column: 'email',
      table: 'users',
    })

    const res = await pg.query(
      `
      SELECT encrypted_text::jsonb FROM encrypted
      WHERE encrypted_text LIKE $1::jsonb::eql_v2_encrypted
      `,
      [search.data],
    )

    const decrypted = await decryptBulk(
      protectClient,
      res.rows.map((row) => ({ ciphertext: row.encrypted_text.data.c })),
    )

    expect(decrypted).toEqual(['aaa ccc'])
  })

  test('can use an exact query', async () => {
    const ciphertexts = await encryptBulk(protectClient, [
      {
        plaintext: 'a',
        column: 'email',
        table: 'users',
      },
      {
        plaintext: 'b',
        column: 'email',
        table: 'users',
      },
    ])

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb::eql_v2_encrypted), ($2::jsonb::eql_v2_encrypted)',
      ciphertexts,
    )

    const res = await pg.query(
      `
      SELECT encrypted_text::jsonb FROM encrypted
      WHERE encrypted_text = $1::jsonb::eql_v2_encrypted
      `,
      [
        await encrypt(protectClient, {
          plaintext: 'b',
          column: 'email',
          table: 'users',
        }),
      ],
    )

    const decrypted = await decryptBulk(
      protectClient,
      res.rows.map((row) => ({ ciphertext: row.encrypted_text.data.c })),
    )

    expect(decrypted).toEqual(['b'])
  })
})

function encryptConfig() {
  return JSON.stringify({
    v: 1,
    tables: {
      users: {
        email: {
          indexes: {
            ore: {},
            match: {
              tokenizer: {
                kind: 'ngram',
                token_length: 3,
              },
              token_filters: [
                {
                  kind: 'downcase',
                },
              ],
              k: 6,
              m: 2048,
              include_original: false,
            },
            unique: {},
          },
        },
      },
    },
  })
}
