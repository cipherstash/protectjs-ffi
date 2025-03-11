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
    // called once before all tests run
    await pg.query(`
      CREATE TABLE encrypted (
        id SERIAL PRIMARY KEY,
        encrypted_text cs_encrypted_v1
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

    const ciphertext = await encrypt(
      protectClient,
      originalPlaintext,
      'email',
      'users',
    )

    await pg.query('INSERT INTO encrypted (encrypted_text) VALUES ($1)', [
      ciphertext,
    ])

    const res = await pg.query('SELECT * FROM encrypted')

    expect(res.rowCount).toBe(1)

    const decrypted = await decrypt(protectClient, res.rows[0].encrypted_text.c)

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
      'INSERT INTO encrypted (encrypted_text) VALUES ($1), ($2), ($3)',
      ciphertexts,
    )

    const res = await pg.query(`
      SELECT encrypted_text FROM encrypted
      ORDER BY cs_ore_64_8_v1(encrypted_text)
    `)

    const decrypted = await decryptBulk(
      protectClient,
      res.rows.map((row) => ({ ciphertext: row.encrypted_text.c })),
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
      'INSERT INTO encrypted (encrypted_text) VALUES ($1), ($2)',
      ciphertexts,
    )

    const res = await pg.query(
      `
      SELECT encrypted_text FROM encrypted
      WHERE cs_match_v1(encrypted_text) @> cs_match_v1($1)
      `,
      [await encrypt(protectClient, 'ccc', 'email', 'users')],
    )

    const decrypted = await decryptBulk(
      protectClient,
      res.rows.map((row) => ({ ciphertext: row.encrypted_text.c })),
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
      'INSERT INTO encrypted (encrypted_text) VALUES ($1), ($2)',
      ciphertexts,
    )

    const res = await pg.query(
      `
      SELECT encrypted_text FROM encrypted
      WHERE cs_unique_v1(encrypted_text) = cs_unique_v1($1)
      `,
      [await encrypt(protectClient, 'b', 'email', 'users')],
    )

    const decrypted = await decryptBulk(
      protectClient,
      res.rows.map((row) => ({ ciphertext: row.encrypted_text.c })),
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
