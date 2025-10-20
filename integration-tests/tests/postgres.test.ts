import 'dotenv/config'
import { describe, expect, test, beforeAll, beforeEach } from 'vitest'
import {
  decrypt,
  encrypt,
  newClient,
  encryptBulk,
  decryptBulk,
  type Encrypted,
  type EncryptConfig,
  EncryptedSV,
  EncryptedCT,
  SteVecEncryptedEntry,
  EncryptedSVE,
} from '@cipherstash/protect-ffi'
import { Client, type QueryResult } from 'pg'
import { encryptQuery } from '../../lib/load.cjs'

describe('postgres', async () => {
  const protectClient = await newClient({ encryptConfig: encryptConfig() })
  const pg = new Client()
  await pg.connect()

  // called once before all tests run
  beforeAll(async () => {
    await pg.query('DROP TABLE IF EXISTS encrypted')

    await pg.query(`
      CREATE TABLE encrypted (
        id SERIAL PRIMARY KEY,
        encrypted_text eql_v2_encrypted,
        encrypted_score eql_v2_encrypted,
        encrypted_profile eql_v2_encrypted
      )
    `)

    await pg.query(
      "SELECT eql_v2.add_encrypted_constraint('encrypted', 'encrypted_text')",
    )
    await pg.query(
      "SELECT eql_v2.add_encrypted_constraint('encrypted', 'encrypted_score')",
    )
    // FIXME: This doesn't work for ste_vec - should there be a different function?
    //await pg.query(
    //  "SELECT eql_v2.add_encrypted_constraint('encrypted', 'encrypted_profile')",
    //)

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
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb)',
      [ciphertext],
    )

    const res: QueryResult<{ encrypted_text: EncryptedCT }> = await pg.query(
      'SELECT encrypted_text::jsonb FROM encrypted',
    )

    expect(res.rowCount).toBe(1)

    const decrypted = await decrypt(protectClient, {
      ciphertext: res.rows[0].encrypted_text,
    })

    expect(decrypted).toBe(originalPlaintext)
  })

  test('can order by an ORE index', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
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
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(`
      SELECT encrypted_text::jsonb FROM encrypted
      ORDER BY eql_v2.order_by(encrypted_text) ASC
    `)

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_text,
      })),
    })

    expect(decrypted).toEqual(['aaa', 'bbb', 'ccc'])
  })

  test('can use a match query', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
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
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const search = await encryptQuery(protectClient, {
      plaintext: 'ccc',
      column: 'email',
      table: 'users',
      operator: '~~',
    })

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(
      `
      SELECT encrypted_text::jsonb FROM encrypted
      WHERE encrypted_text LIKE $1::jsonb
      `,
      [search],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_text,
      })),
    })

    expect(decrypted).toEqual(['aaa ccc'])
  })

  test('can use an ORE query', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: 1000,
          column: 'score',
          table: 'users',
        },
        {
          plaintext: 75,
          column: 'score',
          table: 'users',
        },
        {
          plaintext: 888,
          column: 'score',
          table: 'users',
        },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_score) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const search = await encryptQuery(protectClient, {
      plaintext: 500,
      column: 'score',
      table: 'users',
      operator: '>=',
    })

    const res: QueryResult<{ encrypted_score: Encrypted }> = await pg.query(
      `
      SELECT encrypted_score::jsonb FROM encrypted
      WHERE encrypted_score >= $1::jsonb ORDER BY eql_v2.order_by(encrypted_score) ASC
      `,
      [search],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_score,
      })),
    })

    expect(decrypted).toEqual([888, 1000])
  })

  test('can use an exact query', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
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
      ],
    })

    await pg.query(
      'INSERT INTO encrypted (encrypted_text) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const query = await encryptQuery(protectClient, {
      plaintext: 'b',
      column: 'email',
      table: 'users',
      operator: '=',
    });

    const res: QueryResult<{ encrypted_text: Encrypted }> = await pg.query(
      `
      SELECT encrypted_text::jsonb FROM encrypted
      WHERE encrypted_text = $1::jsonb
      `,
      [query],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({
        ciphertext: row.encrypted_text,
      })),
    })

    expect(decrypted).toEqual(['b'])
  })

  test.only('can use JSON stabby ->', async () => {
    const toStore = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: { foo: 'bar', baz: [1, 2, 3] },
          column: 'profile',
          table: 'users',
        },
        {
          plaintext: { foo: 'baz', qux: [4, 5, 6] },
          column: 'profile',
          table: 'users',
        },
        {
          plaintext: { other: 'foo' },
          column: 'profile',
          table: 'users',
        },
      ],
    })

    console.log("Ciphertexts:", JSON.stringify(toStore[0]));

    await pg.query(
      'INSERT INTO encrypted (encrypted_profile) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      toStore,
    )

    const query = await encryptQuery(protectClient, {
      // FIXME: The first form fails (the selector doesn't map correctly)
      // See JsonIndexer::tokenize_selector (the Dot variant behaves differently)
      //plaintext: "$.foo",
      plaintext: "$['foo']",
      column: 'profile',
      table: 'users',
      operator: '->',
    });

    console.log("Query:", query);

    const res1: QueryResult<{ encrypted_profile: EncryptedSV }> = await pg.query(
      `
      SELECT encrypted_profile::jsonb FROM encrypted
      `
    )

    res1.rows[0].encrypted_profile.sv.forEach((entry) => {
      console.log("Selector:", entry.s);
    });

    // Or jsonb_path_query
    // eql_v2.jsonb_path_query(encrypted_profile, $1)

    // TODO: Use the jsonquery approach from the Json indexer docs
    //SELECT eql_v2."->"(encrypted_profile, eql_v2.selector($1::jsonb))::jsonb as value FROM encrypted
    const res: QueryResult<{ value: SteVecEncryptedEntry | null }> = await pg.query(
      `
      SELECT (encrypted_profile->eql_v2.selector($1::jsonb))::jsonb as value FROM encrypted
      `,
      [query],
    )

    console.log("ROWS:", res.rows[0].value);
    let ciphertexts = res.rows.flatMap((row) => (row.value === null ? [] : [{
        ciphertext: { k: 'sve', sve: row.value } as EncryptedSVE,
      }]));

    console.log("Ciphertexts:", JSON.stringify(ciphertexts));
    const decrypted = await decryptBulk(protectClient, {
      ciphertexts,
    })
    //const decrypted = await decrypt(protectClient, ciphertexts[0])
   //expect(decrypted).toEqual('bar')
   // FIXME: we should handle null as an input and just return null
   expect(decrypted).toEqual(['bar', 'baz'])
  })
})

// TODO: Load the config from common
function encryptConfig(): EncryptConfig {
  return {
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
        score: {
          cast_as: 'double',
          indexes: { ore: {} },
        },
        profile: {
          cast_as: 'jsonb',
          indexes: { ste_vec: { prefix: 'users/profile' } },
        },
      },
    },
  }
}
