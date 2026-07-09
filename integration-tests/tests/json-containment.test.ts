import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type EncryptPayload,
  type QueryPayload,
  encryptBulk,
  encryptQuery,
  encryptQueryBulk,
  newClient,
} from '@cipherstash/protect-ffi'

import { assertSteVec, jsonSteVec } from './common.js'

/**
 * JSON Containment Investigation Tests
 *
 * These tests investigate and verify the behavior of:
 * 1. `encryptBulk` output structure for nested JSON with ste_vec indexes
 * 2. `encryptQueryBulk` with `ste_vec_term` queryOp for containment queries (@>, <@)
 * 3. Differences between storage encryption and query encryption
 *
 * The FFI handles JSON flattening internally via the Rust cipherstash-client library.
 */

const profileColumn = {
  table: 'users',
  column: 'profile',
} as const

describe('encryptBulk output structure for nested JSON', () => {
  test('encryptBulk returns sv array for nested JSON', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const plaintexts: EncryptPayload[] = [
      {
        plaintext: { user: { role: 'admin', level: 5 } },
        ...profileColumn,
      },
    ]

    const result = await encryptBulk(client, { plaintexts })

    // Verify we got a result
    expect(result).toHaveLength(1)
    const encrypted = result[0]

    assertSteVec(encrypted)
    expect(encrypted).toHaveProperty('sv')
    expect(Array.isArray(encrypted.sv)).toBe(true)

    const sv = encrypted.sv
    if (!sv) throw new Error('sv should be defined')

    expect(sv.length).toBeGreaterThan(0)

    // EQL v2.3: SteVec storage places the root ciphertext at sv[0].c, not at the root.
    expect(encrypted).not.toHaveProperty('c')
    expect(sv[0]).toHaveProperty('c')

    // Verify identifier and version
    expect(encrypted).toHaveProperty('i')
    expect(encrypted).toHaveProperty('v')

    // Each entry should have selector (s) field
    for (const entry of sv) {
      expect(entry).toHaveProperty('s') // Selector (hex-encoded path)
    }

    console.log('encryptBulk nested JSON output:')
    console.log(JSON.stringify(encrypted, null, 2))
  })

  test('encryptBulk sv entries have expected index fields', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const plaintexts: EncryptPayload[] = [
      {
        plaintext: {
          name: 'alice',
          age: 30,
          active: true,
          tags: ['admin', 'moderator'],
        },
        ...profileColumn,
      },
    ]

    const result = await encryptBulk(client, { plaintexts })
    const encrypted = result[0]

    assertSteVec(encrypted)
    expect(encrypted.sv).toBeDefined()

    const sv = encrypted.sv
    if (!sv) throw new Error('sv should be defined')

    // Count entries by field presence. Under SteVec Standard mode (pinned by
    // the `jsonSteVec` fixture) numeric and string values share a single
    // orderable field `oc`, and non-orderable values (booleans, null, arrays,
    // objects) carry an `hm` HMAC.
    const withSelector = sv.filter((e) => e.s !== undefined)
    const withHmac = sv.filter((e) => e.hm !== undefined)
    const withOreCllw = sv.filter((e) => e.oc !== undefined)
    const withOpeCllw = sv.filter((e) => e.op !== undefined)
    const withArrayFlag = sv.filter((e) => e.a === true)

    console.log('SteVec entry counts:')
    console.log(`  Total entries: ${sv.length}`)
    console.log(`  With selector (s): ${withSelector.length}`)
    console.log(`  With HMAC (hm): ${withHmac.length}`)
    console.log(`  With ORE CLLW (oc): ${withOreCllw.length}`)
    console.log(`  With array flag (a): ${withArrayFlag.length}`)

    // All entries should have selectors
    expect(withSelector.length).toBe(sv.length)

    // Scalar string and numeric values produce ORE CLLW (`oc`) entries
    expect(withOreCllw.length).toBeGreaterThan(0)

    // The Compat-mode CLLW-OPE key never appears in Standard mode
    expect(withOpeCllw.length).toBe(0)

    // Non-orderable values (root object, booleans, arrays) produce HMAC (`hm`) entries
    expect(withHmac.length).toBeGreaterThan(0)

    // With default ArrayIndexMode (NONE), array elements should not have array flag
    expect(withArrayFlag.length).toBe(0)
  })

  test('encryptBulk handles deeply nested JSON', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const plaintexts: EncryptPayload[] = [
      {
        plaintext: {
          user: {
            profile: {
              settings: {
                notifications: {
                  email: true,
                  sms: false,
                },
              },
            },
          },
        },
        ...profileColumn,
      },
    ]

    const result = await encryptBulk(client, { plaintexts })
    const encrypted = result[0]

    assertSteVec(encrypted)
    expect(encrypted.sv).toBeDefined()

    const sv = encrypted.sv
    if (!sv) throw new Error('sv should be defined')

    expect(sv.length).toBeGreaterThan(0)

    console.log('Deeply nested JSON sv structure:')
    console.log(`  Total entries: ${sv.length}`)
    console.log(JSON.stringify(sv, null, 2))
  })
})

/**
 * Tests for ste_vec_term queryOp
 *
 * ste_vec_term is used for JSON containment queries (@>, <@).
 */
describe('encryptQuery/Bulk with ste_vec_term for containment', () => {
  test('encryptQuery with ste_vec_term - simple object', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQuery(client, {
      plaintext: { name: 'Alice' },
      ...profileColumn,
      indexType: 'ste_vec',
      queryOp: 'ste_vec_term',
    })

    console.log('encryptQuery ste_vec_term simple object output:')
    console.log(JSON.stringify(result, null, 2))

    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
  })

  test('encryptQueryBulk with ste_vec_term produces query structure', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const queries: QueryPayload[] = [
      {
        plaintext: { user: { role: 'admin' } },
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_term',
      },
    ]

    const result = await encryptQueryBulk(client, { queries })

    expect(result).toHaveLength(1)
    const encrypted = result[0]

    expect(encrypted).toHaveProperty('i')
    expect(encrypted).toHaveProperty('v')

    console.log('encryptQueryBulk ste_vec_term output:')
    console.log(JSON.stringify(encrypted, null, 2))
  })

  test('encryptQueryBulk ste_vec_term with nested query object', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const queries: QueryPayload[] = [
      {
        plaintext: { profile: { verified: true } },
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_term',
      },
    ]

    const result = await encryptQueryBulk(client, { queries })
    const encrypted = result[0]

    console.log('ste_vec_term nested query output:')
    console.log(JSON.stringify(encrypted, null, 2))

    expect(encrypted).toHaveProperty('i')
    expect(encrypted).toHaveProperty('v')
  })

  test('encryptQueryBulk ste_vec_term with array value', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const queries: QueryPayload[] = [
      {
        plaintext: { tags: ['admin'] },
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_term',
      },
    ]

    const result = await encryptQueryBulk(client, { queries })
    const encrypted = result[0]

    console.log('ste_vec_term array containment query output:')
    console.log(JSON.stringify(encrypted, null, 2))

    expect(encrypted).toHaveProperty('i')
    expect(encrypted).toHaveProperty('v')
  })
})

describe('compare encryptBulk vs encryptQueryBulk for JSON', () => {
  test('compare storage vs query encryption output', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })
    const jsonPayload = { user: { role: 'admin' } }

    // Storage encryption
    const stored = await encryptBulk(client, {
      plaintexts: [
        {
          plaintext: jsonPayload,
          ...profileColumn,
        },
      ],
    })

    // Query encryption with ste_vec_term
    const queried = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: jsonPayload,
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
      ],
    })

    console.log('=== STORAGE (encryptBulk) ===')
    console.log(JSON.stringify(stored[0], null, 2))

    console.log('\n=== QUERY (encryptQueryBulk with ste_vec_term) ===')
    console.log(JSON.stringify(queried[0], null, 2))

    const storedEnc = stored[0]
    const queriedEnc = queried[0]
    assertSteVec(storedEnc)
    assertSteVec(queriedEnc)

    console.log('\n=== STRUCTURAL COMPARISON ===')
    console.log(
      `Storage has 'sv[0].c' (root ciphertext): ${storedEnc.sv?.[0]?.c !== undefined}`,
    )
    console.log(
      `Query has 'sv[0].c' (root ciphertext): ${queriedEnc.sv?.[0]?.c !== undefined}`,
    )
    console.log(
      `Storage has 'sv' (flattened entries): ${storedEnc.sv !== undefined}`,
    )
    console.log(
      `Query has 'sv' (flattened entries): ${queriedEnc.sv !== undefined}`,
    )

    if (storedEnc.sv && queriedEnc.sv) {
      console.log(`Storage sv count: ${storedEnc.sv.length}`)
      console.log(`Query sv count: ${queriedEnc.sv.length}`)
    }

    expect(storedEnc).toHaveProperty('i')
    expect(storedEnc).toHaveProperty('v')
    expect(queriedEnc).toHaveProperty('i')
    expect(queriedEnc).toHaveProperty('v')
  })

  test('compare storage vs query (selector operation only)', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // Storage encryption
    const stored = await encryptBulk(client, {
      plaintexts: [
        {
          plaintext: { status: 'active' },
          ...profileColumn,
        },
      ],
    })

    // Query with ste_vec_selector (for path extraction)
    const querySelector = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: '$.status',
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_selector',
        },
      ],
    })

    console.log('=== STORAGE (encryptBulk) ===')
    console.log(JSON.stringify(stored[0], null, 2))

    console.log('\n=== QUERY ste_vec_selector ===')
    console.log(JSON.stringify(querySelector[0], null, 2))

    console.log('\n=== FIELD PRESENCE SUMMARY ===')
    const fields = ['c', 'sv', 's', 'b3', 'ocf', 'ocv', 'ob', 'bf', 'hm']

    for (const field of fields) {
      const row = [
        `${field}:`.padEnd(6),
        `storage=${(stored[0] as Record<string, unknown>)[field] !== undefined}`.padEnd(
          16,
        ),
        `selector=${(querySelector[0] as Record<string, unknown>)[field] !== undefined}`,
      ]
      console.log(row.join(' '))
    }

    const storedEnc = stored[0]
    assertSteVec(storedEnc)

    // EQL v2.3: SteVec storage has sv (root ciphertext lives at sv[0].c, not the root).
    expect(storedEnc).not.toHaveProperty('c')
    expect(storedEnc).toHaveProperty('sv')
    expect(storedEnc.sv?.[0]).toHaveProperty('c')

    // Selector query should have s (selector) but not c
    expect(querySelector[0]).toHaveProperty('s')
    expect(querySelector[0]).not.toHaveProperty('c')
  })
})

/**
 * Containment query patterns
 *
 * These tests verify the usage patterns for containment queries:
 * - column @> '{"role": "admin"}'::jsonb
 * - column @> '{"user": {"role": "admin"}}'::jsonb
 * - column @> '{"tags": ["admin"]}'::jsonb
 */
describe('ste_vec_term containment query patterns', () => {
  test('containment query for exact key-value match', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // This is what you'd use for: column @> '{"role": "admin"}'::jsonb
    const result = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: { role: 'admin' },
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
      ],
    })

    console.log('Containment query for {"role": "admin"}:')
    console.log(JSON.stringify(result[0], null, 2))

    expect(result[0]).toHaveProperty('i')
    expect(result[0]).toHaveProperty('v')
  })

  test('containment query for nested path match', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // This is what you'd use for: column @> '{"user": {"role": "admin"}}'::jsonb
    const result = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: { user: { role: 'admin' } },
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
      ],
    })

    console.log('Containment query for {"user": {"role": "admin"}}:')
    console.log(JSON.stringify(result[0], null, 2))

    expect(result[0]).toHaveProperty('i')
    expect(result[0]).toHaveProperty('v')
  })

  test('containment query for array element', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // This is what you'd use for: column @> '{"tags": ["admin"]}'::jsonb
    const result = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: { tags: ['admin'] },
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
      ],
    })

    console.log('Containment query for {"tags": ["admin"]}:')
    console.log(JSON.stringify(result[0], null, 2))

    expect(result[0]).toHaveProperty('i')
    expect(result[0]).toHaveProperty('v')
  })

  test('bulk containment queries for OR conditions', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // Multiple containment queries for: (column @> X) OR (column @> Y)
    const result = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: { role: 'admin' },
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
        {
          plaintext: { role: 'moderator' },
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
        {
          plaintext: { status: 'active' },
          ...profileColumn,
          indexType: 'ste_vec',
          queryOp: 'ste_vec_term',
        },
      ],
    })

    console.log('Bulk containment queries (3 conditions):')
    expect(result).toHaveLength(3)

    for (let i = 0; i < result.length; i++) {
      console.log(`\nQuery ${i + 1}:`)
      console.log(JSON.stringify(result[i], null, 2))
      expect(result[i]).toHaveProperty('i')
      expect(result[i]).toHaveProperty('v')
    }
  })
})

describe('type inference for ste_vec queries', () => {
  test('encryptQuery with default + object infers containment (term)', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // Object plaintext with queryOp: 'default' should infer ste_vec_term
    const result = await encryptQuery(client, {
      plaintext: { role: 'admin' },
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    console.log('Object with default queryOp output:')
    console.log(JSON.stringify(result, null, 2))

    // Should have sv array (containment/term behavior)
    expect(result).toHaveProperty('sv')
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
  })

  test('encryptQuery with default + string infers path selector', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // String plaintext with queryOp: 'default' should infer ste_vec_selector
    const result = await encryptQuery(client, {
      plaintext: '$.user.email',
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    console.log('String with default queryOp output:')
    console.log(JSON.stringify(result, null, 2))

    // Should have s (selector) but not c (no ciphertext for selector-only)
    expect(result).toHaveProperty('s')
    expect(result).not.toHaveProperty('c')
  })

  test('encryptQuery with default + array infers containment (term)', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // Array plaintext with queryOp: 'default' should infer ste_vec_term
    const result = await encryptQuery(client, {
      plaintext: ['admin', 'moderator'],
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    console.log('Array with default queryOp output:')
    console.log(JSON.stringify(result, null, 2))

    // Should have sv array (containment/term behavior)
    expect(result).toHaveProperty('sv')
  })

  test('encryptQueryBulk with default infers from plaintext types', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: { status: 'active' }, // Object → term
          table: 'users',
          column: 'profile',
          indexType: 'ste_vec',
          queryOp: 'default',
        },
        {
          plaintext: '$.name', // String → selector
          table: 'users',
          column: 'profile',
          indexType: 'ste_vec',
          queryOp: 'default',
        },
      ],
    })

    expect(result).toHaveLength(2)

    // First result (object) should have sv
    expect(result[0]).toHaveProperty('sv')

    // Second result (string) should have s but not c
    expect(result[1]).toHaveProperty('s')
    expect(result[1]).not.toHaveProperty('c')
  })
})

describe('type inference edge cases', () => {
  test('explicit ste_vec_term requires JSON (string throws error)', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // ste_vec_term is for JSON containment queries (@>)
    // Passing a string should error - containment requires JSON objects/arrays
    await expect(
      encryptQuery(client, {
        plaintext: 'this is a string but we want term',
        table: 'users',
        column: 'profile',
        indexType: 'ste_vec',
        queryOp: 'ste_vec_term', // Requires JSON, not string
      }),
    ).rejects.toThrow(/Invalid query input for 'ste_vec_term'/)
  })

  test('explicit ste_vec_term with JSON object works', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // ste_vec_term with JSON object should produce sv array for containment
    const result = await encryptQuery(client, {
      plaintext: { role: 'admin' },
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_term',
    })

    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('sv') // Flattened entries for containment
  })

  test('explicit ste_vec_selector overrides inference', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // Explicit queryOp should override type inference
    const result = await encryptQuery(client, {
      plaintext: '$.user.name',
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector', // Explicit
    })

    expect(result).toHaveProperty('s')
    expect(result).not.toHaveProperty('c')
  })

  test('empty object infers term', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQuery(client, {
      plaintext: {},
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    // Empty object is still an object → term
    expect(result).toHaveProperty('sv')
  })

  test('empty array infers term', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQuery(client, {
      plaintext: [],
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    // Empty array is still JSON → term
    expect(result).toHaveProperty('sv')
  })

  test('number with default queryOp fails for ste_vec', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    await expect(
      encryptQuery(client, {
        plaintext: 42,
        table: 'users',
        column: 'profile',
        indexType: 'ste_vec',
        queryOp: 'default',
      }),
    ).rejects.toThrow(/Invalid query input for 'ste_vec \(default\)'/)
  })

  test('boolean with default queryOp fails for ste_vec', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    await expect(
      encryptQuery(client, {
        // biome-ignore lint/suspicious/noExplicitAny: testing invalid type for error path
        plaintext: true as any,
        table: 'users',
        column: 'profile',
        indexType: 'ste_vec',
        queryOp: 'default',
      }),
    ).rejects.toThrow(/Invalid query input for 'ste_vec \(default\)'/)
  })
})

describe('type inference equivalence', () => {
  // Note: Encryption uses randomized nonces, so we compare structural properties
  // rather than full equality (toEqual would fail due to different ciphertext values)

  test('inferred term produces same structure as explicit term', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })
    const plaintext = { role: 'admin' }

    const inferred = await encryptQuery(client, {
      plaintext,
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default', // Inferred as term
    })

    const explicit = await encryptQuery(client, {
      plaintext,
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_term', // Explicit term
    })

    // Both should have same structural properties (sv array for term)
    expect(inferred).toHaveProperty('sv')
    expect(explicit).toHaveProperty('sv')
    expect(inferred).toHaveProperty('i')
    expect(explicit).toHaveProperty('i')
    expect(inferred).toHaveProperty('v')
    expect(explicit).toHaveProperty('v')

    assertSteVec(inferred)
    assertSteVec(explicit)

    // Identifier should match (same table/column)
    expect(inferred.i).toEqual(explicit.i)

    // Version should match
    expect(inferred.v).toEqual(explicit.v)

    // sv array should have same length (same flattening)
    expect(inferred.sv?.length).toEqual(explicit.sv?.length)
  })

  test('inferred selector produces same structure as explicit selector', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })
    const plaintext = '$.user.email'

    const inferred = await encryptQuery(client, {
      plaintext,
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default', // Inferred as selector
    })

    const explicit = await encryptQuery(client, {
      plaintext,
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector', // Explicit selector
    })

    // Both should have same structural properties (s for selector)
    expect(inferred).toHaveProperty('s')
    expect(explicit).toHaveProperty('s')
    expect(inferred).not.toHaveProperty('c')
    expect(explicit).not.toHaveProperty('c')

    assertSteVec(inferred)
    assertSteVec(explicit)

    // Identifier should match
    expect(inferred.i).toEqual(explicit.i)

    // Selector value should match (deterministic for same path)
    expect(inferred.s).toEqual(explicit.s)
  })
})

describe('type inference with nested structures', () => {
  test('deeply nested object infers term', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQuery(client, {
      plaintext: { user: { profile: { settings: { role: 'admin' } } } },
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    expect(result).toHaveProperty('sv')
  })

  test('object with array values infers term', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQuery(client, {
      plaintext: { tags: ['admin', 'moderator'], active: true },
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    expect(result).toHaveProperty('sv')
  })

  test('array of objects infers term', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const result = await encryptQuery(client, {
      plaintext: [{ role: 'admin' }, { role: 'user' }],
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    expect(result).toHaveProperty('sv')
  })

  test('null plaintext is treated as JsonB term for ste_vec', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    // null deserializes as JsPlaintext::JsonB(Value::Null)
    // and is treated as a term (containment query)
    const result = await encryptQuery(client, {
      // biome-ignore lint/suspicious/noExplicitAny: testing null value handling
      plaintext: null as any,
      table: 'users',
      column: 'profile',
      indexType: 'ste_vec',
      queryOp: 'default',
    })

    // null as JsonB goes through StoreMode, producing sv array.
    // EQL v2.3: the root ciphertext lives at sv[0].c, not at the root.
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).not.toHaveProperty('c')
    expect(result).toHaveProperty('sv')
    assertSteVec(result)
    expect(result.sv?.[0]).toHaveProperty('c')
  })
})
