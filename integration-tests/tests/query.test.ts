import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type Identifier,
  type QueryPayload,
  encryptQuery,
  encryptQueryBulk,
  newClient,
} from '@cipherstash/protect-ffi'

// Import shared encryptConfig from common.js
import { encryptConfig } from './common.js'

type UserColumn = Identifier<typeof encryptConfig>

const emailColumn: UserColumn = {
  table: 'users',
  column: 'email',
}

const scoreColumn: UserColumn = {
  table: 'users',
  column: 'score',
}

const profileColumn: UserColumn = {
  table: 'users',
  column: 'profile',
}

describe('encryptQuery for ste_vec indexes', () => {
  test('should encrypt JSON path selector for ste_vec columns with SEM only payloads', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: '$.name',
      ...profileColumn,
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector',
    })

    // ste_vec selectors should NOT have a 'c' field (SEM only payloads)
    expect(result).not.toHaveProperty('c')
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('s') // selector field
  })

  test('should handle different JSON path selectors for ste_vec', async () => {
    const client = await newClient({ encryptConfig })

    const selectors = ['$.name', '$.email', '$.profile.address']

    for (const selector of selectors) {
      const result = await encryptQuery(client, {
        plaintext: selector,
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_selector',
      })

      expect(result).not.toHaveProperty('c')
      expect(result).toHaveProperty('i')
      expect(result).toHaveProperty('v')
      expect(result).toHaveProperty('s') // selector field
    }
  })

  test('should encrypt with default operation for ste_vec without explicit queryOp', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: { tag: 'important' },
      ...profileColumn,
      indexType: 'ste_vec',
    })

    console.log('OBJECT + DEFAULT queryOp output:')
    console.log(JSON.stringify(result, null, 2))

    // JSON object with default queryOp should produce sv array for containment queries
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('c') // Root ciphertext from storage mode
    expect(result).toHaveProperty('sv') // Flattened entries for containment matching
    expect(Array.isArray(result.sv)).toBe(true)
  })

  test('should encrypt string path with explicit ste_vec_selector', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: '$.tag',
      ...profileColumn,
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector', // Must be explicit!
    })

    console.log('STRING + STE_VEC_SELECTOR output:')
    console.log(JSON.stringify(result, null, 2))

    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('s') // selector field
  })
})

describe('encryptQuery for string indexes', () => {
  test('should encrypt for ORE index on string column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 'test@example.com',
      ...emailColumn,
      indexType: 'ore',
    })

    // ORE queries should have SEM fields
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('ob') // ORE blocks for range queries
    expect(Array.isArray(result.ob)).toBe(true)
  })

  test('should encrypt for match index on string column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 'test',
      ...emailColumn,
      indexType: 'match',
    })

    // Match index should include bloom filter
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('bf') // bloom filter for fuzzy/substring match
    expect(Array.isArray(result.bf)).toBe(true)
  })

  test('should encrypt for unique index on string column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 'test@example.com',
      ...emailColumn,
      indexType: 'unique',
    })

    // Unique index should have HMAC
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('hm') // HMAC for exact match queries
    expect(typeof result.hm).toBe('string')
  })
})

describe('encryptQuery for numeric indexes', () => {
  test('should encrypt for ORE index on integer column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 100,
      ...scoreColumn,
      indexType: 'ore',
    })

    // ORE queries should have SEM fields
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('ob') // ORE blocks for range queries
    expect(Array.isArray(result.ob)).toBe(true)
  })
})

describe('encryptQueryBulk for query ordering and grouping', () => {
  test('should encrypt multiple queries in order', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: 'test1@example.com',
        ...emailColumn,
        indexType: 'ore',
      },
      {
        plaintext: 'test2@example.com',
        ...emailColumn,
        indexType: 'match',
      },
      {
        plaintext: 'test3@example.com',
        ...emailColumn,
        indexType: 'unique',
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(Array.isArray(results)).toBe(true)
    expect(results).toHaveLength(3)

    // First should be ORE
    expect(results[0]).toHaveProperty('ob')

    // Second should be match
    expect(results[1]).toHaveProperty('bf')

    // Third should be unique
    expect(results[2]).toHaveProperty('hm')
  })

  test('should handle mixed index types across columns in bulk', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: '$.status',
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_selector',
      },
      {
        plaintext: 'john@example.com',
        ...emailColumn,
        indexType: 'match',
      },
      {
        plaintext: 150,
        ...scoreColumn,
        indexType: 'ore',
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(3)

    // First should be ste_vec (no 'c' field)
    expect(results[0]).not.toHaveProperty('c')

    // Second should have match bloom filter
    expect(results[1]).toHaveProperty('bf')

    // Third should have ORE fields
    expect(results[2]).toHaveProperty('ob')
  })

  test('should preserve lockContext across bulk queries', async () => {
    const client = await newClient({ encryptConfig })
    const lockContext = {
      identityClaim: ['user123'],
    }

    const queries: QueryPayload[] = [
      {
        plaintext: 'email1@example.com',
        ...emailColumn,
        indexType: 'ore',
        lockContext,
      },
      {
        plaintext: 'email2@example.com',
        ...emailColumn,
        indexType: 'match',
        lockContext,
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(2)
    // Both results should be valid encrypted queries
    expect(results[0]).toHaveProperty('i')
    expect(results[1]).toHaveProperty('i')
  })

  test('should handle queries with different lockContext values', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: 'email1@example.com',
        ...emailColumn,
        indexType: 'ore',
        lockContext: {
          identityClaim: ['user1'],
        },
      },
      {
        plaintext: 'email2@example.com',
        ...emailColumn,
        indexType: 'ore',
        lockContext: {
          identityClaim: ['user2'],
        },
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(2)
    // Both should have ORE fields
    expect(results[0]).toHaveProperty('ob')
    expect(results[1]).toHaveProperty('ob')
  })

  test('should preserve order with identical index types and different plaintexts', async () => {
    const client = await newClient({ encryptConfig })

    const plaintexts = [
      'alice@example.com',
      'bob@example.com',
      'charlie@example.com',
    ]
    const queries: QueryPayload[] = plaintexts.map((plaintext) => ({
      plaintext,
      ...emailColumn,
      indexType: 'unique',
    }))

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(3)
    // All should have HMAC (unique index)
    expect(results[0]).toHaveProperty('hm')
    expect(results[1]).toHaveProperty('hm')
    expect(results[2]).toHaveProperty('hm')
    // Results should be different (different plaintexts)
    expect(results[0].hm).not.toEqual(results[1].hm)
    expect(results[1].hm).not.toEqual(results[2].hm)
  })
})

describe('encryptQuery error handling', () => {
  test('should error for missing column', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 'test',
        table: 'users',
        column: 'nonexistent',
        indexType: 'ore',
      }),
    ).rejects.toThrowError()
  })

  test('should error for missing index type', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 'test',
        ...emailColumn,
        // biome-ignore lint/suspicious/noExplicitAny: testing invalid input
        indexType: 'nonexistent' as any,
      }),
    ).rejects.toThrowError()
  })

  test('should error for unknown queryOp', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 'test',
        ...profileColumn,
        indexType: 'ste_vec',
        // biome-ignore lint/suspicious/noExplicitAny: testing invalid input
        queryOp: 'invalid_op' as any,
      }),
    ).rejects.toThrowError()
  })
})

describe('encryptQueryBulk error handling', () => {
  test('should handle partial errors in bulk operations', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: 'test@example.com',
        ...emailColumn,
        indexType: 'ore',
      },
      {
        plaintext: 'test',
        table: 'users',
        column: 'nonexistent',
        indexType: 'ore',
      },
    ]

    // Bulk operations should fail if any query is invalid
    await expect(encryptQueryBulk(client, { queries })).rejects.toThrowError()
  })
})
