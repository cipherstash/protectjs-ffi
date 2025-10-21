import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  newClient,
  type StringOperator,
  type NumericOperator,
  type JsonbOperator,
  type JsPlaintext,
} from '@cipherstash/protect-ffi'

// Import a shared encryptConfig from common.js
import { encryptConfig } from './common.js'
import { encryptQuery } from '../../lib/load.cjs'

const emailValidOperators: { op: StringOperator; index: string }[] = [
  { op: '=', index: 'hm' },
  { op: '~~', index: 'bf' },
  { op: '~~*', index: 'bf' },
  // TODO: What should we do with these? Technically valid, right?
  /*{ op: '>=', index: 'ob' },
  { op: '<=', index: 'ob' },
  { op: '>', index: 'ob' },
  { op: '<', index: 'ob' },*/
]

const scoreValidOperators: { op: NumericOperator; index: string }[] = [
  // NOTE: CipherStash client will use an ORE index for equality queries on numeric types if available
  { op: '=', index: 'ob' },
  { op: '>=', index: 'ob' },
  { op: '<=', index: 'ob' },
  { op: '>', index: 'ob' },
  { op: '<', index: 'ob' },
]

const jsonValidOperators: {
  op: JsonbOperator
  index: string
  v: JsPlaintext
}[] = [
  { op: '->', index: 's', v: '$.foo' },
  { op: '@>', index: 'sv', v: { foo: 'bar' } },
  // TODO: The rest
]

const emailInvalidOperators: { op: NumericOperator | JsonbOperator }[] = [
  { op: '@>' },
  { op: '<@' },
  { op: '->' },
]

const scoreInvalidOperators: { op: StringOperator | JsonbOperator }[] = [
  { op: '@>' },
  { op: '<@' },
  { op: '->' },
  { op: '~~' },
  { op: '~~*' },
]

const jsonInvalidOperators: { op: StringOperator | NumericOperator }[] = [
  { op: '~~' },
  { op: '~~*' },
  { op: '=' },
  { op: '>=' },
  { op: '<=' },
  { op: '>' },
  { op: '<' },
]

describe('query encryption', () => {
  describe.each(emailValidOperators)(
    'using operator $op for email column',
    ({ op, index }) => {
      test(`generates the correct query type: '${index}'`, async () => {
        const client = await newClient({ encryptConfig })

        const query = await encryptQuery(client, {
          plaintext: 'foo@example.net',
          column: 'email',
          table: 'users',
          operator: op,
        })

        expect(query).toHaveProperty(index)
      })
    },
  )

  describe.each(emailInvalidOperators)(
    'using operator $op for email column',
    ({ op }) => {
      test('fails to generate a query term', async () => {
        const client = await newClient({ encryptConfig })

        expect(async () => {
          await encryptQuery(client, {
            plaintext: 'foo@example.net',
            column: 'email',
            table: 'users',
            operator: op,
          })
        }).rejects.toThrowError(
          /no index found for column users.email supporting operator/,
        )
      })
    },
  )

  describe.each(scoreValidOperators)(
    'using operator $op for score column',
    ({ op, index }) => {
      test(`generates the correct query type: '${index}'`, async () => {
        const client = await newClient({ encryptConfig })

        const query = await encryptQuery(client, {
          plaintext: 1000,
          column: 'score',
          table: 'users',
          operator: op,
        })

        expect(query).toHaveProperty(index)
      })
    },
  )

  describe.each(scoreInvalidOperators)(
    'using operator $op for score column',
    ({ op }) => {
      test('fails to generate a query term', async () => {
        const client = await newClient({ encryptConfig })

        expect(async () => {
          await encryptQuery(client, {
            plaintext: 5000,
            column: 'score',
            table: 'users',
            operator: op,
          })
        }).rejects.toThrowError(
          /no index found for column users.score supporting operator/,
        )
      })
    },
  )

  describe.each(jsonValidOperators)(
    'using operator $op for json column',
    ({ op, index, v }) => {
      test(`generates the correct query type: '${index}'`, async () => {
        const client = await newClient({ encryptConfig })

        const query = await encryptQuery(client, {
          // TODO: This plaintext is _different_ to the JSON type
          plaintext: v,
          column: 'profile',
          table: 'users',
          operator: op,
        })

        expect(query).toHaveProperty(index)
      })
    },
  )

  describe.each(jsonInvalidOperators)(
    'using operator $op for json column',
    ({ op }) => {
      test('fails to generate a query term', async () => {
        const client = await newClient({ encryptConfig })

        expect(async () => {
          await encryptQuery(client, {
            plaintext: '$["foo"]',
            column: 'profile',
            table: 'users',
            operator: op,
          })
        }).rejects.toThrowError(
          /no index found for column users.profile supporting operator/,
        )
      })
    },
  )
})
