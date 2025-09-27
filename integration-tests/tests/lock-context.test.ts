import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type CastAs,
  decrypt,
  encrypt,
  newClient,
} from '@cipherstash/protect-ffi'

const encryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'text' as CastAs, // FIXME: do we need the as ?
        indexes: {
          ore: {},
          match: {},
          unique: {},
        },
      },
      score: {
        cast_as: 'double' as CastAs,
        indexes: {} // TODO: add ore index options here when we support them
      },
      profile: {
        cast_as: 'jsonb' as CastAs,
        indexes: {} // TODO: add an index here
      }
    },
  },
}

describe('lock context', () => {
  test('can pass in unverified context', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'
    const unverifiedContext = {
      sub: 'sub-single',
    }

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
      unverifiedContext,
    })

    const decrypted = await decrypt(client, {
      ciphertext: ciphertext.c,
      unverifiedContext,
    })

    expect(decrypted).toBe(originalPlaintext)
  })

  test('encrypt throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    await expect(async () => {
      await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'email',
        table: 'users',
        lockContext: {
          identityClaim: ['sub'],
        },
      })
    }).rejects.toThrowError(/Failed to send request/)
  }, 10000)

  test('decrypt throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    await expect(async () => {
      await decrypt(client, {
        ciphertext: ciphertext.c,
        lockContext: {
          identityClaim: ['sub'],
        },
      })
    }).rejects.toThrowError(/Failed to send request/)
  }, 10000)
})