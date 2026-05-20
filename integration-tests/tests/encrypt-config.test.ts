import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type EncryptConfig,
  ProtectError,
  newClient,
} from '@cipherstash/protect-ffi'

describe('newClient encrypt config', () => {
  test('accepts legacy cast_as vocabulary and ste_vec without mode', async () => {
    const encryptConfig: EncryptConfig = {
      v: 1,
      tables: {
        users: {
          email: { cast_as: 'string', indexes: { match: {} } },
          score: { cast_as: 'bigint', indexes: { ore: {} } },
          score_float: { cast_as: 'number', indexes: { ore: {} } },
          profile: {
            cast_as: 'json',
            indexes: { ste_vec: { prefix: 'users/profile' } },
          },
        },
      },
    }

    const client = await newClient({ encryptConfig })
    expect(client).toBeDefined()
  })

  test('rejects match index on a non-text column with MATCH_REQUIRES_TEXT', async () => {
    const encryptConfig: EncryptConfig = {
      v: 1,
      tables: {
        users: {
          score: { cast_as: 'number', indexes: { match: {} } },
        },
      },
    }

    try {
      await newClient({ encryptConfig })
      throw new Error('expected newClient to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(ProtectError)
      if (err instanceof ProtectError) {
        expect(err.code).toBe('MATCH_REQUIRES_TEXT')
      }
    }
  })

  test('rejects unsupported config version with UNSUPPORTED_CONFIG_VERSION', async () => {
    const encryptConfig: EncryptConfig = {
      v: 2,
      tables: {
        users: {
          email: { cast_as: 'text' },
        },
      },
    }

    try {
      await newClient({ encryptConfig })
      throw new Error('expected newClient to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(ProtectError)
      if (err instanceof ProtectError) {
        expect(err.code).toBe('UNSUPPORTED_CONFIG_VERSION')
      }
    }
  })

  test('rejects ste_vec index on a non-json column with STE_VEC_REQUIRES_JSON_CAST_AS', async () => {
    const encryptConfig: EncryptConfig = {
      v: 1,
      tables: {
        users: {
          email: {
            cast_as: 'text',
            indexes: { ste_vec: { prefix: 'users/email' } },
          },
        },
      },
    }

    try {
      await newClient({ encryptConfig })
      throw new Error('expected newClient to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(ProtectError)
      if (err instanceof ProtectError) {
        expect(err.code).toBe('STE_VEC_REQUIRES_JSON_CAST_AS')
      }
    }
  })
})
