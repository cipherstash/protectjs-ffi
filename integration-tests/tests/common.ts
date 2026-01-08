import type { EncryptConfig } from '../../lib/index.cjs'

export const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'string',
        indexes: {
          ore: {},
          match: {},
          unique: {},
        },
      },
      score: {
        cast_as: 'bigint',
        indexes: { ore: {} },
      },
      score_float: {
        cast_as: 'number',
        indexes: { ore: {} },
      },
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'users/profile' } },
      },
    },
  },
}

// A single JSON column with no indexes (will be treated as an opaque blob)
export const jsonOpaque: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',
        indexes: {},
      },
    },
  },
}

// A single JSON column with an ste_vec index
export const jsonSteVec: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'users/profile' } },
      },
    },
  },
}

