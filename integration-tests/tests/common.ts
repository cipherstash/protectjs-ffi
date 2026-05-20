import type {
  Encrypted,
  EncryptedScalar,
  EncryptedSteVec,
  EncryptConfig,
} from '../../lib/index.cjs'

export function assertSteVec(
  payload: Encrypted,
): asserts payload is EncryptedSteVec {
  if (payload.k !== 'sv') {
    throw new Error(`expected k:"sv" payload, got k:"${payload.k}"`)
  }
}

export function assertScalar(
  payload: Encrypted,
): asserts payload is EncryptedScalar {
  if (payload.k !== 'ct') {
    throw new Error(`expected k:"ct" payload, got k:"${payload.k}"`)
  }
}

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

// Config with a date and a timestamp column for testing JS Date round-trips
export const datesConfig: EncryptConfig = {
  v: 1,
  tables: {
    events: {
      occurred_on: {
        cast_as: 'date',
      },
      occurred_at: {
        cast_as: 'timestamp',
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
