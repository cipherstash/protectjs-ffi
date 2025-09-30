import type { EncryptConfig } from '../../lib/index.cjs'

export const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'text',
        indexes: {
          ore: {},
          match: {},
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
