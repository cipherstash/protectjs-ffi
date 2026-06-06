// Behavioural tests for the Node-side `opts.strategy` (JsBacked) path.
//
// The event-loop-exit suite proves the JsBacked path works end-to-end and
// drains cleanly. This suite asserts the strategy contract directly:
//
//   1. `getToken` is invoked from Rust for every ZeroKMS-bound operation
//      (no Rust-side AutoRefresh caching, matching the wasm contract).
//   2. A rejected `getToken` Promise propagates back as a client error
//      instead of being silently swallowed.
//   3. A strategy without a callable `getToken` is rejected at
//      construction with a clear error.

import 'dotenv/config'
import { AccessKeyStrategy } from '@cipherstash/auth/wasm-inline'
import { describe, expect, test } from 'vitest'

import {
  type AuthStrategy,
  type ClientOpts,
  decrypt,
  encrypt,
  newClient,
} from '@cipherstash/protect-ffi'

import { encryptConfig } from './common.js'

const REQUIRED_ENV = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ACCESS_KEY',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
] as const
const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k])

function buildAccessKeyStrategy(): AccessKeyStrategy {
  const crn = process.env.CS_WORKSPACE_CRN
  const accessKey = process.env.CS_CLIENT_ACCESS_KEY
  if (!crn || !accessKey) {
    throw new Error('unreachable: skipIf gates this')
  }
  // @cipherstash/auth 0.39 takes the full workspace CRN and parses the
  // region from it (earlier versions took only the `<region>.<provider>`
  // segment, requiring callers to split the CRN themselves).
  return AccessKeyStrategy.create(crn, accessKey)
}

const clientOpts: ClientOpts = {
  clientId: process.env.CS_CLIENT_ID,
  clientKey: process.env.CS_CLIENT_KEY,
}

describe.skipIf(missingEnv.length > 0)('opts.strategy (JsBacked)', () => {
  test('invokes getToken from Rust for every operation', async () => {
    const inner = buildAccessKeyStrategy()
    let callCount = 0
    const strategy: AuthStrategy = {
      async getToken() {
        callCount++
        return await inner.getToken()
      },
    }

    const client = await newClient({ encryptConfig, clientOpts, strategy })
    expect(callCount).toBeGreaterThanOrEqual(1) // newClient → load_keyset

    const beforeEncrypt = callCount
    const ciphertext = await encrypt(client, {
      plaintext: 'alice@example.com',
      table: 'users',
      column: 'email',
    })
    expect(callCount).toBeGreaterThan(beforeEncrypt)

    const beforeDecrypt = callCount
    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toBe('alice@example.com')
    expect(callCount).toBeGreaterThan(beforeDecrypt)
  })

  test('propagates a rejected getToken Promise to the client error', async () => {
    const strategy: AuthStrategy = {
      async getToken() {
        throw new Error('strategy intentionally rejected for test')
      },
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/strategy intentionally rejected for test/)
  })

  test('rejects a strategy without a getToken function', async () => {
    // Cast through `unknown` so TS doesn't reject the malformed shape
    // before the test can exercise the runtime check.
    const strategy = { notGetToken: () => {} } as unknown as AuthStrategy

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/getToken/)
  })

  test('rejects a strategy whose getToken is not callable', async () => {
    // present but not a function -> exercises the downcast-failure arm,
    // distinct from the missing/undefined arm covered above.
    const strategy = { getToken: 'not-a-function' } as unknown as AuthStrategy

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/getToken is not a function/)
  })

  test('rejects when getToken throws synchronously', async () => {
    const strategy: AuthStrategy = {
      getToken: (() => {
        throw new Error('sync throw from getToken')
      }) as AuthStrategy['getToken'],
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/threw synchronously|sync throw from getToken/)
  })

  test('rejects when getToken returns a non-Promise', async () => {
    const strategy: AuthStrategy = {
      // biome-ignore lint/suspicious/noExplicitAny: deliberately mistyped
      getToken: (() => ({ token: 'not-wrapped-in-a-promise' })) as any,
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/did not return a Promise/)
  })

  test('rejects when getToken resolves with a non-object', async () => {
    const strategy: AuthStrategy = {
      // biome-ignore lint/suspicious/noExplicitAny: deliberately mistyped
      getToken: (async () => 'just-a-string') as any,
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/did not return an object/)
  })

  test('rejects when getToken resolves without a token field', async () => {
    const strategy: AuthStrategy = {
      // biome-ignore lint/suspicious/noExplicitAny: deliberately mistyped
      getToken: (async () => ({ notToken: 'oops' })) as any,
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/missing 'token' field/)
  })

  test("rejects when the 'token' field is not a string", async () => {
    const strategy: AuthStrategy = {
      // biome-ignore lint/suspicious/noExplicitAny: deliberately mistyped
      getToken: (async () => ({ token: 12345 })) as any,
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/'token' field is not a string/)
  })
})
