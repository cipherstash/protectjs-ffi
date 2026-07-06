// End-to-end round-trip on the wasm build path.
//
// Exercises the same encrypt → decrypt cycle the Neon tests cover, but
// goes through `dist/wasm/protect_ffi_inline.js` instead of the
// `@cipherstash/protect-ffi` Neon entry. Auth is delegated to
// `@cipherstash/auth`'s `AccessKeyStrategy` exactly as a real wasm
// consumer would wire it up.
//
// # Prerequisites
//
// 1. Build the wasm artifacts from the repo root: `npm run build:wasm`.
//    Without `dist/wasm/protect_ffi_inline.js` the suite fails fast with
//    a clear error rather than skipping silently.
// 2. Set `CS_REGION`, `CS_CLIENT_ACCESS_KEY`, `CS_CLIENT_ID`, and
//    `CS_CLIENT_KEY` (the wasm path takes the dataset client key inline;
//    there's no profile-store fallback).
//
// The suite is `describe.skipIf`-gated on the env vars so it stays a
// no-op when credentials aren't configured (matches how the Neon-side
// tests behave when run without `~/.cipherstash/secretkey.json`).

import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

import 'dotenv/config'
import { AccessKeyStrategy } from '@cipherstash/auth/wasm-inline'
import { beforeAll, describe, expect, test } from 'vitest'

const REQUIRED_ENV = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ACCESS_KEY',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
] as const

const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k])

// `__dirname` (CJS) instead of `import.meta.url` because the
// integration-tests tsconfig inherits `module: "node16"` and the package
// has no `"type": "module"`, so .ts files compile as CJS.
const WASM_INLINE_PATH = resolve(
  __dirname,
  '..',
  '..',
  'dist',
  'wasm',
  'protect_ffi_inline.js',
)

// Skip the whole suite when env vars are missing. When they're present
// but the wasm build hasn't been run, `beforeAll` throws so the failure
// surfaces with a clear "run npm run build:wasm" hint instead of an
// opaque ESM import error.
describe.skipIf(missingEnv.length > 0)('wasm round-trip', () => {
  type WasmModule = {
    newClient: (opts: Record<string, unknown>) => Promise<unknown>
    encrypt: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<{
      k: 'ct' | 'sv'
      i: { t: string; c: string }
      c?: string
      hm?: string
    }>
    decrypt: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<unknown>
    isEncrypted: (raw: unknown) => boolean
  }

  let wasm: WasmModule

  beforeAll(async () => {
    if (!existsSync(WASM_INLINE_PATH)) {
      throw new Error(
        `wasm-inline build not found at ${WASM_INLINE_PATH}. Run \`npm run build:wasm\` from the repo root before running the integration tests.`,
      )
    }
    // Dynamic import keeps vitest from trying to resolve the path at
    // module-graph time (when the build may not yet exist).
    wasm = (await import(WASM_INLINE_PATH)) as WasmModule
  })

  test('encrypts and decrypts a scalar value end-to-end', async () => {
    // describe.skipIf above guarantees these are set; pull them into
    // local consts so TS narrows away the `undefined` and the test body
    // doesn't need non-null assertions on every reference.
    const env = {
      workspaceCrn: process.env.CS_WORKSPACE_CRN,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
    }
    if (
      !env.workspaceCrn ||
      !env.accessKey ||
      !env.clientId ||
      !env.clientKey
    ) {
      throw new Error(
        'unreachable: describe.skipIf should have prevented this test from running without env vars',
      )
    }

    // @cipherstash/auth 0.39 takes the full workspace CRN and parses the
    // region from it (earlier versions took only the `<region>.<provider>`
    // segment, requiring callers to split the CRN themselves).
    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            email: {
              // The TS shim normalises 'string' → 'text' before handing the
              // config to native; the wasm test bypasses that shim, so it
              // must use the post-0.36 canonical vocabulary directly.
              cast_as: 'text',
              indexes: { unique: {} },
            },
          },
        },
      },
      clientId: env.clientId,
      clientKey: env.clientKey,
    })

    const plaintext = 'alice@example.com'
    const ciphertext = await wasm.encrypt(client, {
      plaintext,
      table: 'users',
      column: 'email',
    })

    expect(wasm.isEncrypted(ciphertext)).toBe(true)
    expect(ciphertext.k).toBe('ct')
    expect(ciphertext.i).toEqual({ t: 'users', c: 'email' })
    // unique-index HMAC lives at the top-level `hm` field in EQL v2.3.
    expect(ciphertext.hm).toBeTruthy()
    // MessagePack-Base85 ciphertext lives at top-level `c` for scalar payloads.
    expect(ciphertext.c).toBeTruthy()

    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(decrypted).toBe(plaintext)
  })

  test('round-trips a bigint plaintext exactly and rejects out-of-range values', async () => {
    const env = {
      workspaceCrn: process.env.CS_WORKSPACE_CRN,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
    }
    if (
      !env.workspaceCrn ||
      !env.accessKey ||
      !env.clientId ||
      !env.clientKey
    ) {
      throw new Error(
        'unreachable: describe.skipIf should have prevented this test from running without env vars',
      )
    }

    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            score: {
              cast_as: 'big_int',
              indexes: { ore: {} },
            },
          },
        },
      },
      clientId: env.clientId,
      clientKey: env.clientKey,
    })

    // i64::MAX — far beyond Number.MAX_SAFE_INTEGER; must survive exactly.
    const plaintext = 9223372036854775807n
    const ciphertext = await wasm.encrypt(client, {
      plaintext,
      table: 'users',
      column: 'score',
    })

    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(typeof decrypted).toBe('bigint')
    expect(decrypted).toBe(plaintext)

    // 2^63 is just above i64::MAX — the wasm boundary rejects it before
    // serde with an error naming the bounds and direction.
    await expect(
      wasm.encrypt(client, {
        plaintext: 2n ** 63n,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrow(/above the maximum.*signed 64-bit integer/)
  })

  test('json plaintexts follow JSON.stringify semantics (Neon parity)', async () => {
    const env = {
      workspaceCrn: process.env.CS_WORKSPACE_CRN,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
    }
    if (
      !env.workspaceCrn ||
      !env.accessKey ||
      !env.clientId ||
      !env.clientKey
    ) {
      throw new Error(
        'unreachable: describe.skipIf should have prevented this test from running without env vars',
      )
    }

    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            profile: {
              cast_as: 'json',
              indexes: {},
            },
          },
        },
      },
      clientId: env.clientId,
      clientKey: env.clientKey,
    })

    // JSON has no bigint: the wasm boundary canonicalizes plaintexts
    // through JSON.stringify, so a bigint nested inside a json-column
    // document rejects with the engine's own TypeError — exactly as it
    // does on Neon, where neon's `Json` extractor stringifies the options
    // object. (Before canonicalization, serde_wasm_bindgen silently folded
    // the bigint into the document as an i64 that decrypted back through
    // f64, rounding above 2^53.)
    await expect(
      wasm.encrypt(client, {
        plaintext: { count: 2n ** 60n + 1n },
        table: 'users',
        column: 'profile',
      }),
    ).rejects.toThrow(TypeError)

    // The rest of JSON.stringify's semantics apply too: `toJSON` is
    // honored (Date → ISO string), `undefined` properties are dropped,
    // and non-finite numbers become `null`.
    const ciphertext = await wasm.encrypt(client, {
      plaintext: {
        joined: new Date('2026-01-02T03:04:05.678Z'),
        nickname: undefined,
        score: Number.NaN,
      },
      table: 'users',
      column: 'profile',
    })
    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(decrypted).toEqual({
      joined: '2026-01-02T03:04:05.678Z',
      score: null,
    })
  })
})

// The wasm `newClient` requires `opts.strategy` (no env/fs fallback). Both
// guards run *before* serde and before any network call, so they need no
// credentials — gate only on the wasm build existing, not on the env vars.
describe.skipIf(!existsSync(WASM_INLINE_PATH))(
  'wasm newClient validation',
  () => {
    type WasmModule = {
      newClient: (opts: Record<string, unknown>) => Promise<unknown>
    }
    const minimalConfig = { v: 1, tables: {} }

    test('rejects when opts.strategy is missing', async () => {
      const wasm = (await import(WASM_INLINE_PATH)) as WasmModule
      await expect(
        wasm.newClient({ encryptConfig: minimalConfig }),
      ).rejects.toThrow(/opts\.strategy is required/)
    })

    test('rejects a non-callable getToken', async () => {
      const wasm = (await import(WASM_INLINE_PATH)) as WasmModule
      await expect(
        wasm.newClient({
          strategy: { getToken: 42 },
          encryptConfig: minimalConfig,
        }),
      ).rejects.toThrow(/getToken is not a function/)
    })
  },
)
