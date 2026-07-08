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
// 2. Set `CS_WORKSPACE_CRN`, `CS_CLIENT_ACCESS_KEY`, `CS_CLIENT_ID`, and
//    `CS_CLIENT_KEY` (the wasm path takes the dataset client key inline;
//    there's no profile-store fallback).
//
// Missing prerequisites FAIL the suite with a clear error — they never
// skip it. A skipped suite reads as green in CI, which is exactly how a
// misconfigured secret would go unnoticed.

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

/**
 * Read the required credentials, throwing (test failure, not a skip) when
 * any are missing. Returning narrowed strings keeps the test bodies free
 * of non-null assertions.
 */
function requireEnv() {
  const missing = REQUIRED_ENV.filter((k) => !process.env[k])
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}. The wasm integration tests need CipherStash credentials — see the header of this file.`,
    )
  }
  return {
    workspaceCrn: process.env.CS_WORKSPACE_CRN as string,
    accessKey: process.env.CS_CLIENT_ACCESS_KEY as string,
    clientId: process.env.CS_CLIENT_ID as string,
    clientKey: process.env.CS_CLIENT_KEY as string,
  }
}

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

/**
 * Import the wasm-inline build, throwing a "run npm run build:wasm" hint
 * (test failure, not a skip) when the artifact is missing — instead of an
 * opaque ESM import error. Dynamic import keeps vitest from trying to
 * resolve the path at module-graph time.
 */
async function loadWasm<T>(): Promise<T> {
  if (!existsSync(WASM_INLINE_PATH)) {
    throw new Error(
      `wasm-inline build not found at ${WASM_INLINE_PATH}. Run \`npm run build:wasm\` from the repo root before running the integration tests.`,
    )
  }
  return (await import(WASM_INLINE_PATH)) as T
}

describe('wasm round-trip', () => {
  type Ciphertext = {
    k: 'ct' | 'sv'
    i: { t: string; c: string }
    c?: string
    hm?: string
  }
  type WasmModule = {
    newClient: (opts: Record<string, unknown>) => Promise<unknown>
    encrypt: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<Ciphertext>
    encryptBulk: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<Ciphertext[]>
    decrypt: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<unknown>
    decryptBulk: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<unknown[]>
    decryptBulkFallible: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<({ data: unknown } | { error: string })[]>
    isEncrypted: (raw: unknown) => boolean
  }

  let wasm: WasmModule

  beforeAll(async () => {
    // Fail fast on missing prerequisites so every test in the suite
    // reports the same clear error instead of a pile of undefined-env
    // noise further down.
    requireEnv()
    wasm = await loadWasm<WasmModule>()
  })

  test('encrypts and decrypts a scalar value end-to-end', async () => {
    const env = requireEnv()

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
    const env = requireEnv()

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
    // serde with a RangeError (the documented class, same as the Neon
    // boundary) naming the bounds and direction.
    const aboveMax = wasm.encrypt(client, {
      plaintext: 2n ** 63n,
      table: 'users',
      column: 'score',
    })
    await expect(aboveMax).rejects.toThrow(
      /above the maximum.*signed 64-bit integer/,
    )
    await expect(aboveMax).rejects.toBeInstanceOf(RangeError)

    // -(2^63) - 1 is just below i64::MIN — the sign detection picks the
    // "below the minimum" wording.
    const belowMin = wasm.encrypt(client, {
      plaintext: -(2n ** 63n) - 1n,
      table: 'users',
      column: 'score',
    })
    await expect(belowMin).rejects.toThrow(
      /below the minimum.*signed 64-bit integer/,
    )
    await expect(belowMin).rejects.toBeInstanceOf(RangeError)
  })

  test('bulk round-trips a mixed bigint / string / number batch', async () => {
    const env = requireEnv()

    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            email: {
              cast_as: 'text',
              indexes: { unique: {} },
            },
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

    // Mixed batch: exercises the wasm boundary's per-item plaintext
    // rewriting in `encode_plaintext_list` (bigint items get the tagged
    // wire form, the rest are JSON-canonicalized) and the manual JS-array
    // construction in `decrypt_bulk` (needed so bigints decrypt to real JS
    // bigints instead of the serde wire map).
    const plaintexts = [
      { plaintext: 'alice@example.com', table: 'users', column: 'email' },
      { plaintext: 9007199254740993n, table: 'users', column: 'score' },
      { plaintext: 123, table: 'users', column: 'score' },
    ]

    const ciphertexts = await wasm.encryptBulk(client, { plaintexts })
    expect(ciphertexts).toHaveLength(3)

    const decrypted = await wasm.decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })
    // The bigint column ALWAYS decrypts to a JS bigint — including the
    // `123` number input (matches the Neon scalar-bulk suite).
    expect(decrypted).toEqual(['alice@example.com', 9007199254740993n, 123n])

    // decryptBulkFallible: same manual array construction, plus per-item
    // error objects. A corrupted ciphertext yields an `{ error }` arm
    // without poisoning the valid items.
    const fallible = await wasm.decryptBulkFallible(client, {
      ciphertexts: [
        { ciphertext: ciphertexts[1] },
        { ciphertext: { ...ciphertexts[1], c: 'not-a-real-ciphertext' } },
      ],
    })
    expect(fallible).toHaveLength(2)
    expect(fallible[0]).toEqual({ data: 9007199254740993n })
    expect(fallible[1]).toHaveProperty('error')
  })

  test('json plaintexts follow JSON.stringify semantics (Neon parity)', async () => {
    const env = requireEnv()

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
// credentials — only the wasm build (loadWasm fails with the build hint
// when it's missing).
describe('wasm newClient validation', () => {
  type WasmModule = {
    newClient: (opts: Record<string, unknown>) => Promise<unknown>
  }
  const minimalConfig = { v: 1, tables: {} }

  test('rejects when opts.strategy is missing', async () => {
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({ encryptConfig: minimalConfig }),
    ).rejects.toThrow(/opts\.strategy is required/)
  })

  test('rejects a non-callable getToken', async () => {
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        strategy: { getToken: 42 },
        encryptConfig: minimalConfig,
      }),
    ).rejects.toThrow(/getToken is not a function/)
  })
})
