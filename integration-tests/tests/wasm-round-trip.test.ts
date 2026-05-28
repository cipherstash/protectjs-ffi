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
    ) => Promise<{ i: { t: string; c: string }; b?: { c: string } }>
    decrypt: (client: unknown, opts: Record<string, unknown>) => Promise<string>
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

    // stack-auth 0.36 dropped CS_REGION in favour of CS_WORKSPACE_CRN.
    // The wasm AccessKeyStrategy.create still takes a region string but
    // it expects the `<region>.<provider>` form, which is the middle
    // segment of a CRN like `crn:ap-southeast-2.aws:<workspace>`.
    const crnMatch = env.workspaceCrn.match(/^crn:([^:]+):/)
    if (!crnMatch) {
      throw new Error(
        `unexpected CS_WORKSPACE_CRN format: ${env.workspaceCrn}`,
      )
    }
    const strategy = AccessKeyStrategy.create(crnMatch[1], env.accessKey)

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
    expect(ciphertext.i).toEqual({ t: 'users', c: 'email' })
    expect(ciphertext.b?.c).toBeTruthy()

    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(decrypted).toBe(plaintext)
  })
})
