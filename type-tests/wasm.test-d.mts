/**
 * Type tests for the wasm build's declarations (#142).
 *
 * These run against the PATCHED `dist/wasm/protect_ffi.d.ts` — the output of
 * `scripts/type-wasm-dts.mjs` — so they need a wasm build first. That is why
 * they live outside `src/` and outside both root tsconfigs: `npm test` must
 * still pass in a fresh clone with no `dist/`. CI runs them in the `wasm` job,
 * immediately after `npm run build:wasm`, via `npm run test:typecheck:wasm`.
 *
 * The negative cases carry `@ts-expect-error`, which makes this file
 * self-verifying in both directions: if a declaration stops catching the
 * mistake below it, the suppression becomes unused and tsc fails. A test that
 * silently stops testing is the failure mode worth engineering against here,
 * because the thing under test is regenerated on every build.
 */

import {
  decryptBulkFallible,
  encrypt,
  encryptBulk,
  encryptQuery,
  encryptQueryBulk,
  newClient,
} from '../dist/wasm/protect_ffi.js'
import type {
  Context,
  EncryptOptions,
  EncryptedPayload,
  JsPlaintext,
  NewClientOptions,
  QueryOpName,
  WasmClient,
  WasmDecryptResult,
} from '../dist/wasm/protect_ffi.js'

declare const client: WasmClient
declare const authStrategy: NewClientOptions['authStrategy']

// --- the shared option types are reachable from this entry at all ----------
// Before #142 none of these names existed here, and every `opts` was `any`.

const encryptOpts: EncryptOptions = {
  plaintext: 'secret',
  column: 'email',
  table: 'users',
  lockContext: { identityClaim: ['sub'] } satisfies Context,
  unverifiedContext: { requestId: 'r1' },
}
export const encrypted: Promise<EncryptedPayload> = encrypt(client, encryptOpts)

// --- lockContext placement -------------------------------------------------
// Top-level on the single calls, per payload item on the bulk ones. Getting
// this wrong is not a type curiosity: an ignored lock context yields a payload
// that looks encrypted-and-bound but is readable without the claim.

export const bulk = encryptBulk(client, {
  plaintexts: [
    {
      plaintext: 42n,
      column: 'age',
      table: 'users',
      lockContext: { identityClaim: ['sub'] },
    },
  ],
  unverifiedContext: { requestId: 'r1' },
})

export const bulkMisplaced = encryptBulk(client, {
  plaintexts: [{ plaintext: 'x', column: 'email', table: 'users' }],
  // @ts-expect-error lockContext is per payload item on the bulk path; at the
  // top level serde drops it and the values are encrypted unbound.
  lockContext: { identityClaim: ['sub'] },
})

export const queryBulk = encryptQueryBulk(client, {
  queries: [
    {
      plaintext: 'alice@example.com',
      column: 'email',
      table: 'users',
      indexType: 'unique',
      lockContext: { identityClaim: ['sub'] },
    },
  ],
})

// --- bigint plaintexts -----------------------------------------------------
// `encode_plaintext` tags these for the untagged JsPlaintext enum, so they are
// carried exactly rather than folded into an f64. Same on both bindings.

export const big: Promise<EncryptedPayload> = encrypt(client, {
  plaintext: 9223372036854775807n,
  column: 'big',
  table: 'users',
})

// --- query terms -----------------------------------------------------------

export const q = encryptQuery(client, {
  plaintext: 'alice',
  column: 'email',
  table: 'users',
  indexType: 'match',
  queryOp: 'default' satisfies QueryOpName,
})

export const badIndexType = encryptQuery(client, {
  plaintext: 'alice',
  column: 'email',
  table: 'users',
  // @ts-expect-error indexType is a closed set; a typo here previously reached
  // the Rust and failed at runtime.
  indexType: 'matsh',
})

// --- per-item decrypt results ---------------------------------------------
// This build returns what Rust serializes: `{ data }` or `{ error }`. The Neon
// entry's DecryptResult also carries `code`, which its JS wrapper infers from
// the message — Rust never emits it, so it is absent here rather than
// optional-and-never-set.

export async function readBack(): Promise<(JsPlaintext | string)[]> {
  const rows: WasmDecryptResult[] = await decryptBulkFallible(client, {
    ciphertexts: [{ ciphertext: {} as EncryptedPayload }],
  })
  return rows.map((row) => ('data' in row ? row.data : row.error))
}

export async function noCodeField(): Promise<void> {
  const [row] = await decryptBulkFallible(client, { ciphertexts: [] })
  if (row && 'error' in row) {
    // @ts-expect-error `code` is a Neon-wrapper addition, not part of the wasm
    // result. Declaring it optional here would promise something Rust never
    // sends.
    row.code
  }
}

// --- newClient now takes the SAME options as the Neon entry ---------------
// Both bindings deserialize one Rust `NewClientOptions`: credentials nested
// under `clientOpts`, `authStrategy` optional, keyset alongside. When no
// strategy is passed, `CredentialOpts::build_strategy()` resolves an
// `AccessKeyStrategy` from `clientOpts.accessKey` + `workspaceCrn` — the wasm
// arm of `AutoStrategy`, which is access-key-only because there is no
// filesystem to fall back to.

export const client_: Promise<WasmClient> = newClient({
  encryptConfig: { v: 2, tables: { users: { email: { cast_as: 'text' } } } },
  clientOpts: {
    clientId: '00000000-0000-0000-0000-000000000000',
    clientKey: 'deadbeef',
    workspaceCrn: 'crn:ap-southeast-2.aws:ABC',
    accessKey: 'CSAK.test',
  },
})

export const withStrategy: Promise<WasmClient> = newClient({
  encryptConfig: { v: 2, tables: {} },
  clientOpts: {
    clientId: '00000000-0000-0000-0000-000000000000',
    clientKey: 'deadbeef',
    keyset: { Name: 'default' },
  },
  authStrategy,
  eqlVersion: 3,
})

// No strategy and no access key is legal at the type layer — the Rust reports
// it, because whether credentials resolve is a runtime question on both
// bindings.
export const bare: Promise<WasmClient> = newClient({
  encryptConfig: { v: 2, tables: {} },
})

// The deprecated alias still type-checks.
export const deprecatedName: Promise<WasmClient> = newClient({
  encryptConfig: { v: 2, tables: {} },
  strategy: authStrategy,
})

// The public `cast_as` spellings are accepted here now: normalisation moved
// into the Rust, so this binding takes the same config the Neon entry does
// rather than requiring a pre-canonicalised one.
export const publicVocabulary: Promise<WasmClient> = newClient({
  encryptConfig: { v: 2, tables: { users: { email: { cast_as: 'string' } } } },
})

export const flatCredentials = newClient({
  encryptConfig: { v: 2, tables: {} },
  // @ts-expect-error credentials live under `clientOpts` on both bindings now;
  // the flat top-level form this build used to take is gone.
  clientId: '00000000-0000-0000-0000-000000000000',
})
