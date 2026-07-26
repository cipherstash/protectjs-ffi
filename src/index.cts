// This module is the CJS entry point for the library.

import { withEncodedPlaintext, withEncodedPlaintexts } from './bigintWire.js'
import { type CredentialOpts, withEnvCredentials } from './credentials.js'
import { type NativeNewClientOptions, newClientArgs } from './newClientArgs.js'
import * as native from './load.cjs'
export {
  withEnvCredentials,
  type EnvReader,
  type CredentialOpts,
} from './credentials.js'
export * from './eql-v3.js'
import type { EncryptedV3, EncryptedV3Query } from './eql-v3.js'
export {
  PROTECT_ERROR_CODES,
  isProtectErrorCode,
  type ProtectErrorCode,
} from './errors.js'

/**
 * The wire-shape types now live in `./types.js` so the wasm build can name them
 * too — see the header there, and #142. Re-exported wholesale, so this entry's
 * public surface is exactly what it was.
 */
export * from './types.js'
import type {
  AuthStrategy,
  ClientOpts,
  DecryptBulkOptions,
  DecryptOptions,
  DecryptResult,
  EncryptBulkOptions,
  EncryptConfig,
  EncryptOptions,
  EncryptQueryBulkOptions,
  EncryptQueryOptions,
  Encrypted,
  EncryptedPayload,
  EncryptedQuery,
  EnsureKeysetOpts,
  EnsureKeysetResult,
  JsPlaintext,
  NewClientOptions,
} from './types.js'

declare const sym: unique symbol

// Poor man's opaque type.
export type Client = { readonly [sym]: unknown }

// Use this declaration to assign types to the protect-ffi's exports,
// which otherwise default to `any`.
declare module './load.cjs' {
  function newClient(
    opts: NativeNewClientOptions,
    strategy?: AuthStrategy,
  ): Promise<Client>
  function encrypt(
    client: Client,
    opts: EncryptOptions,
  ): Promise<EncryptedPayload>
  function decrypt(client: Client, opts: DecryptOptions): Promise<JsPlaintext>
  function isEncrypted(encrypted: unknown): boolean
  function encryptBulk(
    client: Client,
    opts: EncryptBulkOptions,
  ): Promise<EncryptedPayload[]>
  function decryptBulk(
    client: Client,
    opts: DecryptBulkOptions,
  ): Promise<JsPlaintext[]>
  function decryptBulkFallible(
    client: Client,
    opts: DecryptBulkOptions,
  ): Promise<DecryptResult[]>
  function encryptQuery(
    client: Client,
    opts: EncryptQueryOptions,
  ): Promise<Encrypted | EncryptedQuery | EncryptedV3Query>
  function encryptQueryBulk(
    client: Client,
    opts: EncryptQueryBulkOptions,
  ): Promise<(Encrypted | EncryptedQuery | EncryptedV3Query)[]>
  function ensureKeyset(opts: EnsureKeysetOpts): Promise<EnsureKeysetResult>
}

// Errors are not touched on the way out. Rust builds the JS `Error` and sets
// `code` on it (#146), so there is nothing left for this layer to add — it used
// to re-wrap every failure in a `ProtectError` carrying a code inferred from the
// message, which is the thing that went.
//
// Every promise-returning export below is `async` for one reason worth stating,
// because it looks like a redundant keyword on a function whose body is a
// single `return`: neon extracts arguments SYNCHRONOUSLY. A bad `client` handle,
// or an options object serde rejects — including every unknown-key rejection
// from #144 — throws from the call itself rather than rejecting the promise it
// would otherwise have returned. So does `withEncodedPlaintext` on an
// out-of-range bigint. `async` is what keeps those as rejections now that the
// try/catch wrapper is gone; drop it and `.catch()` stops seeing them.

export async function newClient(opts: NewClientOptions): Promise<Client> {
  return native.newClient(...newClientArgs(opts))
}

export async function encrypt(
  client: Client,
  opts: EncryptOptions,
): Promise<EncryptedPayload> {
  return native.encrypt(client, withEncodedPlaintext(opts))
}

export async function decrypt(
  client: Client,
  opts: DecryptOptions,
): Promise<JsPlaintext> {
  return native.decrypt(client, opts)
}

/**
 * True when `encrypted` is a stored EQL payload in EITHER wire format:
 * an EQL v2.3 payload (`k: "ct"` / `k: "sv"`) or an EQL v3 payload
 * (`{v: 3, i, c}` scalar or `{v: 3, k: "sv", i, sv}` SteVec document).
 * Query payloads (including the v3 containment needle) are not stored
 * payloads and return false.
 */
export function isEncrypted(encrypted: unknown): boolean {
  return native.isEncrypted(encrypted)
}

export async function encryptBulk(
  client: Client,
  opts: EncryptBulkOptions,
): Promise<EncryptedPayload[]> {
  const plaintexts = withEncodedPlaintexts(opts.plaintexts)
  return native.encryptBulk(
    client,
    plaintexts === opts.plaintexts ? opts : { ...opts, plaintexts },
  )
}

export async function decryptBulk(
  client: Client,
  opts: DecryptBulkOptions,
): Promise<JsPlaintext[]> {
  return native.decryptBulk(client, opts)
}

/**
 * Per-item results are returned exactly as Rust serialises them.
 *
 * This used to re-walk the array adding `code` to every failed item by running
 * `inferErrorCode` over its message, because the code existed nowhere else.
 * Rust sets it now (#146), which is also what makes it available on the wasm
 * entry — that build has no JS wrapper to do the second pass.
 */
export async function decryptBulkFallible(
  client: Client,
  opts: DecryptBulkOptions,
): Promise<DecryptResult[]> {
  return native.decryptBulkFallible(client, opts)
}

/**
 * Encrypt a query term.
 *
 * Scalar-only configurations default to `eqlVersion: 2` and return the v2
 * query shapes. Configurations containing `ste_vec` default to v3; client 0.42
 * cannot emit the selector-bound SteVec envelope as v2.
 *
 * Under `eqlVersion: 3` this returns an {@link EncryptedV3Query}:
 *
 * - Scalar index queries (`unique` / `ore` / `ope` / `match`) produce the
 *   term-only operand for the column domain's query twin (`{v, i, <terms>}`,
 *   no `c` ciphertext) — bind with `col = $1::jsonb::eql_v3.query_<name>`.
 *   The operand always carries ALL the column domain's terms, whichever
 *   `indexType` was queried.
 * - JSON containment queries produce the `eql_v3.query_json` needle — bind
 *   with `doc @> $1::jsonb::eql_v3.query_json`.
 * - `ste_vec_selector` queries produce the bare selector hash (a string) —
 *   bind as the `text` argument of `->` / `->>`.
 * - `ste_vec_value_selector` queries accept `{path, value}` and produce a
 *   one-entry selector-only containment needle for exact equality.
 */
export async function encryptQuery(
  client: Client,
  opts: EncryptQueryOptions,
): Promise<Encrypted | EncryptedQuery | EncryptedV3Query> {
  return native.encryptQuery(client, withEncodedPlaintext(opts))
}

/** Bulk variant of {@link encryptQuery} — same EQL v3 shapes apply. */
export async function encryptQueryBulk(
  client: Client,
  opts: EncryptQueryBulkOptions,
): Promise<(Encrypted | EncryptedQuery | EncryptedV3Query)[]> {
  const queries = withEncodedPlaintexts(opts.queries)
  return native.encryptQueryBulk(
    client,
    queries === opts.queries ? opts : { ...opts, queries },
  )
}

/**
 * Test-only helper: ensures a keyset with the given name exists, creating it if necessary,
 * and grants the current client access. Not safe for concurrent use — intended for
 * sequential test setup only.
 */
export async function ensureKeyset(
  opts: EnsureKeysetOpts,
): Promise<EnsureKeysetResult> {
  return native.ensureKeyset(withEnvCredentials(opts))
}
