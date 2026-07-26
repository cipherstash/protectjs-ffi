// This module is the CJS entry point for the library.

import { withEncodedPlaintext, withEncodedPlaintexts } from './bigintWire.js'
import { type CredentialOpts, withEnvCredentials } from './credentials.js'
import * as native from './load.cjs'
export {
  withEnvCredentials,
  type EnvReader,
  type CredentialOpts,
} from './credentials.js'
export * from './eql-v3.js'
import type { EncryptedV3, EncryptedV3Query } from './eql-v3.js'
import { ProtectError, inferErrorCode, normalizeError } from './errors.js'
export { ProtectError, type ProtectErrorCode } from './errors.js'

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

async function wrapAsync<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (err) {
    throw normalizeError(err)
  }
}

function wrapSync<T>(fn: () => T): T {
  try {
    return fn()
  } catch (err) {
    throw normalizeError(err)
  }
}

export function newClient(opts: NewClientOptions): Promise<Client> {
  return wrapAsync(() =>
    native.newClient(
      {
        encryptConfig: opts.encryptConfig,
        clientOpts: withEnvCredentials(opts.clientOpts),
        eqlVersion: opts.eqlVersion,
      },
      // `strategy` is the old name for `authStrategy`, kept working while it is
      // deprecated. The new name wins when both are set.
      opts.authStrategy ?? opts.strategy,
    ),
  )
}

export function encrypt(
  client: Client,
  opts: EncryptOptions,
): Promise<EncryptedPayload> {
  return wrapAsync(() => native.encrypt(client, withEncodedPlaintext(opts)))
}

export function decrypt(
  client: Client,
  opts: DecryptOptions,
): Promise<JsPlaintext> {
  return wrapAsync(() => native.decrypt(client, opts))
}

/**
 * True when `encrypted` is a stored EQL payload in EITHER wire format:
 * an EQL v2.3 payload (`k: "ct"` / `k: "sv"`) or an EQL v3 payload
 * (`{v: 3, i, c}` scalar or `{v: 3, k: "sv", i, sv}` SteVec document).
 * Query payloads (including the v3 containment needle) are not stored
 * payloads and return false.
 */
export function isEncrypted(encrypted: unknown): boolean {
  return wrapSync(() => native.isEncrypted(encrypted))
}

export function encryptBulk(
  client: Client,
  opts: EncryptBulkOptions,
): Promise<EncryptedPayload[]> {
  return wrapAsync(() => {
    const plaintexts = withEncodedPlaintexts(opts.plaintexts)
    return native.encryptBulk(
      client,
      plaintexts === opts.plaintexts ? opts : { ...opts, plaintexts },
    )
  })
}

export function decryptBulk(
  client: Client,
  opts: DecryptBulkOptions,
): Promise<JsPlaintext[]> {
  return wrapAsync(() => native.decryptBulk(client, opts))
}

export async function decryptBulkFallible(
  client: Client,
  opts: DecryptBulkOptions,
): Promise<DecryptResult[]> {
  const results = await wrapAsync(() =>
    native.decryptBulkFallible(client, opts),
  )
  return results.map((item: DecryptResult) => {
    if ('error' in item && typeof item.error === 'string') {
      return { ...item, code: inferErrorCode(item.error) }
    }
    return item
  })
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
export function encryptQuery(
  client: Client,
  opts: EncryptQueryOptions,
): Promise<Encrypted | EncryptedQuery | EncryptedV3Query> {
  return wrapAsync(() =>
    native.encryptQuery(client, withEncodedPlaintext(opts)),
  )
}

/** Bulk variant of {@link encryptQuery} — same EQL v3 shapes apply. */
export function encryptQueryBulk(
  client: Client,
  opts: EncryptQueryBulkOptions,
): Promise<(Encrypted | EncryptedQuery | EncryptedV3Query)[]> {
  return wrapAsync(() => {
    const queries = withEncodedPlaintexts(opts.queries)
    return native.encryptQueryBulk(
      client,
      queries === opts.queries ? opts : { ...opts, queries },
    )
  })
}

/**
 * Test-only helper: ensures a keyset with the given name exists, creating it if necessary,
 * and grants the current client access. Not safe for concurrent use — intended for
 * sequential test setup only.
 */
export function ensureKeyset(
  opts: EnsureKeysetOpts,
): Promise<EnsureKeysetResult> {
  return wrapAsync(() => native.ensureKeyset(withEnvCredentials(opts)))
}

/**
 * Options passed to the native `newClient`.
 *
 * Takes the public {@link EncryptConfig} unchanged. Vocabulary normalisation
 * (`cast_as: 'string'` → `'text'`, the `ste_vec` array-index-mode default)
 * used to happen here in JS; it now runs inside the Rust at the
 * deserialization boundary, so BOTH bindings accept the public spellings and
 * there is one implementation rather than one per entry point. See
 * `crates/protect-ffi/src/encrypt_config.rs`.
 */
type NativeNewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: ClientOpts
  eqlVersion?: 2 | 3
}
