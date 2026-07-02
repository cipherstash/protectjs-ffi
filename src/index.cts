// This module is the CJS entry point for the library.

import { type CredentialOpts, withEnvCredentials } from './credentials.js'
import * as native from './load.cjs'
import {
  type NativeEncryptConfig,
  normalizeEncryptConfig,
} from './normalizeEncryptConfig.js'
export {
  withEnvCredentials,
  type EnvReader,
  type CredentialOpts,
} from './credentials.js'
export * from './eql-v3.js'
import type { EncryptedV3, EncryptedV3Query } from './eql-v3.js'

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

export type ProtectErrorCode =
  | 'INVARIANT_VIOLATION'
  | 'UNKNOWN_QUERY_OP'
  | 'UNKNOWN_COLUMN'
  | 'MISSING_INDEX'
  | 'INVALID_QUERY_INPUT'
  | 'INVALID_JSON_PATH'
  | 'STE_VEC_REQUIRES_JSON_CAST_AS'
  | 'MATCH_REQUIRES_TEXT'
  | 'UNSUPPORTED_CONFIG_VERSION'
  | 'INVALID_EQL_VERSION'
  | 'EQL_V3_QUERY_UNSUPPORTED'
  | 'EQL_V3_UNSUPPORTED_COLUMN'
  | 'UNKNOWN'

export class ProtectError extends Error {
  code: ProtectErrorCode
  details?: unknown
  cause?: unknown

  constructor(opts: {
    code: ProtectErrorCode
    message: string
    details?: unknown
    cause?: unknown
  }) {
    super(opts.message)
    this.name = 'ProtectError'
    this.code = opts.code
    this.details = opts.details
    this.cause = opts.cause
  }
}

export type DecryptResult =
  | { data: JsPlaintext }
  | { error: string; code?: ProtectErrorCode }

function inferErrorCode(message: string): ProtectErrorCode {
  if (message.startsWith('protect-ffi invariant violation:')) {
    return 'INVARIANT_VIOLATION'
  }
  if (message.startsWith('Unknown query operation:')) {
    return 'UNKNOWN_QUERY_OP'
  }
  if (message.startsWith('Invalid query input for')) {
    return 'INVALID_QUERY_INPUT'
  }
  if (message.startsWith('Invalid JSON path')) {
    return 'INVALID_JSON_PATH'
  }
  if (message.includes(' not found in Encrypt config')) {
    return 'UNKNOWN_COLUMN'
  }
  if (message.includes(' index configured')) {
    return 'MISSING_INDEX'
  }
  if (message.includes('requires plaintext_type: json')) {
    return 'STE_VEC_REQUIRES_JSON_CAST_AS'
  }
  if (message.includes('requires plaintext_type: text')) {
    return 'MATCH_REQUIRES_TEXT'
  }
  if (message.includes('unsupported config version')) {
    return 'UNSUPPORTED_CONFIG_VERSION'
  }
  if (message.startsWith('Invalid eqlVersion')) {
    return 'INVALID_EQL_VERSION'
  }
  if (
    message.startsWith('EQL v3 scalar query') ||
    message.startsWith('EQL v3 selector query')
  ) {
    return 'EQL_V3_QUERY_UNSUPPORTED'
  }
  if (message.includes('cannot be represented in EQL v3')) {
    return 'EQL_V3_UNSUPPORTED_COLUMN'
  }
  return 'UNKNOWN'
}

function normalizeError(err: unknown): unknown {
  if (err instanceof ProtectError) {
    return err
  }

  if (err && typeof err === 'object' && 'message' in err) {
    const message = String(
      (err as { message?: unknown }).message ?? 'Unknown error',
    )
    const code = inferErrorCode(message)
    if (code !== 'UNKNOWN') {
      return new ProtectError({ code, message, cause: err })
    }
  }

  return err
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
        encryptConfig: normalizeEncryptConfig(opts.encryptConfig),
        clientOpts: withEnvCredentials(opts.clientOpts),
        eqlVersion: opts.eqlVersion,
      },
      opts.strategy,
    ),
  )
}

export function encrypt(
  client: Client,
  opts: EncryptOptions,
): Promise<EncryptedPayload> {
  return wrapAsync(() => native.encrypt(client, opts))
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
 * (`{v: 3, i, c}` scalar or `{v: 3, i, sv}` SteVec document). Query
 * payloads (including the v3 containment needle) are not stored payloads
 * and return false.
 */
export function isEncrypted(encrypted: unknown): boolean {
  return wrapSync(() => native.isEncrypted(encrypted))
}

export function encryptBulk(
  client: Client,
  opts: EncryptBulkOptions,
): Promise<EncryptedPayload[]> {
  return wrapAsync(() => native.encryptBulk(client, opts))
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
 * Under `eqlVersion: 2` (default) this returns the v2 shapes ({@link
 * Encrypted} for JSON containment, {@link EncryptedQuery} otherwise).
 *
 * Under `eqlVersion: 3` only JSON containment queries are supported and
 * return the `eql_v3.jsonb_query` needle ({@link EncryptedV3Query}). Scalar
 * index queries (`unique` / `ore` / `match`) and `ste_vec_selector` queries
 * throw `EQL_V3_QUERY_UNSUPPORTED` — no EQL v3 scalar/selector query wire
 * shape exists yet, so those queries require an `eqlVersion: 2` client.
 */
export function encryptQuery(
  client: Client,
  opts: EncryptQueryOptions,
): Promise<Encrypted | EncryptedQuery | EncryptedV3Query> {
  return wrapAsync(() => native.encryptQuery(client, opts))
}

/** Bulk variant of {@link encryptQuery} — same EQL v3 restrictions apply. */
export function encryptQueryBulk(
  client: Client,
  opts: EncryptQueryBulkOptions,
): Promise<(Encrypted | EncryptedQuery | EncryptedV3Query)[]> {
  return wrapAsync(() => native.encryptQueryBulk(client, opts))
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

export type EncryptPayload = {
  plaintext: JsPlaintext
  column: string
  table: string
  lockContext?: Context
}

export type BulkDecryptPayload = {
  ciphertext: EncryptedPayload
  lockContext?: Context
}

export type Context = {
  identityClaim: string[]
}

/**
 * EQL v2.3 **storage** payload — the shape persisted in an `eql_v2_encrypted`
 * column. Returned by {@link encrypt} / {@link encryptBulk}; the only shape
 * {@link decrypt} accepts.
 *
 * Discriminated on `k`. A storage payload always carries the ciphertext — `c`
 * on the scalar variant, or `sv[0].c` on the STE-vector variant. Query payloads
 * carry no ciphertext and are a separate type — see {@link EncryptedQuery}.
 *
 * ```ts
 * if (payload.k === 'sv') {
 *   payload.sv.forEach(...)
 * }
 * ```
 */
export type Encrypted = EncryptedScalar | EncryptedSteVec

/**
 * A stored payload in EITHER wire format: EQL v2.3 ({@link Encrypted}) or
 * EQL v3 ({@link EncryptedV3}). {@link encrypt} / {@link encryptBulk} return
 * the format selected by the client's `eqlVersion`; {@link decrypt} accepts
 * both regardless of `eqlVersion` (data-migration scenarios).
 */
export type EncryptedPayload = Encrypted | EncryptedV3

/** Scalar EQL v2.3 storage payload (`k: "ct"`). */
export type EncryptedScalar = {
  k: 'ct'
  /** EQL schema version */
  v: number
  /** Table and column identifier */
  i: { t: string; c: string }
  /** Encrypted ciphertext (mp_base85). Always present on a storage payload. */
  c: string
  /** HMAC-SHA256 term — present when a `unique` index is configured. */
  hm?: string
  /** Bloom filter (set bit positions) — present when a `match` index is configured. */
  bf?: number[]
  /** Block ORE u64_8_256 term — present when an `ore` index is configured. */
  ob?: string[]
}

/**
 * STE-vector EQL v2.3 storage payload (`k: "sv"`). Carries the per-selector
 * entries in `sv`; the root document ciphertext lives at `sv[0].c`.
 */
export type EncryptedSteVec = {
  k: 'sv'
  v: number
  i: { t: string; c: string }
  /** Per-selector entries; root document ciphertext lives at `sv[0].c`. */
  sv: [SteVecEntry, ...SteVecEntry[]]
  s?: never
}

/**
 * EQL v2.3 **query** payload — an encrypted search term. Returned, alongside
 * {@link Encrypted}, by {@link encryptQuery} / {@link encryptQueryBulk}.
 *
 * Unlike a storage payload, a query payload carries no ciphertext (`c`): it is
 * matched against stored values, never decrypted. It must not be passed to
 * {@link decrypt}.
 *
 * This covers the query shapes protect-ffi currently emits. cipherstash-client
 * additionally defines `k: "sv"` hmac / ore / containment query terms; the FFI
 * does not emit those today — JSON containment queries come back as an
 * {@link EncryptedSteVec} storage payload.
 */
export type EncryptedQuery = EncryptedScalarQuery | EncryptedSteVecSelector

/**
 * Scalar query term (`k: "ct"`, no ciphertext) — a `unique` / `match` / `ore`
 * lookup term carrying exactly one of `hm`, `bf`, or `ob`.
 */
export type EncryptedScalarQuery = {
  k: 'ct'
  /** EQL schema version */
  v: number
  /** Table and column identifier */
  i: { t: string; c: string }
  /** Query payloads carry no ciphertext — discriminates against {@link EncryptedScalar}. */
  c?: never
} & ({ hm: string } | { bf: number[] } | { ob: string[] })

/**
 * STE-vector selector query payload (`ste_vec_selector`) — a tokenized JSON
 * path selector, no ciphertext.
 */
export type EncryptedSteVecSelector = {
  k: 'sv'
  v: number
  i: { t: string; c: string }
  /** Tokenized selector for path queries. */
  s: string
  sv?: never
}

/**
 * One entry inside a SteVec payload (`k: "sv"`).
 *
 * Every element carries `s` (selector), `c` (entry ciphertext), and exactly one
 * per-element equality / ordering term (`hm` or `oc`).
 */
export type SteVecEntry = {
  /** Hex-encoded tokenized selector — deterministic per (path, key) */
  s: string
  /** Per-entry encrypted record (mp_base85 encoded) */
  c: string
  /** Array marker — true when the selector points at a JSON array context */
  a?: boolean
  /** Per-entry HMAC term for non-orderable leaves (objects, arrays, booleans, null) */
  hm?: string
  /** Per-entry CLLW ORE term for orderable leaves (strings, numbers) — Standard mode */
  oc?: string
}

/** @deprecated Use SteVecEntry instead */
export type EqlCiphertextBody = SteVecEntry

export type EncryptConfig = {
  v: number
  tables: Record<string, Record<string, Column>>
}

export type Column = {
  cast_as?: CastAs
  indexes?: Indexes
}

export type CastAs =
  | 'bigint'
  | 'boolean'
  | 'date'
  | 'decimal'
  | 'int'
  | 'number'
  | 'small_int'
  | 'string' // deprecated, use text instead but keep for backwards compatibility
  | 'text'
  | 'timestamp'
  | 'json'

// Extract the tables from a specific config
type TablesOf<C extends EncryptConfig> = C['tables']

// Compute valid { table, column } pairs
export type Identifier<C extends EncryptConfig> = {
  [T in keyof TablesOf<C>]: {
    [CName in keyof TablesOf<C>[T]]: { table: T; column: CName }
  }[keyof TablesOf<C>[T]]
}[keyof TablesOf<C>]

export type Indexes = {
  ore?: OreIndexOpts
  ope?: OpeIndexOpts
  unique?: UniqueIndexOpts
  match?: MatchIndexOpts
  ste_vec?: SteVecIndexOpts
}

export type OreIndexOpts = Record<string, never>

export type OpeIndexOpts = Record<string, never>

export type UniqueIndexOpts = {
  token_filters?: TokenFilter[]
}

export type MatchIndexOpts = {
  tokenizer?: Tokenizer
  token_filters?: TokenFilter[]
  k?: number
  m?: number
  include_original?: boolean
}

export type ArrayIndexMode =
  | 'all'
  | 'none'
  | { item?: boolean; wildcard?: boolean; position?: boolean }

/**
 * Encoding mode for SteVec indexes.
 *
 * - `standard`: standard encoding (default).
 * - `compat`: backwards-compatible encoding. Set explicitly to preserve the
 *   pre-0.34.1-alpha.7 behaviour.
 */
export type SteVecMode = 'compat' | 'standard'

export type SteVecIndexOpts = {
  prefix: string
  term_filters?: TokenFilter[]
  array_index_mode?: ArrayIndexMode
  mode?: SteVecMode
}

export type Tokenizer =
  | { kind: 'standard' }
  | { kind: 'ngram'; token_length: number }

export type TokenFilter = { kind: 'downcase' }

export type NewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: ClientOpts
  /**
   * Caller-supplied auth strategy. When provided, `getToken()` is invoked on
   * every ZeroKMS request and `clientOpts.creds` is ignored for auth (the
   * client key is still required). Without this, the native side builds an
   * AutoStrategy from env / profile / `clientOpts.creds`.
   */
  strategy?: AuthStrategy
  /**
   * EQL wire version this client emits. Defaults to `2` (the
   * `eql_v2_encrypted` payload format).
   *
   * With `3`, {@link encrypt} / {@link encryptBulk} return {@link
   * EncryptedV3} payloads for the `eql_v3` per-capability domains
   * (`eql_v3.text_eq`, `eql_v3.int4_ord_ore`, `eql_v3.json`, …), derived
   * from each column's `cast_as` + indexes. {@link decrypt} accepts BOTH
   * formats regardless of this setting.
   *
   * v3 limitation: {@link encryptQuery} supports only JSON containment
   * queries — scalar-index and selector queries throw
   * `EQL_V3_QUERY_UNSUPPORTED` until a v3 scalar query wire shape exists.
   */
  eqlVersion?: 2 | 3
}

/**
 * Auth strategy shape compatible with `@cipherstash/auth` strategies (e.g.
 * `AccessKeyStrategy`). Only `getToken` is required.
 */
export type AuthStrategy = {
  getToken: () => Promise<{ token: string }>
}

/** Options passed to the native `newClient` after vocabulary normalization. */
type NativeNewClientOptions = {
  encryptConfig: NativeEncryptConfig
  clientOpts?: ClientOpts
  eqlVersion?: 2 | 3
}

export type ClientOpts = CredentialOpts & {
  keyset?: KeysetIdentifier
}

export type KeysetIdentifier = { Uuid: string } | { Name: string }

export type EnsureKeysetOpts = CredentialOpts & {
  name: string
}

export type EnsureKeysetResult = {
  id: string
  name: string
}

export type JsPlaintext =
  | string
  | number
  | boolean
  | Record<string, unknown>
  | JsPlaintext[]

export type EncryptOptions = {
  plaintext: JsPlaintext
  column: string
  table: string
  lockContext?: Context
  unverifiedContext?: Record<string, unknown>
}

export type EncryptBulkOptions = {
  plaintexts: EncryptPayload[]
  unverifiedContext?: Record<string, unknown>
}

export type DecryptOptions = {
  /** A stored payload in either wire format (EQL v2.3 or EQL v3). */
  ciphertext: EncryptedPayload
  lockContext?: Context
  unverifiedContext?: Record<string, unknown>
}

export type DecryptBulkOptions = {
  ciphertexts: BulkDecryptPayload[]
  unverifiedContext?: Record<string, unknown>
}

// Query encryption types
export type IndexTypeName = 'ste_vec' | 'match' | 'ore' | 'unique'

export type QueryOpName = 'default' | 'ste_vec_selector' | 'ste_vec_term'

export type EncryptQueryOptions = {
  plaintext: JsPlaintext
  column: string
  table: string
  indexType: IndexTypeName
  queryOp?: QueryOpName
  lockContext?: Context
  unverifiedContext?: Record<string, unknown>
}

export type QueryPayload = {
  plaintext: JsPlaintext
  column: string
  table: string
  indexType: IndexTypeName
  queryOp?: QueryOpName
  lockContext?: Context
}

export type EncryptQueryBulkOptions = {
  queries: QueryPayload[]
  unverifiedContext?: Record<string, unknown>
}
