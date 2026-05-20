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

declare const sym: unique symbol

// Poor man's opaque type.
export type Client = { readonly [sym]: unknown }

// Use this declaration to assign types to the protect-ffi's exports,
// which otherwise default to `any`.
declare module './load.cjs' {
  function newClient(opts: NativeNewClientOptions): Promise<Client>
  function encrypt(client: Client, opts: EncryptOptions): Promise<Encrypted>
  function decrypt(client: Client, opts: DecryptOptions): Promise<JsPlaintext>
  function isEncrypted(encrypted: Encrypted): boolean
  function encryptBulk(
    client: Client,
    opts: EncryptBulkOptions,
  ): Promise<Encrypted[]>
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
  ): Promise<Encrypted>
  function encryptQueryBulk(
    client: Client,
    opts: EncryptQueryBulkOptions,
  ): Promise<Encrypted[]>
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
    native.newClient({
      encryptConfig: normalizeEncryptConfig(opts.encryptConfig),
      clientOpts: withEnvCredentials(opts.clientOpts),
    }),
  )
}

export function encrypt(
  client: Client,
  opts: EncryptOptions,
): Promise<Encrypted> {
  return wrapAsync(() => native.encrypt(client, opts))
}

export function decrypt(
  client: Client,
  opts: DecryptOptions,
): Promise<JsPlaintext> {
  return wrapAsync(() => native.decrypt(client, opts))
}

export function isEncrypted(encrypted: Encrypted): boolean {
  return wrapSync(() => native.isEncrypted(encrypted))
}

export function encryptBulk(
  client: Client,
  opts: EncryptBulkOptions,
): Promise<Encrypted[]> {
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

export function encryptQuery(
  client: Client,
  opts: EncryptQueryOptions,
): Promise<Encrypted> {
  return wrapAsync(() => native.encryptQuery(client, opts))
}

export function encryptQueryBulk(
  client: Client,
  opts: EncryptQueryBulkOptions,
): Promise<Encrypted[]> {
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
  ciphertext: Encrypted
  lockContext?: Context
}

export type CtsToken = {
  accessToken: string
  expiry: number
}

export type Context = {
  identityClaim: string[]
}

/**
 * Represents an EQL v2.3 payload returned by the FFI.
 *
 * This TypeScript type mirrors the Rust `EqlCiphertext` enum from `cipherstash-client`,
 * which is a discriminated union keyed on `k`:
 * - `k: "ct"` — scalar payload with root-scope index terms (`c`, `hm`, `bf`, `ob`).
 *   Storage payloads always carry `c`; query payloads omit `c`.
 * - `k: "sv"` — STE-vector payload with per-selector entries in `sv`.
 *   Storage payloads carry the root ciphertext at `sv[0].c`; query payloads
 *   carry either a single selector (`s`) or a containment vector (`q`).
 */
export type Encrypted = {
  /** EQL v2.3 root discriminator — `"ct"` for scalar, `"sv"` for STE-vector */
  k: 'ct' | 'sv'
  /** The encryption version */
  v: number
  /** The table and column identifier */
  i: { t: string; c: string }
  /** Encrypted ciphertext (mp_base85). Present on scalar storage payloads; absent on scalar queries. */
  c?: string
  /** HMAC-SHA256 hash for exact-match equality (unique index) */
  hm?: string
  /** Bloom filter (set bit positions) for LIKE / ILIKE (match index) */
  bf?: number[]
  /** Block ORE u64_8_256 term for ordered comparisons (ore index) */
  ob?: string[]
  /** Per-selector SteVec entries (present on `k:"sv"` storage payloads) */
  sv?: SteVecEntry[]
  /** Tokenized selector for `ste_vec_selector` queries (present on `k:"sv"` query payloads) */
  s?: string
  /** CLLW ORE term for `ste_vec_term` queries (present on `k:"sv"` query payloads) */
  oc?: string
  /** Full STE query vector for JSON containment queries (present on `k:"sv"` containment queries) */
  q?: unknown
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
  | 'number'
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
  unique?: UniqueIndexOpts
  match?: MatchIndexOpts
  ste_vec?: SteVecIndexOpts
}

export type OreIndexOpts = Record<string, never>

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
}

/** Options passed to the native `newClient` after vocabulary normalization. */
type NativeNewClientOptions = {
  encryptConfig: NativeEncryptConfig
  clientOpts?: ClientOpts
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
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type EncryptBulkOptions = {
  plaintexts: EncryptPayload[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type DecryptOptions = {
  ciphertext: Encrypted
  lockContext?: Context
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type DecryptBulkOptions = {
  ciphertexts: BulkDecryptPayload[]
  serviceToken?: CtsToken
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
  serviceToken?: CtsToken
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
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}
