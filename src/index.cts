// This module is the CJS entry point for the library.

export {
  newClient,
  encrypt,
  encryptBulk,
  encryptQuery,
  encryptQueryBulk,
  isEncrypted,
  decrypt,
  decryptBulk,
  decryptBulkFallible,
} from './load.cjs'

declare const sym: unique symbol

// Poor man's opaque type.
export type Client = { readonly [sym]: unknown }

// Use this declaration to assign types to the protect-ffi's exports,
// which otherwise default to `any`.
declare module './load.cjs' {
  function newClient(opts: NewClientOptions): Promise<Client>
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
  function encryptQuery(client: Client, opts: EncryptQueryOptions): Promise<Encrypted>
  function encryptQueryBulk(client: Client, opts: EncryptQueryBulkOptions): Promise<Encrypted[]>
}

export type DecryptResult = { data: string } | { error: string }

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
 * Represents encrypted data in the EQL format.
 *
 * This TypeScript type mirrors the Rust `EqlCiphertext` structure from `cipherstash-client`.
 * The Rust type hierarchy is:
 * - `EqlCiphertext` (identifier + version + body)
 *   - `EqlCiphertextBody` (ciphertext + SEM fields + array flag)
 *     - `EqlSEM` (all searchable encrypted metadata fields)
 *
 * In the serialized JSON format, `#[serde(flatten)]` is used in Rust to produce a flat
 * structure where all fields appear at the top level rather than nested.
 *
 * Note: The ciphertext field (c) is serialized in MessagePack Base85 format.
 */
export type Encrypted = {
  /** The table and column identifier */
  i: { t: string; c: string }
  /** The encryption version */
  v: number
  /** The encrypted ciphertext (mp_base85 encoded, optional for query-mode payloads) */
  c?: string
  /** Whether this encrypted value is part of an array */
  a?: boolean
  /** ORE block index for 64-bit integers */
  ob?: string[]
  /** Bloom filter for approximate match queries */
  bf?: number[]
  /** HMAC-SHA256 hash for exact matches */
  hm?: string
  /** Selector value for field selection (SteVec) */
  s?: string
  /** Blake3 hash for exact matches (SteVec) */
  b3?: string
  /** ORE CLLW fixed-width index for 64-bit values (SteVec) */
  ocf?: string
  /** ORE CLLW variable-width index for strings (SteVec) */
  ocv?: string
  /** Structured encryption vector entries (recursive) */
  sv?: EqlCiphertextBody[]
}

/**
 * Body of an EQL ciphertext, used recursively in SteVec entries.
 */
export type EqlCiphertextBody = {
  /** The encrypted ciphertext (mp_base85 encoded) */
  c?: string
  /** Whether this entry is part of an array */
  a?: boolean
  /** Selector value for field selection */
  s?: string
  /** Blake3 hash for exact matches */
  b3?: string
  /** ORE CLLW fixed-width index */
  ocf?: string
  /** ORE CLLW variable-width index */
  ocv?: string
  /** Nested SteVec entries (for deeply nested JSON) */
  sv?: EqlCiphertextBody[]
}

/** @deprecated Use EqlCiphertextBody instead */
export type SteVecEntry = EqlCiphertextBody

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
  | 'string'
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

export type SteVecIndexOpts = {
  prefix: string
}

export type Tokenizer =
  | { kind: 'standard' }
  | { kind: 'ngram'; token_length: number }

export type TokenFilter = { kind: 'downcase' }

export type NewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: ClientOpts
}

export type ClientOpts = {
  workspaceCrn?: string
  accessKey?: string
  clientId?: string
  clientKey?: string
  keyset?: KeysetIdentifier
}

export type KeysetIdentifier = { Uuid: string } | { Name: string }

export type JsPlaintext =
  | string
  | number
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
