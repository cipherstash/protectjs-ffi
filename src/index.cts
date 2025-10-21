// This module is the CJS entry point for the library.

export {
  newClient,
  encrypt,
  encryptBulk,
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
  function encrypt<T extends EncryptConfig>(
    client: Client,
    opts: EncryptOptions<T>,
  ): Promise<AnyEncrypted<T>>
  function decrypt<T extends EncryptConfig>(
    client: Client,
    opts: DecryptOptions<T>,
  ): Promise<JsPlaintext>
  function isEncrypted<T extends EncryptConfig>(
    encrypted: AnyEncrypted<T>,
  ): boolean
  function encryptQuery<T extends EncryptConfig, Q extends EncryptedQueryTerm>(
    client: Client,
    opts: QueryOptions<T>,
  ): Promise<Q>
  function encryptBulk<T extends EncryptConfig>(
    client: Client,
    opts: EncryptBulkOptions<T>,
  ): Promise<AnyEncrypted<T>[]>
  function decryptBulk<T extends EncryptConfig>(
    client: Client,
    opts: DecryptBulkOptions<T>,
  ): Promise<JsPlaintext[]>
  function decryptBulkFallible<T extends EncryptConfig>(
    client: Client,
    opts: DecryptBulkOptions<T>,
  ): Promise<DecryptResult[]>
}

export type DecryptResult = { data: string } | { error: string }

export type EncryptPayload<T extends EncryptConfig> = {
  plaintext: JsPlaintext
  lockContext?: Context[]
} & Identifier<T>

export type BulkDecryptPayload<T extends EncryptConfig> = {
  ciphertext: AnyEncrypted<T>
  lockContext?: Context[]
}

export type CtsToken = {
  accessToken: string
  expiry: number
}

// TODO: Handle the Value type as well
export type Context = { identityClaim: string } | { tag: string }

export type Versioned = { v: number }

// Named term types
export type Base85Ciphertext = string
export type BloomFilter = number[]
export type HMAC = string
export type EncodedBlockOREArray = string[]
export type EncodedFixedLengthORE = string
export type EncodedVariableLengthORE = string
export type JSONPathSelector = string

export type EncryptedCell<T extends EncryptConfig> = Versioned & {
  k: 'ct'
  c: Base85Ciphertext
  ob: EncodedBlockOREArray | null
  bf: BloomFilter | null
  hm: HMAC | null
  i: Identifier<T>
}

export type EncryptedSV<T extends EncryptConfig> = Versioned & {
  k: 'sv'
  sv: SteVecEncryptedEntry[]
  i: Identifier<T>
}

// NOTE: We don't currently get the version or identifiers back from an SteVec entry
// This is a limitation of EQL v2
export type EncryptedSVE = {
  k: 'sve'
  sve: SteVecEncryptedEntry
}

export type AnyEncrypted<T extends EncryptConfig> =
  | EncryptedCell<T>
  | EncryptedSV<T>
  | EncryptedSVE

export type SteVecEncryptedEntry = {
  c: Base85Ciphertext
  parent_is_array: boolean
} & SteVecTerm & { s: JSONPathSelector }

export type SteVecQuery = { svq: SteQueryVecEntry[] }
export type SteQueryVecEntry = { s: JSONPathSelector } & SteVecTerm

export type SteVecTerm =
  | { hm: HMAC }
  | { ocf: EncodedFixedLengthORE }
  | { ocv: EncodedVariableLengthORE }

export type EncryptConfig = {
  v: number
  tables: Record<string, Record<string, Column>>
}

export type Column = {
  cast_as?: CastAs
  indexes?: Indexes
}

export type CastAs =
  | 'big_int'
  | 'boolean'
  | 'date'
  | 'real'
  | 'double'
  | 'int'
  | 'small_int'
  | 'text'
  | 'jsonb'

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
  keyset?: IdentifiedBy
}

// This is a UUID or name
export type IdentifiedBy = string

export type JsPlaintext =
  | string
  | number
  | Record<string, unknown>
  | JsPlaintext[]

export type EncryptOptions<T extends EncryptConfig> = {
  plaintext: JsPlaintext
  lockContext?: Context[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
} & Identifier<T>

export type EncryptBulkOptions<T extends EncryptConfig> = {
  plaintexts: EncryptPayload<T>[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type DecryptOptions<T extends EncryptConfig> = {
  ciphertext: AnyEncrypted<T>
  lockContext?: Context[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type DecryptBulkOptions<T extends EncryptConfig> = {
  ciphertexts: BulkDecryptPayload<T>[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type QueryOptions<T extends EncryptConfig> = {
  plaintext: JsPlaintext
  operator: QueryOperator
} & Identifier<T>

// TODO: Limit these based on the encrypt config
export type NumericOperator = '>' | '>=' | '<' | '<=' | '='
export type StringOperator = '~~' | '~~*' | '='
export type JsonbOperator = '@>' | '<@' | '->'

export type QueryOperator = NumericOperator | StringOperator | JsonbOperator

// These types are included in responses from encryptQuery
export type EncryptedQueryTerm = {}
export interface RangeQuery extends EncryptedQueryTerm {
  ob: EncodedBlockOREArray
}
export interface MatchQuery extends EncryptedQueryTerm {
  bf: BloomFilter
}
export interface ExactQuery extends EncryptedQueryTerm {
  hm: HMAC
}
// Used for stabby queries (->)
export interface JsonSelect extends EncryptedQueryTerm {
  s: JSONPathSelector
}
// Used for contains queries (@>)
export interface JsonContainsQuery extends EncryptedQueryTerm {
  sv: SteQueryVecEntry[]
}
// Used for is-contained-by queries (<@)
export interface JsonIsContainedByQuery extends EncryptedQueryTerm {
  sv: SteQueryVecEntry[]
}
