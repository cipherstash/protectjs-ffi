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
  function encrypt(client: Client, opts: EncryptOptions): Promise<Encrypted>
  function decrypt(client: Client, opts: DecryptOptions): Promise<JsPlaintext>
  function isEncrypted(encrypted: Encrypted): boolean
  function encryptQuery(client: Client, opts: QueryOptions): Promise<EncryptedQueryTerm>
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
}

export type DecryptResult = { data: string } | { error: string }

export type EncryptPayload = {
  plaintext: JsPlaintext
  column: string
  table: string
  lockContext?: Context[]
}

export type BulkDecryptPayload = {
  ciphertext: Encrypted
  lockContext?: Context[]
}

export type CtsToken = {
  accessToken: string
  expiry: number
}

// TODO: Handle the Value type as well
export type Context = { identityClaim: string } | { tag: string }

export type Versioned = { v: number };

// Named term types
export type Base85Ciphertext = string;
export type BloomFilter = number[];
export type HMAC = string;
export type EncodedBlockOREArray = string[];
export type EncodedFixedLengthORE = string;
export type EncodedVariableLengthORE = string;
export type JSONPathSelector = string;

export type EncryptedCT = Versioned & {
  k: 'ct';
  c: Base85Ciphertext;
  ob: EncodedBlockOREArray | null;
  bf: BloomFilter | null;
  hm: HMAC | null;
  i: { c: string; t: string };
};

export type EncryptedSV = Versioned & {
  k: 'sv';
  sv: SteVecEncryptedEntry[];
  i: { c: string; t: string };
};

// NOTE: We don't currently get the version or identifiers back from an SteVec entry
// This is a limitation of EQL v2
export type EncryptedSVE = {
  k: 'sve';
  sve: SteVecEncryptedEntry;
}

export type Encrypted = EncryptedCT | EncryptedSV | EncryptedSVE;

export type SteVecEncryptedEntry = {
  s: JSONPathSelector
  c: Base85Ciphertext
  parent_is_array: boolean
} & SteVecTerm;

export type SteVecTerm = { hm: HMAC } | { ocf: EncodedFixedLengthORE } | { ocv: EncodedVariableLengthORE };

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

export type EncryptOptions = {
  plaintext: JsPlaintext
  column: string
  table: string
  lockContext?: Context[]
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
  lockContext?: Context[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type DecryptBulkOptions = {
  ciphertexts: BulkDecryptPayload[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type QueryOptions = {
  plaintext: JsPlaintext
  column: string
  table: string
  operator: QueryOperator
}

export type QueryOperator =
  | '<'
  | '<='
  | '='
  | '>='
  | '>'
  | '~~'
  | '~~*'
  | '@>'
  | '<@'
  | '->'

// These types are included in responses from encryptQuery
export type EncryptedQueryTerm =
  | { ob: EncodedBlockOREArray }
  | { bf: BloomFilter }
  | { hm: HMAC }
  | { s: JSONPathSelector }
