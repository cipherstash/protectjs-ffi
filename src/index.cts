// This module is the CJS entry point for the library.

export {
  newClient,
  encrypt,
  encryptBulk,
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
  function decrypt(client: Client, opts: DecryptOptions): Promise<string>
  function encryptBulk(
    client: Client,
    opts: EncryptBulkOptions,
  ): Promise<Encrypted[]>
  function decryptBulk(
    client: Client,
    opts: DecryptBulkOptions,
  ): Promise<string[]>
  function decryptBulkFallible(
    client: Client,
    opts: DecryptBulkOptions,
  ): Promise<DecryptResult[]>
}

export type DecryptResult = { data: string } | { error: string }

export type EncryptPayload = {
  plaintext: string
  column: string
  table: string
  lockContext?: Context
}

export type BulkDecryptPayload = {
  ciphertext: string
  lockContext?: Context
}

export type CtsToken = {
  accessToken: string
  expiry: number
}

export type Context = {
  identityClaim: string[]
}

export type Encrypted = {
  k: string
  c: string
  ob: string[] | null
  bf: number[] | null
  hm: string | null
  i: {
    c: string
    t: string
  }
  v: number
}

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
}

export type EncryptOptions = {
  plaintext: string
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
  ciphertext: string
  lockContext?: Context
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

export type DecryptBulkOptions = {
  ciphertexts: BulkDecryptPayload[]
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}
