// This module is the CJS entry point for the library.

export {
  newClient,
  encrypt,
  encryptBulk,
  decryptBulk,
} from './load.cjs'
import {
  decrypt as ffiDecrypt,
  decryptBulkFallible as ffiDecryptBulkFallible,
} from './load.cjs'

declare const sym: unique symbol

// Poor man's opaque type.
export type Client = { readonly [sym]: unknown }

// Use this declaration to assign types to the protect-ffi's exports,
// which otherwise default to `any`.
declare module './load.cjs' {
  function newClient(opts: NewClientOptions): Promise<Client>
  function encrypt(
    client: Client,
    opts: EncryptOptions,
  ): Promise<Encrypted>
  function decrypt(
    client: Client,
    opts: DecryptOptions,
  ): Promise<string>
  function encryptBulk(
    client: Client,
    opts: EncryptBulkOptions,
  ): Promise<Encrypted[]>
  function decryptBulk(
    client: Client,
    ciphertexts: BulkDecryptPayload[],
    ctsToken?: CtsToken,
  ): Promise<string[]>
  function decryptBulkFallible(
    client: Client,
    ciphertexts: BulkDecryptPayload[],
    ctsToken?: CtsToken,
  ): Promise<DecryptResult[]>
}

export function decrypt(
  client: Client,
  opts: DecryptOptions,
): Promise<string> {
  return ffiDecrypt(client, opts)
}

export function decryptBulkFallible(
  client: Client,
  ciphertexts: BulkDecryptPayload[],
  ctsToken?: CtsToken,
): Promise<DecryptResult[]> {
  if (ctsToken) {
    return ffiDecryptBulkFallible(client, ciphertexts, ctsToken)
  }

  return ffiDecryptBulkFallible(client, ciphertexts)
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

export type NewClientOptions = {
  encryptConfig: string
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
}

export type EncryptBulkOptions = {
  plaintexts: EncryptPayload[]
  serviceToken?: CtsToken
}

export type DecryptOptions = {
  ciphertext: string
  lockContext?: Context
  serviceToken?: CtsToken
}
