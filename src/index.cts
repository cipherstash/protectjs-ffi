// This module is the CJS entry point for the library.

export { encrypt, encryptBulk, newClient, decryptBulk } from './load.cjs'
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
  function newClient(
    encryptSchema: string,
    clientOpts?: string,
  ): Promise<Client>
  function encrypt(
    client: Client,
    plaintext: EncryptPayload,
    ctsToken?: CtsToken,
    unverifiedContext?: Record<string, unknown>,
  ): Promise<Encrypted>
  function decrypt(
    client: Client,
    ciphertext: string,
    // unverifiedContext?: Record<string, unknown>,
    context?: Context,
    ctsToken?: CtsToken,
  ): Promise<string>
  function encryptBulk(
    client: Client,
    plaintextTargets: EncryptPayload[],
    // unverifiedContext?: Record<string, unknown>,
    ctsToken?: CtsToken,
  ): Promise<Encrypted[]>
  function decryptBulk(
    client: Client,
    ciphertexts: BulkDecryptPayload[],
    // unverifiedContext?: Record<string, unknown>,
    ctsToken?: CtsToken,
  ): Promise<string[]>
  function decryptBulkFallible(
    client: Client,
    ciphertexts: BulkDecryptPayload[],
    // unverifiedContext?: Record<string, unknown>,
    ctsToken?: CtsToken,
  ): Promise<DecryptResult[]>
}

export function decrypt(
  client: Client,
  ciphertext: string,
  // unverifiedContext: Record<string, unknown> = {},
  lockContext?: Context,
  ctsToken?: CtsToken,
): Promise<string> {
  if (ctsToken) {
    return ffiDecrypt(
      client,
      ciphertext,
      // unverifiedContext,
      lockContext,
      ctsToken,
    )
  }

  if (lockContext) {
    return ffiDecrypt(client, ciphertext, /* unverifiedContext, */ lockContext)
  }

  return ffiDecrypt(client, ciphertext /*, unverifiedContext */)
}

export function decryptBulkFallible(
  client: Client,
  ciphertexts: BulkDecryptPayload[],
  // unverifiedContext: Record<string, unknown> = {},
  ctsToken?: CtsToken,
): Promise<DecryptResult[]> {
  if (ctsToken) {
    return ffiDecryptBulkFallible(
      client,
      ciphertexts,
      // unverifiedContext,
      ctsToken,
    )
  }

  return ffiDecryptBulkFallible(client, ciphertexts /* , unverifiedContext */)
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
