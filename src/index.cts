// This module is the CJS entry point for the library.

export { encrypt, encryptBulk, newClient, decryptBulk } from './load.cjs'
import { decrypt as ffiDecrypt } from './load.cjs'

declare const sym: unique symbol

// Poor man's opaque type.
export type Client = { readonly [sym]: unknown }

// Use this declaration to assign types to the protect-ffi's exports,
// which otherwise default to `any`.
declare module './load.cjs' {
  function newClient(encryptSchema: string): Promise<Client>
  function encrypt(
    client: Client,
    plaintext: EncryptPayload,
    ctsToken?: CtsToken,
  ): Promise<Encrypted>
  function decrypt(
    client: Client,
    ciphertext: string,
    context?: Context,
    ctsToken?: CtsToken,
  ): Promise<string>
  function encryptBulk(
    client: Client,
    plaintextTargets: EncryptPayload[],
    ctsToken?: CtsToken,
  ): Promise<Encrypted[]>
  function decryptBulk(
    client: Client,
    ciphertexts: BulkDecryptPayload[],
    ctsToken?: CtsToken,
  ): Promise<string[]>
}

export function decrypt(
  client: Client,
  ciphertext: string,
  lockContext?: Context,
  ctsToken?: CtsToken,
): Promise<string> {
  if (ctsToken) {
    return ffiDecrypt(client, ciphertext, lockContext, ctsToken)
  }

  if (lockContext) {
    return ffiDecrypt(client, ciphertext, lockContext)
  }

  return ffiDecrypt(client, ciphertext)
}

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
  o: string[] | null
  m: number[] | null
  u: string | null
  i: {
    c: string
    t: string
  }
  v: number
}
