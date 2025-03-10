// This module is the CJS entry point for the library.

export { encrypt, encryptBulk, newClient, decryptBulk } from './load.cjs'
import { decrypt as ffiDecrypt } from './load.cjs'

declare const sym: unique symbol

// Poor man's opaque type.
export type Client = { readonly [sym]: unknown }

// Use this declaration to assign types to the jseql's exports,
// which otherwise by default are `any`.
declare module './load.cjs' {
  function newClient(encryptSchema?: string): Promise<Client>
  function encrypt(
    client: Client,
    plaintext: EncryptPayload,
    ctsToken?: CtsToken,
  ): Promise<string>
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
  ): Promise<string[]>
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
