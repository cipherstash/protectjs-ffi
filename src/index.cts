// This module is the CJS entry point for the library.

// The Rust addon.
import * as addon from './load.cjs'

// Use this declaration to assign types to the jseql's exports,
// which otherwise by default are `any`.
declare module './load.cjs' {
  interface Client {}

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

export function newClient(encryptSchema?: string): Promise<addon.Client> {
  return addon.newClient(encryptSchema)
}

export const encrypt = addon.encrypt

export function decrypt(
  client: addon.Client,
  ciphertext: string,
  lockContext?: Context,
  ctsToken?: CtsToken,
): Promise<string> {
  if (ctsToken) {
    return addon.decrypt(client, ciphertext, lockContext, ctsToken)
  }

  if (lockContext) {
    return addon.decrypt(client, ciphertext, lockContext)
  }

  return addon.decrypt(client, ciphertext)
}

export function encryptBulk(
  client: addon.Client,
  plaintextTargets: EncryptPayload[],
  ctsToken?: CtsToken,
): Promise<string[]> {
  if (ctsToken) {
    return addon.encryptBulk(client, plaintextTargets, ctsToken)
  }

  return addon.encryptBulk(client, plaintextTargets)
}

export function decryptBulk(
  client: addon.Client,
  ciphertexts: BulkDecryptPayload[],
  ctsToken?: CtsToken,
): Promise<string[]> {
  if (ctsToken) {
    return addon.decryptBulk(client, ciphertexts, ctsToken)
  }

  return addon.decryptBulk(client, ciphertexts)
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

export type EncryptedEqlPayload = {
  c: string
}

export type BulkEncryptedEqlPayload = {
  c: string
  id: string
}[]
