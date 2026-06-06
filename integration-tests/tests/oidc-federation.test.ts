// Coverage for the `OidcFederation` auth strategy.
//
// `stack-auth` introduced an `OidcFederationStrategy` that federates a
// third-party OIDC JWT (Clerk, Supabase, …) into a CipherStash CTS service
// token via `POST /api/authorise`. It is surfaced to JS by `@cipherstash/auth`
// (>= 0.39.0) on both the node and `wasm-inline` entries.
//
// From protect-ffi's perspective it is just another `opts.strategy`: the
// native boundary duck-types on the
// `AuthStrategy = { getToken: () => Promise<{ token: string }> }` contract
// (see `src/index.cts`) and never branches on the concrete strategy type. So
// there is nothing new to test on the FFI side — the coverage that matters is
// consumer-side wiring, mirroring `js-strategy.test.ts` (Neon path) and
// `wasm-round-trip.test.ts` (wasm path).
//
// # Two tiers
//
//   1. Contract (runs in CI today, no credentials, no network): the real
//      published `OidcFederationStrategy` constructs via its `.create` factory
//      and exposes `getToken`, and a `getToken`-shaped strategy threads through
//      protect-ffi's `newClient` with rejections propagating as client errors.
//
//   2. End-to-end (gated on OIDC env): a real federation round-trip —
//      third-party JWT → CTS token → encrypt → decrypt. `describe.skipIf` keeps
//      it a no-op until the env vars below are set, matching how every other
//      credentialed suite behaves.
//
// A fully *hermetic* round-trip via `@cipherstash/auth`'s `MockAuthServer` is
// not possible through the published consumer API: the mock is napi-only (the
// integration tests run on the `wasm-inline` entry) and the public
// `OidcFederationStrategy.create` exposes no base-URL override to point a
// strategy at the mock (that override is `test-utils`-gated inside stack-auth
// and used only by its own internal tests). Hence the live exchange is
// env-gated rather than mocked.

import 'dotenv/config'
import { OidcFederationStrategy } from '@cipherstash/auth/wasm-inline'
import { describe, expect, test } from 'vitest'

import {
  type AuthStrategy,
  type ClientOpts,
  decrypt,
  encrypt,
  isEncrypted,
  newClient,
} from '@cipherstash/protect-ffi'

import { encryptConfig } from './common.js'

const clientOpts: ClientOpts = {
  clientId: process.env.CS_CLIENT_ID,
  clientKey: process.env.CS_CLIENT_KEY,
}

// `OidcFederationStrategy.create(region, workspaceId, getJwt)` takes the
// region (`<region>.<provider>`) and workspace id as separate args — both are
// segments of a CRN like `crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY`.
function splitCrn(crn: string): { region: string; workspaceId: string } {
  const match = crn.match(/^crn:([^:]+):(.+)$/)
  if (!match) {
    throw new Error(`unexpected CS_WORKSPACE_CRN format: ${crn}`)
  }
  return { region: match[1], workspaceId: match[2] }
}

// ---------------------------------------------------------------------------
// Contract — no credentials, no network.
// ---------------------------------------------------------------------------
describe('OidcFederation strategy contract', () => {
  test('the published strategy constructs and exposes getToken', () => {
    // Exercises the real `@cipherstash/auth` factory + signature, not a stand-in.
    // Region/workspace/JWT are arbitrary — `.create` does no I/O, so this stays
    // offline; the federation call would only happen on `getToken()`.
    const strategy = OidcFederationStrategy.create(
      'ap-southeast-2.aws',
      'ZVATKW3VHMFG27DY',
      () => 'third-party.oidc.jwt',
    )

    expect(typeof strategy.getToken).toBe('function')
    // It satisfies the FFI's structural `AuthStrategy` contract.
    const asStrategy: AuthStrategy = strategy
    expect(asStrategy).toBeDefined()
  })

  test('a rejected getToken propagates as a client error', async () => {
    // The OidcFederationStrategy reaches `newClient` through the exact
    // `opts.strategy` path asserted here; a `getJwt`/federation failure
    // surfaces as a rejected `getToken`, which must reach the caller. The
    // strategy guards run before any ZeroKMS call, so no credentials/network.
    const strategy: AuthStrategy = {
      async getToken() {
        throw new Error('OIDC federation exchange failed')
      },
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/OIDC federation exchange failed/)
  })
})

// ---------------------------------------------------------------------------
// End-to-end — gated on a real third-party OIDC JWT + dataset credentials.
//
// Set CS_OIDC_JWT to a third-party OIDC token the target workspace is
// configured to federate, plus the usual CS_WORKSPACE_CRN / CS_CLIENT_ID /
// CS_CLIENT_KEY. Absent any of these the suite is skipped, exactly like the
// other credentialed suites.
// ---------------------------------------------------------------------------
const E2E_ENV = [
  'CS_OIDC_JWT',
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
] as const
const missingE2eEnv = E2E_ENV.filter((k) => !process.env[k])

describe.skipIf(missingE2eEnv.length > 0)('OidcFederation end-to-end', () => {
  test('federates an OIDC JWT and round-trips encrypt/decrypt', async () => {
    const jwt = process.env.CS_OIDC_JWT
    const crn = process.env.CS_WORKSPACE_CRN
    if (!jwt || !crn) {
      throw new Error('unreachable: skipIf gates this')
    }
    const { region, workspaceId } = splitCrn(crn)

    // `getJwt` is re-invoked on every (re-)federation; here it just returns the
    // pre-minted token from the environment.
    const strategy = OidcFederationStrategy.create(
      region,
      workspaceId,
      () => jwt,
    )

    const client = await newClient({ encryptConfig, clientOpts, strategy })

    const plaintext = 'alice@example.com'
    const ciphertext = await encrypt(client, {
      plaintext,
      table: 'users',
      column: 'email',
    })

    expect(isEncrypted(ciphertext)).toBe(true)
    expect(await decrypt(client, { ciphertext })).toBe(plaintext)
  })
})
