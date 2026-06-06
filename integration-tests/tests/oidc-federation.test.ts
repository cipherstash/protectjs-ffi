// Pending scaffold for the `OidcFederation` auth strategy.
//
// `stack-auth` introduced an `OidcFederation` strategy, surfaced to JS via
// `@cipherstash/auth`. From protect-ffi's perspective it is just another
// `opts.strategy` — the native boundary duck-types on the
// `AuthStrategy = { getToken: () => Promise<{ token: string }> }` contract
// (see `src/index.cts`) and never branches on the concrete strategy type.
// So there is nothing new to test on the FFI side; the coverage that matters
// is consumer-side wiring, and it mirrors `js-strategy.test.ts` (Neon path)
// and `wasm-round-trip.test.ts` (wasm path).
//
// # Why most of this file is skipped
//
// The hermetic end-to-end coverage is blocked on two upstream additions in
// `@cipherstash/auth` (tracked in cipherstash/cipherstash-suite):
//
//   1. `OidcFederation` is not exported yet by the installed auth build
//      (0.38.0 exposes only AutoStrategy / AccessKeyStrategy / OAuthStrategy
//      on the node entry, and AccessKeyStrategy on `wasm-inline`).
//   2. `MockAuthServer` only mocks the device-code / OAuth endpoints
//      (`/oauth/device/token`, `/create-client`). A hermetic federation test
//      needs a mock for the OIDC token-*exchange* endpoint plus a base-URL
//      override on `OidcFederation.create(...)` (a `test-utils`-gated variant,
//      the same pattern as `beginDeviceCodeFlowWithBaseUrl`).
//
// Until those land, the hermetic block below stays `describe.skip` so it
// documents the intended shape without executing against an API that does
// not exist. The live block at the bottom exercises the part that is real
// today: the FFI accepts and drives any `getToken`-shaped strategy, and a
// rejected token propagates as a client error — the contract `OidcFederation`
// will satisfy. It needs no credentials and no network (the strategy guards
// run before serde and before any ZeroKMS call).
//
// TODO(auth bump): once `@cipherstash/auth` exports `OidcFederation` and
// `MockAuthServer` gains an OIDC-exchange mock + base-URL override, replace
// the placeholder strategy with the real one, drop the `.skip`, and gate on
// the export existing (see `hasOidcFederation` below) instead of skipping
// unconditionally.

import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type AuthStrategy,
  type ClientOpts,
  newClient,
} from '@cipherstash/protect-ffi'

import { encryptConfig } from './common.js'

const clientOpts: ClientOpts = {
  clientId: process.env.CS_CLIENT_ID,
  clientKey: process.env.CS_CLIENT_KEY,
}

// Flips to `true` once the auth package exports the strategy. Used to gate
// the hermetic block in place of the unconditional `.skip` after the bump.
//
// import * as auth from '@cipherstash/auth'
// const hasOidcFederation = typeof (auth as { OidcFederation?: unknown }).OidcFederation === 'function'
const hasOidcFederation = false

// ---------------------------------------------------------------------------
// Hermetic end-to-end — PENDING the auth-package additions described above.
// ---------------------------------------------------------------------------
describe.skip('OidcFederation (hermetic, pending auth bump)', () => {
  test('round-trips encrypt/decrypt via a mocked OIDC exchange', async () => {
    // const mock = await MockAuthServer.start()
    // mock.mockOidcExchangeEndpoint()   // upstream addition
    // mock.mockCreateClientEndpoint()
    //
    // const strategy = OidcFederation.createWithBaseUrl(
    //   { issuer: 'https://issuer.test', audience: 'cipherstash', token: 'fake.id.jwt' },
    //   mock.baseUrl,                    // test-utils override
    // )
    //
    // const client = await newClient({ encryptConfig, clientOpts, strategy })
    // const ciphertext = await encrypt(client, {
    //   plaintext: 'alice@example.com', table: 'users', column: 'email',
    // })
    // expect(isEncrypted(ciphertext)).toBe(true)
    // expect(await decrypt(client, { ciphertext })).toBe('alice@example.com')
    expect(hasOidcFederation).toBe(true)
  })

  test('surfaces a rejected OIDC exchange as a client error', async () => {
    // const mock = await MockAuthServer.start()
    // mock.mockTokenEndpointError('invalid_grant', 'expired id token')
    // const strategy = OidcFederation.createWithBaseUrl(/* … */, mock.baseUrl)
    // await expect(
    //   newClient({ encryptConfig, clientOpts, strategy }),
    // ).rejects.toThrow(/invalid_grant|expired/)
    expect(hasOidcFederation).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Live today — the FFI strategy contract `OidcFederation` plugs into. No
// credentials or network: the strategy shape is validated, and `getToken`
// rejections propagate, before any ZeroKMS call. This is the same guarantee
// `js-strategy.test.ts` proves generically; kept here as an OIDC-labelled
// anchor so the contract is asserted against the exact `opts.strategy` path
// the real `OidcFederation` will travel.
// ---------------------------------------------------------------------------
describe('OidcFederation strategy contract', () => {
  test('a rejected getToken propagates as a client error', async () => {
    // Stand-in for `OidcFederation` until it is exported: any object
    // satisfying `AuthStrategy` reaches the same native code path.
    const strategy: AuthStrategy = {
      async getToken() {
        throw new Error('OIDC exchange failed (placeholder for OidcFederation)')
      },
    }

    await expect(
      newClient({ encryptConfig, clientOpts, strategy }),
    ).rejects.toThrow(/OIDC exchange failed/)
  })
})
