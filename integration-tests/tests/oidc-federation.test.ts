// Contract coverage for the `OidcFederation` auth strategy.
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
// the protect-ffi-side coverage that matters is consumer-side wiring: that the
// published strategy satisfies the FFI's `AuthStrategy` shape and that a
// strategy threads through `newClient` with failures propagating. Both run in
// CI unconditionally — no credentials, no network.
//
// # Why there is no live end-to-end round-trip here
//
// A real federation round-trip (third-party JWT → CTS token → encrypt/decrypt)
// is deliberately *not* tested in this repo:
//
//   - The FFI ⇄ wasm-strategy ⇄ ZeroKMS encrypt/decrypt path is already proven
//     by `wasm-round-trip.test.ts` / `js-strategy.test.ts` via
//     `AccessKeyStrategy`. The strategy *type* is irrelevant to the FFI, which
//     only ever calls `getToken`.
//   - The OIDC-specific part (`getJwt` → `/api/authorise` → CTS token) lives
//     entirely inside `stack-auth`, which tests it hermetically with its own
//     `MockAuthServer` + a base-URL override. That override is `test-utils`-
//     gated and not exposed on the published consumer API, so it cannot be
//     reproduced here.
//   - A live round-trip would need a *fresh* third-party OIDC JWT per run (they
//     expire in minutes), so it can't be driven from a static CI secret without
//     real IdP infrastructure — and gating it on an env var that CI never sets
//     would make it permanently skipped: green but inert.

import 'dotenv/config'
import { OidcFederationStrategy } from '@cipherstash/auth/wasm-inline'
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

describe('OidcFederation strategy contract', () => {
  test('the published strategy constructs and exposes getToken', () => {
    // Exercises the real `@cipherstash/auth` factory + signature, not a stand-in.
    // `OidcFederationStrategy.create(region, workspaceId, getJwt)` takes the
    // region (`<region>.<provider>`) and workspace id as separate args. Both are
    // arbitrary here — `.create` does no I/O, so this stays offline; the
    // federation call would only happen on `getToken()`.
    const strategy = OidcFederationStrategy.create(
      'ap-southeast-2.aws',
      'ZVATKW3VHMFG27DY',
      () => 'third-party.oidc.jwt',
    )

    // Compile-time: the wasm strategy is structurally assignable to the FFI's
    // `AuthStrategy`. Runtime: `getToken` — the only member the FFI calls — is
    // callable on that contract-typed handle.
    const asStrategy: AuthStrategy = strategy
    expect(typeof asStrategy.getToken).toBe('function')
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
