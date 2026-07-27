// `clientOpts` must mean the same thing on both bindings.
//
// This PR routes the wasm `newClient` through the shared `NewClientOptions`,
// whose `ClientOpts` carries `#[serde(flatten)] creds: CredentialOpts`.
// `flatten` makes serde buffer the whole map — it cannot know which keys
// belong to the flattened struct until it has read them all — so *every*
// value in `clientOpts` is deserialized via `deserialize_any`, including
// keys the struct does not declare.
//
// serde-wasm-bindgen's `deserialize_any` (de.rs:284-333) handles only
// JSON-ish values: nullish, bool, bigint, number, string, array, bytes, and
// objects that are either a `Map` or carry no `Symbol.iterator`. Anything
// else lands in `invalid_type`. Without `flatten` those keys would go to
// `deserialize_ignored_any`, which the same crate implements as
// `visitor.visit_unit()` (de.rs:609-611) — skipped without ever being looked
// at. That is how the wasm binding behaved before this PR, when it had its
// own flatten-free `NewClientOpts`.
//
// Neon cannot reach the failure: its `Json` extractor is
// `serde_json::from_str(&stringify(cx, v)?)` (neon-1.1.1
// types_impl/extract/json.rs:100), so `JSON.stringify` has already dropped
// the function before serde runs.
//
// The result is a caller who builds one `clientOpts` for both entries and
// puts anything on it beyond the declared fields — a logger, a callback, a
// tags `Set` — getting a hard `newClient` failure on wasm and silence on
// Neon.
//
// Every assertion below compares a call against the same call without the
// stray key, on the same binding. Nothing asserts a particular message. These
// are deliberately red while wasm treats the undeclared value differently;
// they encode the existing Neon/main contract that an undeclared key is
// ignored. A resolution that instead rejects unknown keys on both bindings
// would need assertions for that different contract.
//
// # Prerequisites
//
// `npm run build:wasm` and a debug Neon build, both of which
// `mise run test:integration` already does. No credentials and no network:
// every clean call carries an invalid `eqlVersion`, which is rejected after
// deserialization but before auth. A stray value that reaches serde replaces
// that deterministic failure with its own type error.

import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

import { newClient as neonNewClient } from '@cipherstash/protect-ffi'
import { beforeAll, describe, expect, test } from 'vitest'

const WASM_INLINE_PATH = resolve(
  __dirname,
  '..',
  '..',
  'dist',
  'wasm',
  'protect_ffi_inline.js',
)

type NewClient = (opts: Record<string, unknown>) => Promise<unknown>

const encryptConfig = {
  v: 1,
  tables: { users: { email: { cast_as: 'text' } } },
}

// Structurally valid so deserialization has no reason of its own to complain.
// Never used against a real service — every call here stops before network.
const clientId = '00000000-0000-0000-0000-000000000000'
const clientKey = 'ab'.repeat(32)

const clean = () => ({
  encryptConfig,
  clientOpts: { clientId, clientKey },
  // Deliberately invalid: resolve_eql_version rejects this after options have
  // deserialized and before either binding can consult ambient credentials.
  eqlVersion: 4,
})

const withExtra = (extra: unknown) => ({
  encryptConfig,
  clientOpts: { clientId, clientKey, extra },
  eqlVersion: 4,
})

/**
 * Resolve `newClient` to the message it rejects with, or `null` when it
 * succeeds. Comparing messages is the point: a stray key that is correctly
 * ignored leaves the message identical to the clean call, and one that
 * reaches serde replaces it with a type error.
 */
async function failureOf(fn: NewClient, opts: Record<string, unknown>) {
  try {
    await fn(opts)
    return null
  } catch (e) {
    return String((e as Error)?.message ?? e).split('\n')[0]
  }
}

// Values a caller plausibly hangs off a shared options object. `Map` is here
// deliberately: serde-wasm-bindgen special-cases it, so it is the boundary of
// what survives and pins that the failure is about iterables and functions
// rather than "any non-plain object".
const STRAY_VALUES: [string, () => unknown][] = [
  ['a callback', () => () => {}],
  ['a Set', () => new Set([1, 2])],
  ['a Map', () => new Map([['k', 'v']])],
  ['a generator', () => (function* () {})()],
]

describe('clientOpts parity across bindings', () => {
  let wasmNewClient: NewClient

  beforeAll(async () => {
    if (!existsSync(WASM_INLINE_PATH)) {
      throw new Error(
        `wasm-inline build not found at ${WASM_INLINE_PATH}. Run \`npm run build:wasm\` from the repo root first.`,
      )
    }
    const mod = (await import(WASM_INLINE_PATH)) as { newClient: NewClient }
    wasmNewClient = mod.newClient
  })

  test.each(STRAY_VALUES)(
    'wasm newClient ignores %s in clientOpts',
    async (_label, make) => {
      // The stray key is not a declared field, so it must not change where
      // the call fails. Equality — not merely "no type error" — because a
      // divergence that swaps one failure for another is still a divergence.
      expect(await failureOf(wasmNewClient, withExtra(make()))).toBe(
        await failureOf(wasmNewClient, clean()),
      )
    },
  )

  test.each(STRAY_VALUES)(
    'neon newClient ignores %s in clientOpts',
    async (_label, make) => {
      expect(
        await failureOf(
          neonNewClient as unknown as NewClient,
          withExtra(make()),
        ),
      ).toBe(await failureOf(neonNewClient as unknown as NewClient, clean()))
    },
  )

  // The asymmetry that makes this easy to miss in review: the very same
  // function is harmless at the top level, because `NewClientOptions` has no
  // flatten and serde-wasm-bindgen never inspects an ignored key. `newClient`
  // already relies on this — `authStrategy` is a function-carrying object
  // sitting at the top level, and it survives serde untouched.
  test('wasm tolerates a callback at the top level', async () => {
    const topLevel = {
      encryptConfig,
      onRetry: () => {},
      clientOpts: { clientId, clientKey },
      eqlVersion: 4,
    }

    expect(await failureOf(wasmNewClient, topLevel)).toBe(
      await failureOf(wasmNewClient, clean()),
    )
  })
})
