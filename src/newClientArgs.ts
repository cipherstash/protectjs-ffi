import { withEnvCredentials } from './credentials.js'
import type { AuthStrategy, ClientOpts, EncryptConfig } from './types.js'
import type { NewClientOptions } from './types.js'

/**
 * The options object the addon actually receives — `NewClientOptions` minus the
 * auth strategy, which travels separately.
 *
 * Takes the public {@link EncryptConfig} unchanged. Vocabulary normalisation
 * (`cast_as: 'string'` → `'text'`, the `ste_vec` array-index-mode default)
 * used to happen here in JS; it now runs inside the Rust at the
 * deserialization boundary, so BOTH bindings accept the public spellings and
 * there is one implementation rather than one per entry point. See
 * `crates/protect-ffi/src/encrypt_config.rs`.
 */
export type NativeNewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: ClientOpts
  eqlVersion?: 2 | 3
}

/**
 * Split `newClient`'s options into the two arguments the addon takes.
 *
 * The strategy cannot ride along inside the options object: neon's `Json`
 * extractor is `JSON.stringify`-based, which drops functions, so the addon
 * takes it as a separate `Root<JsObject>` argument. The wasm entry solves the
 * same problem by pulling it off with `Reflect::get` before serde runs.
 *
 * Its own module, rather than inline in `index.cts`, so it is reachable from a
 * unit test — vitest cannot transform `.cts`, and the alternative is an
 * integration test that needs real credentials to reach the line under test.
 */
export function newClientArgs(
  opts: NewClientOptions,
): [NativeNewClientOptions, AuthStrategy | undefined] {
  // Pull out only what this layer has to handle — the auth strategy and
  // `clientOpts` (credentials are filled in from env here). Everything else is
  // forwarded verbatim rather than re-listed field by field, so a key the Rust
  // doesn't recognise reaches serde and is rejected by name instead of being
  // quietly dropped on the way through. The wasm entry rejects the same input
  // the same way.
  const { authStrategy, strategy, clientOpts, ...rest } = opts
  return [
    { ...rest, clientOpts: withEnvCredentials(clientOpts) },
    // `strategy` is the old name for `authStrategy`, kept working while it is
    // deprecated. The new name wins when both are set — a rename is only safe
    // if it does, or a caller mid-migration passing both silently keeps the old
    // object.
    authStrategy ?? strategy,
  ]
}
