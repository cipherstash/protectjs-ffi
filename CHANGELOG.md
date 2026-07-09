# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is pre-1.0, breaking changes are released as minor version
bumps and called out under a `Breaking` heading — an addition to the standard
Keep a Changelog categories (Added/Changed/Deprecated/Removed/Fixed/Security).

Add notes for unreleased work under the `[Unreleased]` heading below. On
release, the `version` npm lifecycle hook promotes that section to a dated
release entry (see `scripts/changelog-release.mjs`), and the release workflow
uses the promoted section as the GitHub release notes.

## [Unreleased]

### Added

- **EQL v3 scalar query-term encryption (CIP-3423).** On an `eqlVersion: 3`
  client, `encryptQuery` / `encryptQueryBulk` on a scalar index now return the
  term-only operand for the column domain's query twin — `{v: 3, i, <terms>}`
  with **no `c` ciphertext** — bindable as
  `col = $1::jsonb::eql_v3.query_<name>` (and the ordering / `@>` match
  operators). The operand always carries ALL the column domain's terms
  (`text_search_ore` → `hm` + `ob` + `bf`), whichever `indexType` was queried:
  the EQL v3 operators pair each column domain only with its same-name query
  twin, whose domain CHECK requires the full term set. Terms derive from the
  same conversion as storage encryption, so bounds behaviour (e.g. bigint i64
  boundary rejection) is identical. This replaces the interim
  full-storage-envelope workaround — query operands no longer carry a
  decryptable ciphertext through query strings and SQL logs.
- **EQL v3 selector queries.** `queryOp: 'ste_vec_selector'` on a v3 client
  returns the bare selector hash as a **string** (there is no
  encrypted-selector envelope in v3) — bind it as the `text` argument of the
  `->` / `->>` operators. It is the same `Selector` encoding SteVec entries
  carry in `s`.
- The vendored EQL v3 TypeScript types now include the 38 scalar query-twin
  payload types (`TextEqQuery`, `IntegerOrdOreQuery`, …), exported alongside a
  new `EncryptedV3ScalarQuery` union.

### Changed

- Bumped `eql-bindings` to `3.0.0` (from `3.0.0-alpha.3`) and
  `cipherstash-client` (with `cts-common`, `stack-auth`, `stack-profile`) to
  `0.40.0` (from `0.39.1`). The EQL v3 SQL snapshot and the vendored
  `src/eql-v3-types/**` TypeScript types were regenerated from the newly
  locked release (`mise run eql:v3:build`, `scripts/sync-eql-v3-types.sh`).
- Bumped `eql-bindings` to `3.0.0-alpha.3` (from `0.4.2`): catalog-generated
  scalar `QueryPayload` variants, scalar term hoisting in `from_v2_query`, and
  the CIP-3442 domain rename — query operands are `eql_v3.query_<name>` /
  `eql_v3.query_jsonb` (the pre-release `jsonb_query` name is gone), column
  domains live in `public.*`.
- The integration-test EQL v3 SQL snapshot
  (`integration-tests/sql/cipherstash-encrypt-v3.sql`) is now extracted from
  the locked `eql-bindings` release (`eql_bindings::sql::INSTALL_SQL`, via the
  `print_eql_v3_sql` example) instead of a sibling checkout, and was refreshed
  to EQL `3.0.0-alpha.3` — column domains are now `public.<name>` and the
  `eql_v3.query_*` operand domains exist. Rebuild with `mise run eql:v3:build`
  after bumping `eql-bindings`.
- v3 scalar queries perform a full storage-mode encryption internally (the
  ciphertext is computed, then dropped when the terms are hoisted) — the same
  trade the JSON containment path already makes.

### Breaking

- **EQL v3 public column domains are versioned (CIP-3472).** Every
  public-schema column domain gained an `eql_v3_` prefix: a column declared
  `email public.text_eq` is now `email public.eql_v3_text_eq`, and
  `public.json` is `public.eql_v3_json`. The term-only query twins are
  unchanged (`eql_v3.query_text_eq`) — the `eql_v3` schema already versions
  them. Existing v3 tables must be migrated to the new column types.
- **`text_search` now means OPE, not ORE.** The bare search domain carries
  `hm` + `op` + `bf`; the ORE search domain is the new
  `eql_v3_text_search_ore` (`hm` + `ob` + `bf`). A `unique` + `ore` + `match`
  text column therefore targets `eql_v3_text_search_ore` and binds against
  `eql_v3.query_text_search_ore`. The same flip applies to the bare
  `<family>_ord` domains upstream; protect-ffi only ever selects the explicit
  `_ord_ore` / `_ord_ope` variants, which are unaffected. As a result,
  `unique` + `ope` + `match` on text now resolves (to `eql_v3_text_search`)
  where it previously errored.
- **The `ste_vec` index mode default flipped to `compat`** in
  `cipherstash-client` 0.40.0 (it was `standard`). An unconfigured JSON
  column now emits CLLW-OPE `op` SteVec terms instead of CLLW-ORE `oc` — in
  **v2 output as well as v3**. Indexes built under the two modes are not
  cross-comparable, so JSON columns with existing rows must either pin
  `mode: 'standard'` or be re-encrypted.
- **EQL v3 requires `compat`-mode `ste_vec`.** v3 orders SteVec entries by
  the `op` term under native byte comparison; ORE ciphertext bytes do not
  order that way, so `oc` has no mechanical conversion. A `standard`-mode
  JSON column on an `eqlVersion: 3` client now fails at configuration time
  with `EQL_V3_UNSUPPORTED_COLUMN` rather than converting incorrectly.
- The `OreCllw` TypeScript type is removed — v3 SteVec entries carry `hm` XOR
  `op`, so `oc` no longer appears in any v3 payload. `TextSearchOre` and
  `TextSearchOreQuery` are added.
- The `EQL_V3_QUERY_UNSUPPORTED` error code is removed from
  `ProtectErrorCode` — the scalar and selector queries that threw it now
  succeed and return operands.
- `EncryptedV3Query` widened from `SteVecQuery` to
  `EncryptedV3ScalarQuery | SteVecQuery | Selector`. Code that assumed every
  v3 query payload has an `sv` key must narrow first; selector results are
  plain strings.

### Fixed

- **`AuthStrategy` now types the contract the runtime already implements.** Both
  the Node (Neon) and WASM clients have accepted either a bare `{ token }` or a
  `@byteslice/result` envelope (`{ data: { token } }` / `{ failure }`) since
  `0.28.0`, but the exported `AuthStrategy` type still declared only
  `getToken: () => Promise<{ token: string }>`. That made every
  `@cipherstash/auth` `>= 0.41` strategy — whose `getToken()` resolves the
  envelope — unassignable to `newClient`'s `opts.strategy`, so downstream
  consumers hit `TS2322` on code that runs correctly. `getToken` may now resolve
  `TokenResult | TokenResultEnvelope`; both are exported. The bare shape is
  unchanged, so this is backward compatible.

  The WASM `newClient` doc comment said the same thing and has been corrected.

  Nothing here exercised the mismatch: `integration-tests` pins
  `@cipherstash/auth ^0.39.0` (pre-`Result`), so `oidc-federation.test.ts`
  compiled against the old shape. Added type-level coverage in
  `src/index.types.test.ts` asserting both shapes assign.

## [0.28.0] - 2026-07-08

### Added

- Support for `@cipherstash/auth` `0.41`'s `@byteslice/result` `Result`-shaped
  `getToken()` — `{ data: { token, … } }` on success, `{ failure: { type,
  error, … } }` on error — on both the Node (Neon) and WASM auth paths. The
  bare `{ token }` shape (the documented `getToken(): Promise<{ token }>`
  contract, used by `@cipherstash/auth` `<= 0.40` and custom strategies) is
  still accepted, so this is backward compatible. A `failure` result is
  reconstructed into the real `stack_auth::AuthError` via
  `AuthError::from_error_code`, preserving its code (e.g. `NOT_AUTHENTICATED`,
  `EXPIRED_TOKEN`) rather than flattening every failure to `Server`; unknown or
  foreign codes become `AuthError::Custom`. On the WASM path the structured
  payload rides along too, so `WORKSPACE_MISMATCH` round-trips; the Node path
  reconstructs by code + message (there `WORKSPACE_MISMATCH` surfaces as
  `Custom`, with the workspace detail preserved in the message).
- `CHANGELOG.md` plus automated release notes. On `npm version`, the `version`
  lifecycle hook promotes the `[Unreleased]` section to a dated entry
  (`scripts/changelog-release.mjs`); the release workflow then publishes that
  section as the GitHub release body (`scripts/changelog-extract.mjs`).

### Changed

- Bumped `cipherstash-client`, `cts-common`, `stack-auth`, and `stack-profile`
  to `0.39.1`. `stack-auth`'s `AuthError::Server` now wraps a `ServerError`
  newtype rather than a bare `String`, and `0.39.1` adds
  `AuthError::from_error_code` (the reconstruction the auth bridge now uses).

## [0.26.0] - 2026-06-08

### Changed

- Bumped `cipherstash-client` and `stack-auth` to `0.37.0`.
- npm publishing now uses OIDC trusted publishing, and the release publish job
  was hardened (the publisher app token is scoped to `contents:write`).

### Added

- Integration coverage for the `OidcFederation` auth strategy, wired against
  `@cipherstash/auth` 0.39.0.

### Fixed

- Point the `dryrun` npm script at `release.yml`.

## [0.25.0] - 2026-05-29

### Breaking

- Removed `serviceToken` from `EncryptOptions`, `DecryptOptions`, and the query
  option types.
- Removed the `CtsToken` public type export.
- Auth environment updated for stack-auth 0.36: `CS_REGION` is dropped in favour
  of `CS_WORKSPACE_CRN`.

### Added

- `newClient` now accepts an optional `opts.strategy` (an `AuthStrategy`,
  `@cipherstash/auth`-shaped object) on **both Node and WASM**. When supplied,
  `getToken()` is invoked on every ZeroKMS request. On WASM the strategy is
  **required** (there is no env/filesystem fallback); on Node it is optional and
  falls back to the `AutoStrategy` built from credentials / profile.

### Fixed

- Node: capture a per-isolate Neon `Channel` for the JS-backed strategy, and
  `unref` it so scripts can exit cleanly after a round trip.
- Node: wrap the `getToken` JS call in `Context::try_catch` so a strategy that
  throws (or otherwise misbehaves) surfaces as a clean error instead of an
  unhandled rejection.

### Changed

- Bumped `cipherstash-client`, `cts-common`, `stack-auth`, and `stack-profile`
  to `0.36.0`.
- Expanded integration coverage: JS-backed auth contract, event-loop-exit, and
  `newClient` guard tests.

## [0.24.0] - 2026-05-26

### Added

- WASM build target: a `wasm-bindgen` surface (`src/wasm.rs`), a build pipeline
  with CI integration, and an end-to-end round-trip integration test.

### Fixed

- WASM: match Neon's flat API shape and drop the `@ts-self-types` directive from
  the inline shim.
- WASM: wrap the `client_key` hex in a `ZeroizeOnDrop` newtype from
  deserialization, with tighter typing and zeroize for client credentials.
- WASM: use `CanonicalEncryptionConfig` after the config refactor.

### Changed

- `cfg`-gate Neon-only code so `wasm32` compiles.
- Bumped dependencies for a wasm-ready `cipherstash-client` and `vitaminc`.

## [0.23.0] - 2026-05-21

### Fixed

- Types: split the storage `Encrypted` payload from the query payload types.
- Types: forbid ciphertext on `EncryptedScalarQuery`.

## [0.22.0] - 2026-05-20

### Added

- Expose the STE-vector encoding mode option.
- Normalize encrypt config vocabulary at the FFI boundary, including a
  `normalizeEncryptConfig` `cast_as` translation helper.

### Changed

- Replace the hand-rolled encrypt config with `CanonicalEncryptionConfig`
  (see the migration notes documented in this release for breaking config
  changes).
- Upgrade `cipherstash-client` to `0.35.0`.

[Unreleased]: https://github.com/cipherstash/protectjs-ffi/compare/v0.28.0...HEAD
[0.28.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.26.0...v0.28.0
[0.26.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.21.4...v0.22.0
