# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is pre-1.0, breaking changes are released as minor version bumps.

Add notes for unreleased work under the `[Unreleased]` heading below. On
release, the `version` npm lifecycle hook promotes that section to a dated
release entry (see `scripts/changelog-release.mjs`), and the release workflow
uses the promoted section as the GitHub release notes.

## [Unreleased]

### Added

- `CHANGELOG.md` plus automated release notes. On `npm version`, the `version`
  lifecycle hook promotes the `[Unreleased]` section to a dated entry
  (`scripts/changelog-release.mjs`); the release workflow then publishes that
  section as the GitHub release body (`scripts/changelog-extract.mjs`).

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

[Unreleased]: https://github.com/cipherstash/protectjs-ffi/compare/v0.26.0...HEAD
[0.26.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.21.4...v0.22.0
