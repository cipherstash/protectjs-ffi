# Protect.js CipherStash Client FFI

> [!IMPORTANT]
> If you are looking to implement this package into your application please use the official [protect package](https://github.com/cipherstash/protectjs).

This project provides the JS bindings for the CipherStash Client Rust SDK and is bootstrapped by [create-neon](https://www.npmjs.com/package/create-neon).

## Building

Building requires a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support).

To run the build, run:

```sh
$ npm run build
```

This command uses the [@neon-rs/cli](https://www.npmjs.com/package/@neon-rs/cli) utility to assemble the binary Node addon from the output of `cargo`.

## Local setup

You can use the `stash` CLI tool to set up your local environment.

You will be prompted to sign in or create an account and follow steps to create a keyset and client key.

```sh
brew install cipherstash/tap/stash
stash setup
```

## Exploring

After building `protect-ffi`, you can explore its exports at the Node console.
`CS_CLIENT_ID` and `CS_CLIENT_KEY` must be set in your environment for the call to `newClient()` to succeed.

```sh
$ npm i
$ npm run build
$ node
> const addon = require(".");
> const client = await addon.newClient(JSON.stringify({v: 1, tables: {users: {email: {indexes: {ore: {}, match: {}, unique: {}}}}}}));
> const ciphertext = await addon.encrypt(client, "plaintext", "email", "users");
> const plaintext = await addon.decrypt(client, JSON.parse(ciphertext).c);
> console.log({ciphertext, plaintext});
```

## Available Scripts

In the project directory, you can run:

#### `npm run build`

Builds the Node addon (`index.node`) from source, generating a release build with `cargo --release`.

Additional [`cargo build`](https://doc.rust-lang.org/cargo/commands/cargo-build.html) arguments may be passed to `npm run build` and similar commands. For example, to enable a [cargo feature](https://doc.rust-lang.org/cargo/reference/features.html):

```
npm run build -- --feature=beetle
```

#### `npm run debug`

Similar to `npm run build` but generates a debug build with `cargo`.

#### `npm run cross`

Similar to `npm run build` but uses [cross-rs](https://github.com/cross-rs/cross) to cross-compile for another platform. Use the [`CARGO_BUILD_TARGET`](https://doc.rust-lang.org/cargo/reference/config.html#buildtarget) environment variable to select the build target.

#### `npm run release`

Initiate a full build and publication of a new patch release of this library via GitHub Actions.

#### `npm run dryrun`

Initiate a dry run of a patch release of this library via GitHub Actions. This performs a full build but does not publish the final result.

#### `npm test`

Formats and lints Rust and TypeScript code.
Also runs Rust tests.

Note: `npm test` at project root does not run integration tests.
For integration tests, see [below](#integration-tests).

## Project Layout

The directory structure of this project is:

```
protect-ffi/
├── Cargo.toml
├── README.md
├── integration-tests/
├── lib/
├── src/
|   ├── index.mts
|   └── index.cts
├── crates/
|   └── protect-ffi/
|       └── src/
|           └── lib.rs
├── platforms/
├── package.json
└── target/
```

| Entry                | Purpose                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `Cargo.toml`         | The Cargo [manifest file](https://doc.rust-lang.org/cargo/reference/manifest.html), which informs the `cargo` command.             |
| `README.md`          | This file.                                                                                                                         |
| `integration-tests/` | The directory containing integration tests.                                              |
| `lib/`               | The directory containing the generated output from [tsc](https://typescriptlang.org).                                              |
| `src/`               | The directory containing the TypeScript source files.                                                                              |
| `index.mts`          | Entry point for when this library is loaded via [ESM `import`](https://nodejs.org/api/esm.html#modules-ecmascript-modules) syntax. |
| `index.cts`          | Entry point for when this library is loaded via [CJS `require`](https://nodejs.org/api/modules.html#requireid).                    |
| `crates/`            | The directory tree containing the Rust source code for the project.                                                                |
| `lib.rs`             | Entry point for the Rust source code.                                                                                              |
| `platforms/`         | The directory containing distributions of the binary addon backend for each platform supported by this library.                    |
| `package.json`       | The npm [manifest file](https://docs.npmjs.com/cli/v7/configuring-npm/package-json), which informs the `npm` command.              |
| `target/`            | Binary artifacts generated by the Rust build.                                                                                      |

## Integration tests

Integration tests live in the `./integration-tests` directory.
These tests use the local build of Rust and JavaScript artifacts to test `@cipherstash/protect-ffi` as API consumers would.

These tests rely on:

- CipherStash to be configured (via `.toml` config or environment variables), and 
- Environment variables for Postgres to be set

Example environment variables:
```
CS_CLIENT_ID=
CS_CLIENT_KEY=
CS_CLIENT_ACCESS_KEY=
CS_WORKSPACE_ID=
PGPORT=5432
PGDATABASE=cipherstash
PGUSER=cipherstash
PGPASSWORD=password
PGHOST=localhost
```

To run integration tests:
```
npm run debug
cd integration-tests
docker compose up --detach --wait
npm run eql:download
npm run eql:install
npm run test
```

## Releasing

Releases are handled by GitHub Actions using a `workflow_dispatch` event trigger.
The [release workflow](./.github/workflows/release.yml) was generated by [Neon](https://neon-rs.dev/).

The release workflow is responsible for:

- Building and publishing the main `@cipherstash/protect-ffi` package as well as the native packages for each platform (e.g. `@cipherstash/protect-ffi-darwin-arm64`).
- Creating the GitHub release.
- Creating a Git tag for the version.

To perform a release:

1. Navigate to the ["Release" workflow page](https://github.com/cipherstash/protect-ffi/actions/workflows/release.yml) in GitHub.
1. Click on "Run workflow".
1. Select the branch to release from.
   Use the default of `main` unless you want to do a pre-release version or dry run from a branch.
1. Select whether or not to do a dry run.
   Dry runs are useful for verifying that the build will succeed for all platforms before doing a full run with a publish.
1. Choose a version to publish.
   The options are similar to [`npm version`](https://docs.npmjs.com/cli/v11/commands/npm-version).
   Select "custom" in the dropdown and fill in the "Custom version" text box if you want to use a semver string instead of the shorthand (patch, minor, major, etc.).
1. Click "Run workflow".

Note that we currently don't have any automation around release notes or a changelog.
However, you can add release notes after running the workflow by editing the release on GitHub.

## Learn More

Learn more about:

- [Neon](https://neon-bindings.com).
- [Rust](https://www.rust-lang.org).
- [Node](https://nodejs.org).
