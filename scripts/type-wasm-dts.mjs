// Replaces `opts: any` with the real option types in the wasm-pack `.d.ts`.
//
// Why this is needed
// ------------------
// `wasm-pack --target bundler` types every exported function as
// `(client: WasmClient, opts: any): Promise<any>`, because wasm-bindgen sees
// only `JsValue` on the Rust side. The result was a package whose two entries
// described the same Rust core with wildly different fidelity: the Neon entry
// declared fourteen option and payload types, the wasm entry declared none and
// checked nothing.
//
// That is not a cosmetic gap. A consumer writing one interface over both
// bindings — which is exactly what `@cipherstash/stack` does — had to import
// the option types from the Neon entry, because that was the only place they
// existed. Doing so puts a `@cipherstash/protect-ffi` specifier into the
// published types of a bundle whose entire purpose is to avoid loading a
// native binary. See #142.
//
// Why the signatures below are safe to assert
// -------------------------------------------
// They are not a guess at a parallel API. `crates/protect-ffi/src/wasm.rs`
// deserializes each `opts` into the SAME Rust struct the Neon entry does —
// `EncryptOptions`, `EncryptBulkOptions`, `DecryptOptions`,
// `DecryptBulkOptions`, `EncryptQueryOptions`, `EncryptQueryBulkOptions` — and
// then calls the same `do_*` helper. The accepted shape is identical by
// construction, not by convention.
//
// The plaintext boundary is deliberately reconciled too: `encode_plaintext`
// tags bigints for the untagged `JsPlaintext` enum and round-trips everything
// else through `JSON.stringify`/`parse`, specifically so wasm matches Neon's
// `neon::types::extract::Json` semantics (`toJSON` honored, `undefined`
// dropped, nested bigint rejected). So `JsPlaintext` genuinely is one type.
//
// The three places they diverge are declared as divergences rather than
// papered over — see WASM_ONLY_TYPES below.
//
// Why patch rather than hand-write a wrapper
// ------------------------------------------
// wasm-pack regenerates this file on every build, so a wrapper would have to
// re-export it to keep `WasmClient` nominally identical, and would silently
// miss any export wasm-bindgen adds later. Patching in place keeps one file,
// keeps class identity, and leaves new exports alone. The assertions below
// fail the build if wasm-bindgen's output shape changes, so this cannot
// silently no-op.

import { readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const dtsPath = resolve(here, '..', 'dist', 'wasm', 'protect_ffi.d.ts')

/**
 * Types imported from the shared module. `../../lib/` is relative and inside
 * the package, so it resolves for every consumer without naming the Neon
 * entry — which is the whole point.
 */
const IMPORT_BLOCK = `import type {
  DecryptBulkOptions,
  DecryptOptions,
  Encrypted,
  EncryptedPayload,
  EncryptedQuery,
  EncryptBulkOptions,
  EncryptOptions,
  EncryptQueryBulkOptions,
  EncryptQueryOptions,
  JsPlaintext,
  CanonicalEncryptConfig,
  NewClientOptions,
} from "../../lib/types.js";
import type { EncryptedV3Query } from "../../lib/eql-v3.js";

export type * from "../../lib/types.js";
export type { EncryptedV3, EncryptedV3Query } from "../../lib/eql-v3.js";
`

/**
 * Where the two bindings genuinely differ. Each is a real behavioural
 * difference in the Rust or the JS wrapper, not a typing convenience.
 */
const WASM_ONLY_TYPES = `
/**
 * \`newClient\` options for this build.
 *
 * The credential and keyset shape is now the SAME \`NewClientOptions\` the Neon
 * entry takes — both deserialize into one Rust struct, and
 * \`CredentialOpts::build_strategy()\` resolves an \`AccessKeyStrategy\` from
 * \`clientOpts.accessKey\` + \`clientOpts.workspaceCrn\` here exactly as it
 * resolves an \`AutoStrategy\` there. \`authStrategy\` is optional on both.
 *
 * One field still differs, and it is a JS-layer gap rather than a Rust one:
 * \`encryptConfig\` must already be in the CANONICAL \`cast_as\` vocabulary
 * (\`text\` / \`float\` / \`big_int\`). Both bindings deserialize
 * \`CanonicalEncryptionConfig\`, but the Neon entry has a JS wrapper that runs
 * \`normalizeEncryptConfig\` for you first, and this binding has no wrapper to
 * do it. Pass the public spellings (\`string\` / \`number\` / \`bigint\`) and
 * they reach the Rust untranslated and fail there.
 */
export type WasmNewClientOptions = Omit<NewClientOptions, "encryptConfig"> & {
  encryptConfig: CanonicalEncryptConfig;
};

/**
 * Per-item result from {@link decryptBulkFallible}.
 *
 * Narrower than the Neon entry's \`DecryptResult\`, which also carries
 * \`code?: ProtectErrorCode\`. That field is not produced by Rust — the Neon
 * wrapper adds it in JS by running \`inferErrorCode(item.error)\` over the
 * message (see \`src/index.cts\`). This build returns what Rust serializes, so
 * the field is absent rather than optional-and-never-set.
 */
export type WasmDecryptResult =
  | { data: JsPlaintext }
  | { error: string };
`

/**
 * `[generated signature, typed replacement]`.
 *
 * The left side must match wasm-bindgen's output exactly; a miss is a build
 * failure, so this cannot rot into a silent no-op when the generator changes.
 */
const SIGNATURES = [
  [
    'export function newClient(opts: any): Promise<WasmClient>;',
    'export function newClient(opts: WasmNewClientOptions): Promise<WasmClient>;',
  ],
  [
    'export function encrypt(client: WasmClient, opts: any): Promise<any>;',
    'export function encrypt(client: WasmClient, opts: EncryptOptions): Promise<EncryptedPayload>;',
  ],
  [
    'export function encryptBulk(client: WasmClient, opts: any): Promise<any>;',
    'export function encryptBulk(client: WasmClient, opts: EncryptBulkOptions): Promise<EncryptedPayload[]>;',
  ],
  [
    'export function decrypt(client: WasmClient, opts: any): Promise<any>;',
    'export function decrypt(client: WasmClient, opts: DecryptOptions): Promise<JsPlaintext>;',
  ],
  [
    'export function decryptBulk(client: WasmClient, opts: any): Promise<any>;',
    'export function decryptBulk(client: WasmClient, opts: DecryptBulkOptions): Promise<JsPlaintext[]>;',
  ],
  [
    'export function decryptBulkFallible(client: WasmClient, opts: any): Promise<any>;',
    'export function decryptBulkFallible(client: WasmClient, opts: DecryptBulkOptions): Promise<WasmDecryptResult[]>;',
  ],
  [
    'export function encryptQuery(client: WasmClient, opts: any): Promise<any>;',
    'export function encryptQuery(client: WasmClient, opts: EncryptQueryOptions): Promise<Encrypted | EncryptedQuery | EncryptedV3Query>;',
  ],
  [
    'export function encryptQueryBulk(client: WasmClient, opts: any): Promise<any>;',
    'export function encryptQueryBulk(client: WasmClient, opts: EncryptQueryBulkOptions): Promise<(Encrypted | EncryptedQuery | EncryptedV3Query)[]>;',
  ],
  [
    'export function isEncrypted(raw: any): boolean;',
    'export function isEncrypted(raw: unknown): boolean;',
  ],
]

let dts = await readFile(dtsPath, 'utf-8')

if (dts.includes('../../lib/types.js')) {
  console.log('type-wasm-dts: already typed, nothing to do')
  process.exit(0)
}

const missing = SIGNATURES.filter(
  ([generated]) => !dts.includes(generated),
).map(([generated]) => generated)
if (missing.length > 0) {
  throw new Error(
    `type-wasm-dts: wasm-bindgen output does not match the expected signatures.\nThis script would have silently typed nothing. Update SIGNATURES to match:\n${missing.map((s) => `  - ${s}`).join('\n')}`,
  )
}

for (const [generated, typed] of SIGNATURES) {
  dts = dts.replace(generated, typed)
}

dts = `${IMPORT_BLOCK}${dts}${WASM_ONLY_TYPES}`

await writeFile(dtsPath, dts)

console.log(
  `type-wasm-dts: typed ${SIGNATURES.length} signatures in dist/wasm/protect_ffi.d.ts`,
)
