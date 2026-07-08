# JSONB API Reference

Complete API reference for JSONB operations in protectjs-ffi.

## Table of Contents

1. [Supported Operations](#supported-operations)
2. [Path Selector Syntax](#path-selector-syntax)
3. [QueryOp Types](#queryop-types)
4. [Output Structure](#output-structure)
5. [Type Inference Rules](#type-inference-rules)
6. [Schema Configuration](#schema-configuration)

---

## Supported Operations

### PostgreSQL to Encrypted Mapping

| PostgreSQL Operation | SQL Syntax | protectjs-ffi Approach |
|---------------------|------------|------------------------|
| Path selection | `column->'key'` | `encryptQuery` with selector |
| Path text | `column->>'key'` | `encryptQuery` with selector |
| Containment | `column @> '{"k":"v"}'` | `encryptQuery` with term |
| Contained by | `'{"k":"v"}' <@ column` | `encryptQuery` with term |
| Path exists | `column ? 'key'` | `encryptQuery` with selector |
| Nested path | `column->'a'->'b'` | `encryptQuery` with `$.a.b` |

### EQL v2 Functions

| Function | Purpose | Input Type |
|----------|---------|------------|
| `eql_v2.jsonb_path_query(col, sel)` | Select values at path | Selector |
| `eql_v2.jsonb_path_exists(col, sel)` | Check path exists | Selector |
| `eql_v2.jsonb_path_query_first(col, sel)` | First value at path | Selector |
| `eql_v2.ste_vec_contains(col, term)` | Containment check | Term |
| `col @> term` | Containment operator | Term |
| `term <@ col` | Contained by operator | Term |
| `eql_v2.jsonb_array_length(col)` | Array length | - |
| `eql_v2.jsonb_array_elements(col)` | Expand array to rows | - |
| `eql_v2.jsonb_array_elements_text(col)` | Expand array to text rows | - |

**Security Note:** Selectors can be passed as plaintext JSONPath strings (e.g., `'$.user.email'`) but this is **less secure** than using encrypted selectors from `encryptQuery`. Always prefer encrypted selectors in production.

---

## Path Selector Syntax

Path selectors use a subset of JSONPath syntax (eJsonPath).

### Selector Components

| Component | Syntax | Example |
|-----------|--------|---------|
| Root | `$` | `$` (matches root) |
| Dot notation | `.key` | `$.user` |
| Bracket notation | `['key']` | `$['user-name']` |
| Array index | `[n]` | `$.items[0]` |
| Nested path | `.a.b.c` | `$.user.profile.name` |

### Valid Path Examples

```javascript
// Simple key access
'$.name'

// Nested object access
'$.user.profile.email'

// Array element access
'$.items[0]'

// Mixed nesting
'$.users[0].profile.settings'

// Keys with special characters (use bracket notation)
"$['user-name']"
"$['@type']"
```

### Path Construction Rules

1. Paths **must** start with `$` (root selector)
2. Use dot notation for simple alphanumeric keys
3. Use bracket notation for keys with special characters
4. Array indices are zero-based integers

---

## QueryOp Types

The `queryOp` parameter controls how query encryption is performed.

### `default`

Automatically infers operation from plaintext type:

| Plaintext Type | Inferred Operation | Behavior |
|---------------|-------------------|----------|
| String | `ste_vec_selector` | Path query |
| Object | `ste_vec_term` | Containment query |
| Array | `ste_vec_term` | Containment query |
| Number | **Error** | Not supported |
| Boolean | **Error** | Not supported |

```typescript
// String → selector
await encryptQuery(client, {
  plaintext: '$.user.email',
  indexType: 'ste_vec',
  queryOp: 'default'  // Infers ste_vec_selector
})

// Object → term
await encryptQuery(client, {
  plaintext: { role: 'admin' },
  indexType: 'ste_vec',
  queryOp: 'default'  // Infers ste_vec_term
})
```

### `ste_vec_selector`

Explicitly encrypts a JSONPath string for path queries.

**Input:** String (JSONPath like `$.user.email`)
**Output:** `{ i, v, s }` (selector only, no ciphertext)

```typescript
const selector = await encryptQuery(client, {
  plaintext: '$.user.name',
  table: 'users',
  column: 'profile',
  indexType: 'ste_vec',
  queryOp: 'ste_vec_selector'
})

// Use with: eql_v2.jsonb_path_query(profile, $selector)
```

### `ste_vec_term`

Explicitly encrypts a JSON fragment for containment queries.

**Input:** Object or Array
**Output:** `{ i, v, sv: [...] }` (flattened entries with ciphertext)

```typescript
const term = await encryptQuery(client, {
  plaintext: { user: { role: 'admin' } },
  table: 'users',
  column: 'profile',
  indexType: 'ste_vec',
  queryOp: 'ste_vec_term'
})

// Use with: profile @> $term::jsonb
```

**Error Case:** Passing a string to `ste_vec_term` will throw:
```
Error: Unsupported conversion from "String" to JsonB
```

---

## Output Structure

### EqlCiphertext Format

By default (`eqlVersion: 2`) all encryption operations return an EQL v2.3 payload, a discriminated union keyed on `k`. Clients created with `eqlVersion: 3` return the EQL v3 shapes instead — see [EQL v3 output](#eql-v3-output-eqlversion-3) below.

```typescript
type EqlCiphertext = EncryptedScalar | EncryptedSteVec

// k = "ct" — scalar payload
type EncryptedScalar = {
  k: 'ct'
  v: number                     // Version
  i: { t: string; c: string }  // Identifier (table, column)
  c: string                     // Encrypted ciphertext (mp_base85) — required for storage
  hm?: string                   // HMAC-SHA256 (unique index)
  bf?: number[]                 // Bloom filter (match index)
  ob?: string[]                 // Block ORE u64_8_256 (ore index)
}

// k = "sv" — STE-vector payload
type EncryptedSteVec = {
  k: 'sv'
  v: number                     // Version
  i: { t: string; c: string }  // Identifier (table, column)
  sv: SteVecEntry[]            // Per-selector entries; root ciphertext lives at sv[0].c
}

type SteVecEntry = {
  s: string       // Hex-encoded tokenized selector
  c: string       // Per-entry ciphertext (mp_base85) — required
  a?: boolean     // Array marker
  hm?: string     // HMAC term — non-orderable leaves (objects, arrays, booleans, null)
  oc?: string     // CLLW ORE term — orderable leaves (strings, numbers), Standard mode
}
```

Query payloads share the same `{ k, v, i, ... }` shape but omit `c` at the root (queries do not encrypt for storage). For `k = "ct"` queries, the payload carries exactly one of `hm`, `bf`, or `ob`. For `k = "sv"` queries, the FFI emits two shapes: selector queries (`ste_vec_selector`) carry a single tokenized `s`; containment queries (`ste_vec_term`) are emitted as full SteVec storage payloads with an `sv` array — see the *Output by Operation* table below.

Under SteVec **Standard** mode (the default since `cipherstash-client` 0.34.1-alpha.7), each `sv` entry carries either `hm` or `oc` depending on the underlying JSON value:

| JSON value type | SteVec entry field |
|-----------------|--------------------|
| Object, array, boolean, null | `hm` (HMAC-SHA256) |
| String, number | `oc` (CLLW ORE, tagged-plaintext) |

Numeric and string values share the single `oc` orderable field — domain separation is enforced on the plaintext bit stream before encryption, so numeric ciphertexts always sort below string ciphertexts.

### Output by Operation

| Operation | Discriminator | Fields Present |
|-----------|---------------|----------------|
| Scalar storage (`encrypt` on non-JSON column) | `k: "ct"` | `k, v, i, c` + any of `hm, bf, ob` |
| SteVec storage (`encrypt` on JSON column) | `k: "sv"` | `k, v, i, sv` (root ciphertext at `sv[0].c`) |
| Scalar query (`encryptQuery` with `ore`/`match`/`unique`) | `k: "ct"` | `k, v, i` + one of `hm, bf, ob` |
| SteVec selector query (`encryptQuery` with `ste_vec_selector`) | `k: "sv"` | `k, v, i, s` |
| SteVec containment query (`encryptQuery` with object/array input) | `k: "sv"` | `k, v, i, sv` |

### Example Outputs

**Scalar storage encryption (e.g. `email`, `score`):**
```json
{
  "k": "ct",
  "v": 2,
  "i": { "t": "users", "c": "email" },
  "c": "base85encodedciphertext...",
  "hm": "abc123...",
  "bf": [1, 2, 3]
}
```

**SteVec storage encryption (Standard mode):**
```json
{
  "k": "sv",
  "v": 2,
  "i": { "t": "users", "c": "profile" },
  "sv": [
    { "s": "rootselector", "hm": "rootmac", "c": "rootciphertext..." },
    { "s": "abc123", "hm": "def456", "c": "..." },
    { "s": "jkl012", "oc": "pqr678", "c": "..." }
  ]
}
```

**Selector query:**
```json
{
  "k": "sv",
  "v": 2,
  "i": { "t": "users", "c": "profile" },
  "s": "abc123def456"
}
```

**Containment query (Standard mode):**
```json
{
  "k": "sv",
  "v": 2,
  "i": { "t": "users", "c": "profile" },
  "sv": [
    { "s": "abc123", "oc": "ghi789", "c": "..." }
  ]
}
```

### EQL v3 output (`eqlVersion: 3`)

Clients created with `newClient({ ..., eqlVersion: 3 })` emit the `eql_v3`
wire format instead. Scalar payloads carry no `k` discriminator (the
envelope is `{ v: 3, i, ... }` with the shape determined by the column's
`eql_v3` domain); SteVec documents keep `k: "sv"`.

**SteVec storage encryption (`eql_v3.json`):**
```json
{
  "v": 3,
  "k": "sv",
  "i": { "t": "users", "c": "profile" },
  "sv": [
    { "s": "rootselector", "hm": "rootmac", "c": "rootciphertext..." },
    { "s": "abc123", "oc": "ghi789", "c": "..." }
  ]
}
```

Entry order is preserved from v2 and `sv[0]` remains the **decryption
root**: `sv[0].c` is the record ciphertext `decrypt` uses. Reordering `sv`
entries breaks decryption.

**Containment query (`eql_v3.query_jsonb` needle):**
```json
{
  "sv": [
    { "s": "abc123", "oc": "ghi789" }
  ]
}
```

The needle carries no envelope (`v`/`i`) and no per-entry ciphertexts —
each entry is the selector plus exactly one of `hm`/`oc`, mirroring the SQL
cast `eql_v3.to_ste_vec_query`. Use it with the `@>`/`<@` operators against
a `public.json` column (`WHERE doc @> $1::jsonb::eql_v3.query_jsonb`).

**Selector (path) query:** `encryptQuery` with `queryOp: 'ste_vec_selector'`
returns the bare selector hash as a **string** — there is no
encrypted-selector envelope in v3. Bind it as the `text` argument of the
`->` / `->>` operators (`SELECT doc -> $1::text`); it is the same
`Selector` encoding SteVec entries carry in `s`.

**Scalar queries:** supported under `eqlVersion: 3` since protect-ffi 0.29 —
`encryptQuery` on a scalar column returns the term-only operand
(`{v, i, <terms>}`, no `c`) for the column domain's `eql_v3.query_<name>`
twin. See the README's EQL v3 section for the domain/operator matrix.

---

## Type Inference Rules

### JsPlaintext Type Detection

The FFI receives JavaScript values and categorizes them:

| JavaScript Value | JsPlaintext Variant | Notes |
|-----------------|---------------------|-------|
| `"string"` | `String` | Strings |
| `42`, `3.14` | `Number` | All numbers (integers and floats) |
| `42n` | `BigInt` | Top-level scalar plaintexts only — i64-bounded, not valid inside JSON |
| `true`, `false` | `Boolean` | Booleans (supported for storage and decryption) |
| `{ key: val }` | `JsonB` | Objects |
| `[1, 2, 3]` | `JsonB` | Arrays |
| `null` | `JsonB` | JSON null |

### Conversion Rules

Type coercion follows strict rules (conversion allowed, parsing not; a
value that cannot be represented exactly in the target type errors instead
of being truncated):

| From | To | Result |
|------|----|--------|
| String | Utf8Str | Allowed |
| String | JsonB | **Error** |
| Number | Float | Allowed (including fractional and non-finite values) |
| Number | BigInt/Int/SmallInt/BigUInt | Allowed (errors on fractional / out-of-range / non-finite) |
| Number | Decimal | Allowed (errors on non-finite) |
| Number | Utf8Str | **Error** |
| BigInt | BigInt/Int/SmallInt/BigUInt/Decimal | Allowed (errors on out-of-range) |
| BigInt | Float/JsonB/Utf8Str | **Error** |
| Boolean | Boolean | Allowed |
| Boolean | Utf8Str | **Error** |
| JsonB | JsonB | Allowed |
| JsonB | Utf8Str | **Error** |

### Query Type Inference (SteVec)

For `ste_vec` index with `queryOp: 'default'`:

```
                    ┌─────────────────────┐
                    │  JsPlaintext type   │
                    └─────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌─────────┐    ┌─────────┐    ┌─────────┐
         │ String  │    │ JsonB   │    │ Number/ │
         │         │    │(obj/arr)│    │ Boolean │
         └─────────┘    └─────────┘    └─────────┘
              │               │               │
              ▼               ▼               ▼
         ┌─────────┐    ┌─────────┐    ┌─────────┐
         │Selector │    │  Term   │    │  ERROR  │
         │(Query)  │    │(Store)  │    │         │
         └─────────┘    └─────────┘    └─────────┘
```

---

## Schema Configuration

### EncryptConfig Structure

```typescript
type EncryptConfig = {
  v: number  // Version (always 1)
  tables: Record<string, Record<string, Column>>
}

type Column = {
  cast_as?:
    | 'bigint' | 'boolean' | 'date' | 'json'
    | 'number' | 'string' | 'text' | 'timestamp'
  indexes?: {
    ore?: {}
    unique?: { token_filters?: TokenFilter[] }
    match?: { tokenizer?: Tokenizer; k?: number; m?: number; include_original?: boolean }
    ste_vec?: {
      prefix: string
      term_filters?: TokenFilter[]
      array_index_mode?: ArrayIndexMode
      mode?: 'compat' | 'standard'
    }
  }
}
```

### JSONB Column Configuration

For searchable JSONB columns, use:

```typescript
const config = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',  // Required for JSONB
        indexes: {
          ste_vec: {
            prefix: 'users/profile'  // Unique prefix per column
          }
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `v` | number | Yes | Config schema version. Must be `1`; other values fail at `newClient` with `UNSUPPORTED_CONFIG_VERSION`. |
| `cast_as` | string | Yes | Must be `'json'` for JSONB. See *cast_as vocabulary* below. |
| `indexes.ste_vec` | object | Yes* | Enables JSONB queries. Requires `cast_as: 'json'`; other values fail at `newClient` with `STE_VEC_REQUIRES_JSON_CAST_AS`. |
| `indexes.ste_vec.prefix` | string | Yes | Unique identifier for index |
| `indexes.ste_vec.term_filters` | array | No | Token filters for values |
| `indexes.ste_vec.array_index_mode` | string \| object | No | Controls how array elements are indexed. Defaults to `'none'`. |
| `indexes.ste_vec.mode` | string | No | Encoding mode: `'standard'` (default) or `'compat'`. See *SteVec mode* below. |
| `indexes.match` | object | No | Full-text search index. Requires a text-family `cast_as` (`'text'` or `'string'`); other values fail at `newClient` with `MATCH_REQUIRES_TEXT`. |

*Required for path/containment queries. Without `ste_vec`, JSON is stored as opaque blob.

### cast_as vocabulary

The public `cast_as` union accepts a JS-friendly vocabulary. Three values are translated internally before reaching the native config; the remaining values pass through unchanged.

| Public value | Internal value | Notes |
|-------------|----------------|-------|
| `'string'` | `text` | Translated automatically |
| `'number'` | `float` | Translated automatically |
| `'bigint'` | `big_int` | Translated automatically |
| `'text'` | `text` | Pass-through |
| `'boolean'` | `boolean` | Pass-through |
| `'date'` | `date` | Pass-through |
| `'json'` | `json` | Pass-through; required for `ste_vec` indexes |
| `'timestamp'` | `timestamp` | Pass-through |

The translation happens in TypeScript at the `newClient` boundary and is invisible to callers.

### SteVec mode

The `mode` option controls the encoding format used for `ste_vec` index entries. The default is `'standard'`. Use `'compat'` only when you need to read data indexed by an older release that used `Compat` encoding.

**Warning:** changing `mode` on an existing column requires re-encrypting all stored data for that column; the two encodings are not cross-compatible.

### Opaque vs Searchable JSON

**Opaque (no queries):**
```typescript
{
  cast_as: 'json',
  indexes: {}
}
```

**Searchable (with queries):**
```typescript
{
  cast_as: 'json',
  indexes: {
    ste_vec: { prefix: 'table/column' }
  }
}
```

---

## Function Signatures

### newClient

```typescript
function newClient(opts: NewClientOptions): Promise<Client>

type NewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: {
    workspaceCrn?: string
    accessKey?: string
    clientId?: string
    clientKey?: string
    keyset?: { Uuid: string } | { Name: string }
  }
}
```

### encrypt / encryptBulk

```typescript
function encrypt(client: Client, opts: EncryptOptions): Promise<Encrypted>

type EncryptOptions = {
  plaintext: JsPlaintext
  table: string
  column: string
  lockContext?: { identityClaim: string[] }
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

function encryptBulk(
  client: Client,
  opts: { plaintexts: EncryptPayload[] }
): Promise<Encrypted[]>
```

### encryptQuery / encryptQueryBulk

```typescript
function encryptQuery(
  client: Client,
  opts: EncryptQueryOptions
): Promise<Encrypted>

type EncryptQueryOptions = {
  plaintext: JsPlaintext
  table: string
  column: string
  indexType: 'ste_vec' | 'match' | 'ore' | 'ope' | 'unique'
  queryOp?: 'default' | 'ste_vec_selector' | 'ste_vec_term'
  lockContext?: { identityClaim: string[] }
  serviceToken?: CtsToken
  unverifiedContext?: Record<string, unknown>
}

function encryptQueryBulk(
  client: Client,
  opts: { queries: QueryPayload[] }
): Promise<Encrypted[]>
```

### isEncrypted

```typescript
function isEncrypted(encrypted: Encrypted): boolean
```

Synchronously checks if a value is a valid encrypted ciphertext structure. Useful for conditionally processing data that may or may not be encrypted.

### decrypt / decryptBulk

```typescript
function decrypt(client: Client, opts: DecryptOptions): Promise<JsPlaintext>

function decryptBulk(
  client: Client,
  opts: { ciphertexts: BulkDecryptPayload[] }
): Promise<JsPlaintext[]>

function decryptBulkFallible(
  client: Client,
  opts: { ciphertexts: BulkDecryptPayload[] }
): Promise<DecryptResult[]>

type DecryptResult =
  | { data: JsPlaintext }
  | { error: string; code?: ProtectErrorCode }
```

### Errors

Errors thrown by the async APIs surface as `ProtectError` instances with a stable `code`.

```typescript
type ProtectErrorCode =
  | 'INVARIANT_VIOLATION'
  | 'UNKNOWN_QUERY_OP'
  | 'UNKNOWN_COLUMN'
  | 'MISSING_INDEX'
  | 'INVALID_QUERY_INPUT'
  | 'INVALID_JSON_PATH'
  | 'STE_VEC_REQUIRES_JSON_CAST_AS'
  | 'MATCH_REQUIRES_TEXT'
  | 'UNSUPPORTED_CONFIG_VERSION'
  | 'INVALID_EQL_VERSION'
  | 'EQL_V3_UNSUPPORTED_COLUMN'
  | 'EQL_V3_CONVERSION_FAILED'
  | 'INVALID_CIPHERTEXT'
  | 'UNKNOWN'

class ProtectError extends Error {
  code: ProtectErrorCode
}
```

Example:

```typescript
try {
  await encryptQuery(client, opts)
} catch (err) {
  if (err instanceof ProtectError && err.code === 'INVALID_JSON_PATH') {
    // handle JSON path mistakes
  }
  throw err
}
```

---

## Related Documentation

- [Integration Guide](./jsonb-integration.md) - Architecture and data flow
- [Troubleshooting](./jsonb-troubleshooting.md) - Common issues and solutions
