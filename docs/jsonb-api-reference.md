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

All encryption operations return an `EqlCiphertext` structure:

```typescript
type EqlCiphertext = {
  // Required fields
  i: { t: string; c: string }  // Identifier (table, column)
  v: number                     // Version

  // Optional body fields
  c?: string      // Encrypted ciphertext (mp_base85)
  a?: boolean     // Array flag

  // Searchable encrypted metadata (top-level)
  ob?: string[]   // ORE block (64-bit integers)
  bf?: number[]   // Bloom filter (match index)
  hm?: string     // HMAC-SHA256 (unique index / SteVec MAC entries)
  s?: string      // Selector (SteVec path)
  oc?: string     // SteVec ORE CLLW term — Standard mode (numeric ∪ string)
  op?: string     // SteVec OPE CLLW term — Compat mode (numeric ∪ string)
  opf?: string    // OPE CLLW fixed (non-SteVec numeric)
  opv?: string    // OPE CLLW variable (non-SteVec string)

  // Nested entries
  sv?: EqlCiphertextBody[]  // SteVec flattened entries
}

type EqlCiphertextBody = {
  c?: string      // Entry ciphertext
  a?: boolean     // Array flag
  s?: string      // Entry selector
  hm?: string     // Entry HMAC — non-orderable values (objects, arrays, booleans, null)
  oc?: string     // Entry ORE CLLW term (Standard mode) — orderable values (strings, numbers)
  op?: string     // Entry OPE CLLW term (Compat mode) — orderable values (strings, numbers)
  sv?: EqlCiphertextBody[]  // Nested entries
}
```

Under SteVec **Standard** mode (the default since `cipherstash-client` 0.34.1-alpha.7), each `sv` entry carries either `hm` or `oc` depending on the underlying JSON value:

| JSON value type | SteVec entry field |
|-----------------|--------------------|
| Object, array, boolean, null | `hm` (HMAC-SHA256) |
| String, number | `oc` (CLLW ORE, tagged-plaintext) |

Under **Compat** mode (`ste_vec.mode: 'compat'`), the orderable term is OPE instead of ORE and serializes as `op`. Numeric and string values share a single orderable field in both modes — domain separation is enforced on the plaintext bit stream before encryption, so numeric ciphertexts always sort below string ciphertexts.

### Output by Operation

| Operation | Fields Present |
|-----------|----------------|
| Storage (`encrypt`) | `i, v, c, sv` |
| Selector query | `i, v, s` |
| Term query | `i, v, c, sv` |

### Example Outputs

**Storage encryption (Standard mode):**
```json
{
  "i": { "t": "users", "c": "profile" },
  "v": 2,
  "c": "base85encodedciphertext...",
  "sv": [
    { "s": "abc123", "hm": "def456", "c": "..." },
    { "s": "jkl012", "oc": "pqr678", "c": "..." }
  ]
}
```

**Selector query:**
```json
{
  "i": { "t": "users", "c": "profile" },
  "v": 2,
  "s": "abc123def456"
}
```

**Term query (Standard mode):**
```json
{
  "i": { "t": "users", "c": "profile" },
  "v": 2,
  "c": "base85encodedciphertext...",
  "sv": [
    { "s": "abc123", "oc": "ghi789", "c": "..." }
  ]
}
```

---

## Type Inference Rules

### JsPlaintext Type Detection

The FFI receives JavaScript values and categorizes them:

| JavaScript Value | JsPlaintext Variant | Notes |
|-----------------|---------------------|-------|
| `"string"` | `String` | Strings |
| `42`, `3.14` | `Number` | All numbers (integers and floats) |
| `true`, `false` | `Boolean` | Booleans (supported for storage and decryption) |
| `{ key: val }` | `JsonB` | Objects |
| `[1, 2, 3]` | `JsonB` | Arrays |
| `null` | `JsonB` | JSON null |

### Conversion Rules

Type coercion follows strict rules (conversion allowed, parsing not):

| From | To | Result |
|------|----|--------|
| String | Utf8Str | Allowed |
| String | JsonB | **Error** |
| Number | Float/BigInt/Int | Allowed (with truncation) |
| Number | Utf8Str | **Error** |
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
  indexType: 'ste_vec' | 'match' | 'ore' | 'unique'
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
