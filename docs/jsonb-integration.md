# JSONB Integration Guide

This guide provides a comprehensive overview of JSONB encryption and querying in protectjs-ffi.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Flow](#data-flow)
3. [SteVec Flattening Process](#stevec-flattening-process)
4. [Quick Start](#quick-start)

---

## Architecture Overview

The JSONB encryption system consists of three layers:

```mermaid
flowchart TD
    APP["<b>Application Layer</b><br/>(@cipherstash/stack)<br/>Schema definition with .searchableJson()<br/>High-level query API (encryptQuery)<br/>Path utilities (toDollarPath, buildNestedObject)"]
    FFI["<b>FFI Layer</b><br/>(protectjs-ffi)<br/>JsPlaintext type conversion<br/>Query operation inference<br/>Schema configuration (EncryptConfig)"]
    ENC["<b>Encryption Layer</b><br/>(cipherstash-client)<br/>JsonbIndexer&lt;T&gt; for JSON processing<br/>SteVec&lt;N&gt; for flattened entry storage<br/>eJsonPath parser for path selectors<br/>Cryptographic operations (AES-GCM-SIV, ORE, Blake3)"]
    APP --> FFI --> ENC
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `JsPlaintext` | `crates/protect-ffi/src/js_plaintext.rs` | JavaScript value representation |
| `EncryptConfig` | `crates/protect-ffi/src/encrypt_config.rs` | Schema configuration |
| `to_query_plaintext` | `crates/protect-ffi/src/lib.rs` | Query type inference |
| `JsonbIndexer` | `cipherstash-client` | JSON to SteVec conversion |
| `SteVec` | `cipherstash-client` | Flattened encrypted entries |

---

## Data Flow

### Storage Path (encrypt/encryptBulk)

When storing JSONB data, the flow is:

```mermaid
flowchart LR
    IN["JSON Object<br/>{ 'user': { 'role': 'admin' } }"] --> JP["JsPlaintext<br/>(JsonB variant)"]
    JP --> PT["Plaintext::JsonB"]
    PT -- "flatten" --> EE["encrypt_eql()<br/>Store mode"]
    EE --> EC["EqlCiphertext<br/>(unified format)"]
    EC --> OUT["EQL Ciphertext<br/>{ i, v, c, sv: [...] }"]
```

**Key Points:**
- `EqlOperation::Store` is used
- Root ciphertext (`c`) is produced for decryption
- SteVec entries (`sv`) are produced for querying
- Each entry contains searchable encrypted metadata (selector, blake3, ORE, etc.)

**Update Semantics:**
- There is **no partial in-place update** of encrypted JSON fields
- To update, re-encrypt the entire JSON value and overwrite the column
- Individual nested fields cannot be modified without re-encrypting the whole document

### Query Path (encryptQuery/encryptQueryBulk)

Query encryption follows different paths based on query type:

#### Path Selector Query (ste_vec_selector)

```mermaid
flowchart LR
    IN["JSONPath String<br/>'$.user.email'"] --> JP["JsPlaintext<br/>(String variant)"]
    JP --> PT["Plaintext::Utf8Str"]
    PT --> EE["encrypt_eql_v3()<br/>Query mode"]
    EE --> EC["EqlQueryPayloadV3<br/>(selector only)"]
    EC --> OUT["Bare selector hash<br/>'...'"]
```

**Output:** The bare selector hash as a string, with no ciphertext.

#### Containment Query (default)

```mermaid
flowchart LR
    IN["JSON Fragment<br/>{ 'role': 'admin' }"] --> JP["JsPlaintext<br/>(JsonB variant)"]
    JP --> PT["Plaintext::JsonB"]
    PT --> EE["encrypt_eql_v3()<br/>Store mode"]
    EE --> EC["EqlCiphertextV3<br/>(with sv array)"]
    EC --> OUT["Containment Needle<br/>{ sv: [...] }"]
```

**Output:** SteVec entries (`sv`) array, typically with ciphertext (`c`)

---

## SteVec Flattening Process

When JSON is encrypted with a `ste_vec` index, it is "flattened" into a vector of entries. Each entry represents a path-value pair in the JSON structure.

### Example Flattening

**Input JSON:**
```json
{
  "user": {
    "name": "alice",
    "age": 30,
    "tags": ["admin", "moderator"]
  }
}
```

**Flattened Entries (conceptual):**

| Path | Value | Index Fields |
|------|-------|--------------|
| `$.user.name` | `"alice"` | s, b3, ocv |
| `$.user.age` | `30` | s, b3, ocf |
| `$.user.tags[0]` | `"admin"` | s, b3, ocv, a=true |
| `$.user.tags[1]` | `"moderator"` | s, b3, ocv, a=true |

### Index Fields in SteVec Entries

| Field | Name | Purpose | Generated For |
|-------|------|---------|---------------|
| `s` | Selector | Encrypted path identifier | All entries |
| `b3` | Blake3 | Exact match hash | All leaf values |
| `ocf` | ORE Fixed | Range comparison (64-bit) | Numeric values |
| `ocv` | ORE Variable | Range comparison (variable) | String values |
| `a` | Array Flag | Indicates array membership | Array elements |
| `c` | Ciphertext | Encrypted value | All entries |

---

## Quick Start

### 1. Configure Schema

```typescript
// Using protectjs-ffi directly
const encryptConfig = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',
        indexes: {
          ste_vec: { prefix: 'users/profile' }
        }
      }
    }
  }
}
```

### 2. Initialize Client

```typescript
import { newClient } from '@cipherstash/protect-ffi'

const client = await newClient({ encryptConfig })
```

### 3. Encrypt JSON for Storage

```typescript
import { encrypt } from '@cipherstash/protect-ffi'

const ciphertext = await encrypt(client, {
  plaintext: { user: { role: 'admin', name: 'alice' } },
  table: 'users',
  column: 'profile'
})

// Result: { i, v, c, sv: [...] }
```

### 4. Encrypt Path Selector Query

```typescript
import { encryptQuery } from '@cipherstash/protect-ffi'

// For field access queries (e.g., jsonb_path_query)
const selector = await encryptQuery(client, {
  plaintext: '$.user.name',
  table: 'users',
  column: 'profile',
  indexType: 'ste_vec',
  queryOp: 'ste_vec_selector'  // Or use 'default' with string
})

// Result: { i, v, s: "..." }
```

### 5. Encrypt Containment Query

```typescript
import { encryptQuery } from '@cipherstash/protect-ffi'

// For containment queries (e.g., @> operator)
const query = await encryptQuery(client, {
  plaintext: { user: { role: 'admin' } },
  table: 'users',
  column: 'profile',
  indexType: 'ste_vec',
  queryOp: 'default'
})

// Result: { i, v, sv: [...] }
```

### 6. Use with SQL

```sql
-- Path selection
SELECT * FROM users
WHERE eql_v2.jsonb_path_exists(profile, $selector);

-- Containment
SELECT * FROM users
WHERE profile @> $query::jsonb;
```

---

## @cipherstash/stack Higher-Level API

If using the full [`@cipherstash/stack`](https://github.com/cipherstash/stack) library (not just protect-ffi directly), you get additional convenience patterns:

| @cipherstash/stack Pattern | Translates To | Output |
|-------------------|---------------|--------|
| `{ path: "user.email" }` | `encryptQuery` with `$.user.email` selector | `{ s }` |
| `{ path: "user.role", value: "admin" }` | `encryptQuery` with `{ user: { role: "admin" } }` term | `{ sv }` |
| `{ contains: { role: "admin" } }` | `encryptQuery` with term | `{ sv }` |
| `{ containedBy: { role: "admin" } }` | `encryptQuery` with term | `{ sv }` |

**Note:** Path+value queries use containment semantics (not selector+value comparison). The path is used to build a nested object structure for the containment query.

See the [@cipherstash/stack source](https://github.com/cipherstash/stack) for implementation details.

---

## Next Steps

- [API Reference](./jsonb-api-reference.md) - Detailed API documentation
- [Troubleshooting](./jsonb-troubleshooting.md) - Common issues and solutions
