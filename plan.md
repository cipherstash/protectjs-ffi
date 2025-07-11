# Neon Export Macro Refactoring Plan

## Overview

This plan outlines the refactoring of the CipherStash protect-ffi project to use Neon's modern `#[neon::export]` macro instead of the traditional `FunctionContext` approach, while also converting functions to accept options objects.

## Current State Analysis

### Existing Functions (lib.rs:824-834)
```rust
cx.export_function("newClient", new_client)?;
cx.export_function("encrypt", encrypt)?;
cx.export_function("encryptBulk", encrypt_bulk)?;
cx.export_function("decrypt", decrypt)?;
cx.export_function("decryptBulk", decrypt_bulk)?;
cx.export_function("decryptBulkFallible", decrypt_bulk_fallible)?;
```

### Current Function Signatures (Positional Args)
1. **newClient**: `(encrypt_config: String, client_opts?: String)`
2. **encrypt**: `(client: Box<Client>, plaintext_obj: Object, service_token?: Object)`
3. **encryptBulk**: `(client: Box<Client>, plaintext_array: Array, service_token?: Object)`
4. **decrypt**: `(client: Box<Client>, ciphertext: String, lock_context?: Object, service_token?: Object)`
5. **decryptBulk**: `(client: Box<Client>, ciphertext_array: Array, service_token?: Object)`
6. **decryptBulkFallible**: `(client: Box<Client>, ciphertext_array: Array, service_token?: Object)`

## Refactoring Goals

1. Replace manual `cx.export_function` calls with `#[neon::export]` macro
2. Convert all functions to accept single options objects
3. Leverage `#[neon::export(json)]` for complex data structures
4. Use `#[neon::export(task)]` for async operations
5. Improve type safety and ergonomics

## Step-by-Step Implementation Plan

### Phase 1: Preparation and Dependencies
- [ ] Update Cargo.toml dependencies to ensure latest Neon version
- [ ] Remove manual `#[neon::main]` function
- [ ] Create new option structs using serde for deserialization

### Phase 2: Define Options Structures

#### 2.1 Client Creation Options
```rust
#[derive(Debug, Deserialize)]
struct NewClientOptions {
    encrypt_config: String,
    client_opts: Option<ClientOpts>,
}
```

#### 2.2 Encryption Options
```rust
#[derive(Debug, Deserialize)]
struct EncryptOptions {
    client: String, // Will need to handle Client reference differently
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<EncryptionContext>,
    service_token: Option<ServiceToken>,
}

#[derive(Debug, Deserialize)]
struct EncryptBulkOptions {
    client: String,
    plaintexts: Vec<PlaintextPayload>,
    service_token: Option<ServiceToken>,
}
```

#### 2.3 Decryption Options
```rust
#[derive(Debug, Deserialize)]
struct DecryptOptions {
    client: String,
    ciphertext: String,
    lock_context: Option<EncryptionContext>,
    service_token: Option<ServiceToken>,
}

#[derive(Debug, Deserialize)]
struct DecryptBulkOptions {
    client: String,
    ciphertexts: Vec<BulkDecryptPayload>,
    service_token: Option<ServiceToken>,
}
```

### Phase 3: Refactor Functions to Use Export Macro

#### 3.1 New Client Function
```rust
#[neon::export(task)]
async fn new_client(opts: NewClientOptions) -> Result<Client, Error> {
    // Implementation using opts.encrypt_config and opts.client_opts
}
```

#### 3.2 Encryption Functions
```rust
#[neon::export(task)]
async fn encrypt(opts: EncryptOptions) -> Result<Encrypted, Error> {
    // Implementation using options object
}

#[neon::export(task)]
async fn encrypt_bulk(opts: EncryptBulkOptions) -> Result<Vec<Encrypted>, Error> {
    // Implementation using options object
}
```

#### 3.3 Decryption Functions
```rust
#[neon::export(task)]
async fn decrypt(opts: DecryptOptions) -> Result<String, Error> {
    // Implementation using options object
}

#[neon::export(task)]
async fn decrypt_bulk(opts: DecryptBulkOptions) -> Result<Vec<String>, Error> {
    // Implementation using options object
}

#[neon::export(task)]
async fn decrypt_bulk_fallible(opts: DecryptBulkOptions) -> Result<Vec<Result<String, Error>>, Error> {
    // Implementation using options object
}
```

### Phase 4: Handle Client Reference Management

**Challenge**: The current implementation passes `Box<Client>` directly. With options objects, we need an alternative approach.

**Solutions**:
1. **Client ID Approach**: Store clients in a global registry with IDs
2. **Serialization Approach**: Serialize client state (if feasible)
3. **Hybrid Approach**: Keep some functions with direct client parameter

**Recommended**: Client ID approach using a global concurrent HashMap:

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

static CLIENT_REGISTRY: Lazy<Arc<Mutex<HashMap<String, Client>>>> = 
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[neon::export(task)]
async fn new_client(opts: NewClientOptions) -> Result<String, Error> {
    let client = new_client_inner(opts.encrypt_config, opts.client_opts).await?;
    let client_id = Uuid::new_v4().to_string();
    
    CLIENT_REGISTRY.lock().unwrap().insert(client_id.clone(), client);
    Ok(client_id)
}
```

### Phase 5: Update TypeScript Definitions

Update `src/index.cts` to reflect new options-based API:

```typescript
interface NewClientOptions {
  encryptConfig: string;
  clientOpts?: ClientOpts;
}

interface EncryptOptions {
  clientId: string;
  plaintext: string;
  column: string;
  table: string;
  lockContext?: Context;
  serviceToken?: CtsToken;
}

// ... similar for other options
```

### Phase 6: Backward Compatibility

**Option A**: Create wrapper functions maintaining old API
**Option B**: Version bump with breaking changes
**Option C**: Support both APIs temporarily

**Recommended**: Option B with clear migration guide.

### Phase 7: Testing and Validation

- [ ] Update integration tests to use new options-based API
- [ ] Verify performance characteristics
- [ ] Test error handling and edge cases
- [ ] Validate TypeScript type definitions

## Benefits of This Refactoring

1. **Improved Developer Experience**: Single options object is more intuitive
2. **Better Type Safety**: Leverages serde for automatic validation
3. **Reduced Boilerplate**: No manual argument extraction
4. **Future-Proofing**: Easier to add new options without breaking changes
5. **Consistency**: All functions follow the same pattern
6. **Better Documentation**: Options structs serve as self-documenting interfaces

## Potential Challenges

1. **Client Management**: Need robust client lifecycle management
2. **Memory Management**: Ensure clients are properly cleaned up
3. **Breaking Changes**: API changes require version bump
4. **Performance**: Additional serialization/deserialization overhead
5. **Error Handling**: Need to adapt error types for new patterns

## Implementation Timeline

- **Week 1**: Phase 1-2 (Preparation and Options Structures)
- **Week 2**: Phase 3-4 (Function Refactoring and Client Management)  
- **Week 3**: Phase 5-6 (TypeScript Updates and Compatibility)
- **Week 4**: Phase 7 (Testing and Validation)

## Migration Guide for Users

```javascript
// Old API
const client = await newClient(encryptConfig, clientOptsJson);
const result = await encrypt(client, { plaintext: "data", column: "col", table: "table" });

// New API  
const clientId = await newClient({ 
  encryptConfig, 
  clientOpts: JSON.parse(clientOptsJson) 
});
const result = await encrypt({ 
  clientId, 
  plaintext: "data", 
  column: "col", 
  table: "table" 
});
```

This refactoring will modernize the codebase while providing a more ergonomic and maintainable API for users.