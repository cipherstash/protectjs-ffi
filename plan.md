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

#### 2.2 Encryption Options (No Client - Passed Separately)
```rust
#[derive(Debug, Deserialize)]
struct EncryptOptions {
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<EncryptionContext>,
    service_token: Option<ServiceToken>,
}

#[derive(Debug, Deserialize)]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    service_token: Option<ServiceToken>,
}
```

#### 2.3 Decryption Options (No Client - Passed Separately)
```rust
#[derive(Debug, Deserialize)]
struct DecryptOptions {
    ciphertext: String,
    lock_context: Option<EncryptionContext>,
    service_token: Option<ServiceToken>,
}

#[derive(Debug, Deserialize)]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    service_token: Option<ServiceToken>,
}
```

### Phase 3: Refactor Functions to Use Export Macro

#### 3.1 New Client Function
```rust
#[neon::export(task, json)]
async fn new_client(opts: NewClientOptions) -> Result<Client, Error> {
    new_client_inner(opts.encrypt_config, opts.client_opts).await
}
```

#### 3.2 Encryption Functions (Client + Options Pattern)
```rust
#[neon::export(task, json)]
async fn encrypt(client: &Client, opts: EncryptOptions) -> Result<Encrypted, Error> {
    let plaintext_target = PlaintextTarget::new(
        opts.plaintext,
        // Get column config from client.encrypt_config
    );
    encrypt_inner(client.clone(), plaintext_target, ident, opts.service_token).await
}

#[neon::export(task, json)]
async fn encrypt_bulk(client: &Client, opts: EncryptBulkOptions) -> Result<Vec<Encrypted>, Error> {
    // Convert opts.plaintexts to Vec<(PlaintextTarget, Identifier)>
    encrypt_bulk_inner(client.clone(), plaintext_targets, opts.service_token).await
}
```

#### 3.3 Decryption Functions (Client + Options Pattern)
```rust
#[neon::export(task, json)]
async fn decrypt(client: &Client, opts: DecryptOptions) -> Result<String, Error> {
    decrypt_inner(
        client.clone(), 
        opts.ciphertext, 
        opts.lock_context.unwrap_or_default(), 
        opts.service_token
    ).await
}

#[neon::export(task, json)]
async fn decrypt_bulk(client: &Client, opts: DecryptBulkOptions) -> Result<Vec<String>, Error> {
    decrypt_bulk_inner(client.clone(), opts.ciphertexts, opts.service_token).await
}

#[neon::export(task, json)]
async fn decrypt_bulk_fallible(client: &Client, opts: DecryptBulkOptions) -> Result<Vec<Result<String, Error>>, Error> {
    decrypt_bulk_fallible_inner(client.clone(), opts.ciphertexts, opts.service_token).await
}
```

### Phase 4: Client Reference Management (Simplified)

**Solution**: Keep `Box<Client>` as the first parameter, eliminating the need for client registries.

**Benefits**:
- No complex client lifecycle management
- Direct memory management by Neon
- Maintains existing performance characteristics
- Simpler implementation

**Implementation**: The `#[neon::export]` macro can handle `Box<Client>` references directly, so we keep the current client management approach while only changing the options structure.

### Phase 5: Update TypeScript Definitions

Update `src/index.cts` to reflect new options-based API:

```typescript
interface NewClientOptions {
  encryptConfig: string;
  clientOpts?: ClientOpts;
}

interface EncryptOptions {
  plaintext: string;
  column: string;
  table: string;
  lockContext?: Context;
  serviceToken?: CtsToken;
}

interface EncryptBulkOptions {
  plaintexts: EncryptPayload[];
  serviceToken?: CtsToken;
}

interface DecryptOptions {
  ciphertext: string;
  lockContext?: Context;
  serviceToken?: CtsToken;
}

interface DecryptBulkOptions {
  ciphertexts: BulkDecryptPayload[];
  serviceToken?: CtsToken;
}

// Updated function signatures
declare module './load.cjs' {
  function newClient(opts: NewClientOptions): Promise<Client>
  function encrypt(client: Client, opts: EncryptOptions): Promise<Encrypted>
  function encryptBulk(client: Client, opts: EncryptBulkOptions): Promise<Encrypted[]>
  function decrypt(client: Client, opts: DecryptOptions): Promise<string>
  function decryptBulk(client: Client, opts: DecryptBulkOptions): Promise<string[]>
  function decryptBulkFallible(client: Client, opts: DecryptBulkOptions): Promise<DecryptResult[]>
}
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
const client = await newClient({ 
  encryptConfig, 
  clientOpts: JSON.parse(clientOptsJson) 
});
const result = await encrypt(client, { 
  plaintext: "data", 
  column: "col", 
  table: "table" 
});
```

This refactoring will modernize the codebase while providing a more ergonomic and maintainable API for users.