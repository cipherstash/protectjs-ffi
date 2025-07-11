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
4. Use `async fn` with registered Tokio runtime for async operations
5. Improve type safety and ergonomics

## Async Functions vs Task Attribute

**Key Insight**: You do NOT need `#[neon::export(task)]` when using `async fn`. Here's the difference:

- **`async fn`**: Uses the registered global executor (Tokio runtime), returns a Promise automatically
- **`#[neon::export(task)]`**: Executes sync functions on Node's libuv worker pool

**Our Approach**: Use `async fn` with the global Tokio runtime since our functions are already async.

```rust
// ✅ Correct - async fn with registered runtime
#[neon::export(json)]
async fn encrypt(client: &Client, opts: EncryptOptions) -> Result<Encrypted, Error> {
    // This runs on the registered Tokio runtime
}

// ❌ Incorrect - mixing task with async
#[neon::export(task, json)]
async fn encrypt(...) -> ... {
    // This would be an error
}

// ✅ Alternative - task for sync functions
#[neon::export(task, json)]
fn encrypt_sync(client: &Client, opts: EncryptOptions) -> Result<Encrypted, Error> {
    // This runs on Node's worker pool
    // Would need to block_on() for async operations
}
```

## Step-by-Step Implementation Plan

### Phase 1: Preparation and Dependencies
- [ ] Update Cargo.toml dependencies to ensure latest Neon version (neon = "1")
- [ ] Update `#[neon::main]` function to register global Tokio runtime
- [ ] Create new option structs using serde for deserialization

#### 1.1 Runtime Setup
The current code already uses a global tokio runtime. We need to register it with Neon:

```rust
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // Register the global runtime with Neon for async fn support
    let runtime = RUNTIME.get_or_try_init(|| Runtime::new())?;
    neon::set_global_executor(runtime.handle().clone())?;

    // No need to manually export functions anymore -
    // #[neon::export] will handle this automatically
    Ok(())
}
```

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
#[neon::export(json)]
async fn new_client(opts: NewClientOptions) -> Result<Client, Error> {
    new_client_inner(opts.encrypt_config, opts.client_opts).await
}
```

#### 3.2 Encryption Functions (Client + Options Pattern)
```rust
#[neon::export(json)]
async fn encrypt(client: &Client, opts: EncryptOptions) -> Result<Encrypted, Error> {
    let plaintext_target = PlaintextTarget::new(
        opts.plaintext,
        // Get column config from client.encrypt_config
    );
    encrypt_inner(client.clone(), plaintext_target, ident, opts.service_token).await
}

#[neon::export(json)]
async fn encrypt_bulk(client: &Client, opts: EncryptBulkOptions) -> Result<Vec<Encrypted>, Error> {
    // Convert opts.plaintexts to Vec<(PlaintextTarget, Identifier)>
    encrypt_bulk_inner(client.clone(), plaintext_targets, opts.service_token).await
}
```

#### 3.3 Decryption Functions (Client + Options Pattern)
```rust
#[neon::export(json)]
async fn decrypt(client: &Client, opts: DecryptOptions) -> Result<String, Error> {
    decrypt_inner(
        client.clone(),
        opts.ciphertext,
        opts.lock_context.unwrap_or_default(),
        opts.service_token
    ).await
}

#[neon::export(json)]
async fn decrypt_bulk(client: &Client, opts: DecryptBulkOptions) -> Result<Vec<String>, Error> {
    decrypt_bulk_inner(client.clone(), opts.ciphertexts, opts.service_token).await
}

#[neon::export(json)]
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

## Function-by-Function Implementation Checklist

### Setup (Do Once)
- [x] Register global Tokio runtime in `#[neon::main]` function
- [x] Define all option structs with serde derives

### Individual Function Updates

#### newClient
- [x] Define `NewClientOptions` struct
- [x] Replace `fn new_client(mut cx: FunctionContext)` with `#[neon::export(json)] async fn new_client(opts: NewClientOptions)`
- [x] Update TypeScript definitions
- [x] Update integration tests to use new options-based API
- [x] Run `npm run debug` to verify Rust and TypeScript compile successfully
- [x] Run `npm test` in `./integration-tests` to verify behavior works correctly

#### encrypt
- [x] Define `EncryptOptions` struct
- [x] Replace `fn encrypt(mut cx: FunctionContext)` with `#[neon::export(json)] async fn encrypt(client: &Client, opts: EncryptOptions)`
- [x] Update TypeScript definitions
- [x] Update integration tests to use new options-based API
- [x] Run `npm run debug` to verify Rust and TypeScript compile successfully
- [x] Run `npm test` in `./integration-tests` to verify behavior works correctly

#### encryptBulk
- [x] Define `EncryptBulkOptions` struct
- [x] Replace `fn encrypt_bulk(mut cx: FunctionContext)` with `#[neon::export(json)] async fn encrypt_bulk(client: &Client, opts: EncryptBulkOptions)`
- [x] Update TypeScript definitions
- [x] Update integration tests to use new options-based API
- [x] Run `npm run debug` to verify Rust and TypeScript compile successfully
- [x] Run `npm test` in `./integration-tests` to verify behavior works correctly

#### decrypt
- [x] Define `DecryptOptions` struct
- [x] Replace `fn decrypt(mut cx: FunctionContext)` with `#[neon::export(json)] async fn decrypt(client: &Client, opts: DecryptOptions)`
- [x] Update TypeScript definitions
- [x] Update integration tests to use new options-based API
- [x] Run `npm run debug` to verify Rust and TypeScript compile successfully
- [x] Run `npm test` in `./integration-tests` to verify behavior works correctly

#### decryptBulk
- [x] Define `DecryptBulkOptions` struct
- [x] Replace `fn decrypt_bulk(mut cx: FunctionContext)` with `#[neon::export(json)] async fn decrypt_bulk(client: &Client, opts: DecryptBulkOptions)`
- [x] Update TypeScript definitions
- [x] Update integration tests to use new options-based API
- [x] Run `npm run debug` to verify Rust and TypeScript compile successfully
- [x] Run `npm test` in `./integration-tests` to verify behavior works correctly

#### decryptBulkFallible
- [x] Define `DecryptBulkFallibleOptions` struct (or reuse `DecryptBulkOptions`)
- [x] Replace `fn decrypt_bulk_fallible(mut cx: FunctionContext)` with `#[neon::export(json)] async fn decrypt_bulk_fallible(client: &Client, opts: DecryptBulkFallibleOptions)`
- [x] Update TypeScript definitions
- [x] Update integration tests to use new options-based API
- [x] Run `npm run debug` to verify Rust and TypeScript compile successfully
- [x] Run `npm test` in `./integration-tests` to verify behavior works correctly

### Final Cleanup
- [x] Remove manual `cx.export_function` calls from `#[neon::main]`
- [x] Remove unused helper functions (if any)
- [x] Run full integration test suite
- [ ] Update documentation and examples

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
