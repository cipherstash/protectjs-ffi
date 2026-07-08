//! Wasm-bindgen bindings for protect-ffi.
//!
//! Mirrors the Neon exports in `lib.rs` for the `wasm32-unknown-unknown`
//! target. Uses `serde-wasm-bindgen` for JS↔Rust marshalling and wraps a
//! JS `getToken` callable (matching `@cipherstash/auth`'s
//! `AccessKeyStrategy.getToken()` shape) into a [`stack_auth::AuthStrategy`]
//! via a small adapter struct.
//!
//! Unlike the Neon path which uses `AutoStrategy` + env vars + the
//! filesystem-backed `stack-profile`, the wasm path is fully inline: the
//! client key is passed as a constructor option, and auth is delegated to
//! the JS-supplied strategy on every ZeroKMS request.
//!
//! # Auth caching
//!
//! [`JsAuthStrategy::get_token`] is invoked on every ZeroKMS request —
//! there is no Rust-side equivalent of [`stack_auth::AutoRefresh`] in the
//! wasm path. Caching is the JS strategy's responsibility (cookies,
//! `localStorage`, or whatever the embedding runtime provides). The
//! adapter is intentionally a thin shim so the host environment owns the
//! refresh / persistence policy.
//!
//! # Surface omissions
//!
//! Admin-shape operations (`ensureKeyset`, workspace management) are
//! intentionally not exported on the wasm surface — provisioning belongs
//! in your server, not in browser / edge code.

#![cfg(target_arch = "wasm32")]

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;

use cipherstash_client::encryption::{Plaintext, ScopedCipher, TypeParseError};
use cipherstash_client::eql::{
    encrypt_eql, EqlEncryptOpts, EqlOperation, Identifier as EqlIdentifier, PreparedPlaintext,
};
use cipherstash_client::schema::{CanonicalEncryptionConfig, ColumnConfig, Identifier};
use cipherstash_client::zerokms::{
    self, SecretKey, ViturKeyMaterial, WithContext, ZeroKMSBuilder, ZeroKMSWithClientKey,
};
use cipherstash_client::IdentifiedBy;
use serde::{Deserialize, Serialize};
use stack_auth::{AuthError, AuthStrategy, SecretToken, ServerError, ServiceToken};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::js_plaintext::{JsPlaintext, BIGINT_WIRE_KEY};
use crate::{
    auth_failure_message, encrypted_record_from_value, into_store_ciphertext, is_encrypted_value,
    prepare_query_plaintext, query_output, storage_output, validate_eql_version,
    DecryptBulkOptions, DecryptOptions, DecryptResult, EncryptBulkOptions, EncryptOptions,
    EncryptQueryBulkOptions, EncryptQueryOptions, EncryptedOutput, EqlVersion, Error, QueryOutput,
};

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

/// Install [`console_error_panic_hook`] so Rust panics surface as a JS
/// `Error` in the browser / Node console instead of a bare
/// `RuntimeError: unreachable executed` from the wasm trap. Idempotent —
/// safe to call from any number of entry points.
///
/// Wired via `#[wasm_bindgen(start)]` so it runs once at module
/// instantiation, before any `newClient` / `encrypt` / `decrypt` call.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// Auth strategy adapter
// ---------------------------------------------------------------------------

/// JS-backed [`AuthStrategy`].
///
/// Holds a JS callable `getToken(): Promise<TokenResult>` (the shape
/// `@cipherstash/auth`'s strategies expose) and calls it whenever
/// cipherstash-client asks for a fresh service token. Inline rather than
/// going through `stack_auth::AuthStrategyFn` because the JS callable type
/// is hard to express as a Rust closure in a stored struct.
pub(crate) struct JsAuthStrategy {
    /// The original JS strategy object — kept so `getToken()` is invoked with the
    /// correct `this` receiver. Class-based strategies read instance state via
    /// `this`; calling with `JsValue::NULL` breaks them.
    strategy: JsValue,
    get_token: js_sys::Function,
}

impl JsAuthStrategy {
    fn new(strategy: JsValue, get_token: js_sys::Function) -> Self {
        Self {
            strategy,
            get_token,
        }
    }
}

// Safety: wasm32-unknown-unknown is single-threaded, and `JsValue` /
// `js_sys::Function` handles cannot cross threads even in principle. The
// `Send + Sync` bound only exists because `cipherstash_client::ScopedCipher`
// and `ZeroKMSWithClientKey` carry a blanket `C: Send + Sync + 'static`
// bound on their methods (inherited from the native build). Dropping this
// unsafe impl requires an upstream change in cipherstash-client to relax
// those bounds on `target_arch = "wasm32"` (similar to the existing
// `AuthStrategy` split in `stack-auth`).
unsafe impl Send for JsAuthStrategy {}
unsafe impl Sync for JsAuthStrategy {}

impl AuthStrategy for &JsAuthStrategy {
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> {
        let promise = self.get_token.call0(&self.strategy);
        async move {
            let promise = promise.map_err(|e| {
                AuthError::Server(ServerError(format!("strategy.getToken() threw: {e:?}")))
            })?;
            let promise: js_sys::Promise = promise.dyn_into().map_err(|_| {
                AuthError::Server(ServerError(
                    "strategy.getToken() did not return a Promise".to_string(),
                ))
            })?;
            let result = JsFuture::from(promise).await.map_err(|e| {
                AuthError::Server(ServerError(format!("strategy.getToken() rejected: {e:?}")))
            })?;
            // `Reflect::get` throws on a non-object receiver, so validate up
            // front: a non-object resolution (e.g. a bare string) is a distinct,
            // clearer failure than the "missing token field" it would otherwise
            // surface as. Mirrors the Node seam's `downcast::<JsObject>` guard.
            if !result.is_object() {
                return Err(AuthError::Server(ServerError(
                    "strategy.getToken() did not return an object".to_string(),
                )));
            }
            // Accept both `@cipherstash/auth` shapes:
            //   >= 0.41: a `@byteslice/result` `Result` — `{ data: TokenResult }`
            //            on success, `{ failure: AuthFailure }` on error.
            //   <= 0.40 / custom strategies: the bare `TokenResult`, with `token`
            //            at the top level (the documented
            //            `getToken(): Promise<{ token }>` contract).
            // `result` is an object, so `Reflect::get` only throws on a getter
            // that itself throws (e.g. a Proxy trap) — propagate that rather than
            // silently treating the field as absent.
            let failure =
                js_sys::Reflect::get(&result, &JsValue::from_str("failure")).map_err(|e| {
                    AuthError::Server(ServerError(format!("reading failure field: {e:?}")))
                })?;
            if !failure.is_undefined() && !failure.is_null() {
                return Err(js_failure_to_auth_error(failure));
            }
            // Unwrap the `data` envelope when present (0.41+); otherwise read the
            // bare result object directly (<= 0.40).
            let data = js_sys::Reflect::get(&result, &JsValue::from_str("data")).map_err(|e| {
                AuthError::Server(ServerError(format!("reading data field: {e:?}")))
            })?;
            let source = if data.is_object() { data } else { result };
            let token =
                js_sys::Reflect::get(&source, &JsValue::from_str("token")).map_err(|e| {
                    AuthError::Server(ServerError(format!("missing token field: {e:?}")))
                })?;
            let token = token.as_string().ok_or_else(|| {
                AuthError::Server(ServerError("token field is not a string".to_string()))
            })?;
            Ok(ServiceToken::new(SecretToken::new(token)))
        }
    }
}

/// Reconstruct a [`stack_auth::AuthError`] from an `@cipherstash/auth`
/// `AuthFailure` (`{ ...payload, type, error: Error, help?, url? }`) via
/// [`AuthError::from_error_code`], so a strategy failure crosses back into Rust
/// as the real typed error — preserving its code and any structured payload
/// (e.g. `WORKSPACE_MISMATCH`'s `expected`/`actual`) — rather than a flattened
/// `Server`. Unknown / foreign codes fall through to `AuthError::Custom`.
fn js_failure_to_auth_error(failure: JsValue) -> AuthError {
    // A non-object failure (a bare string/number) carries no `type`/`error`, so
    // reconstruction would produce a blank `Custom("")`. Treat it as a malformed
    // strategy result with a clear message instead — mirroring the Neon seam's
    // `downcast::<JsObject>` guard.
    if !failure.is_object() {
        return AuthError::Server(ServerError("strategy.getToken failed".to_string()));
    }
    let code = js_sys::Reflect::get(&failure, &JsValue::from_str("type"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let message = js_sys::Reflect::get(&failure, &JsValue::from_str("error"))
        .ok()
        .and_then(|err| js_sys::Reflect::get(&err, &JsValue::from_str("message")).ok())
        .and_then(|m| m.as_string())
        .unwrap_or_default();
    // The structured payload is every own field except the reserved
    // `type`/`error`/`help`/`url`. `error` is a live JS `Error`; the rest are
    // plain values, so deserialization is lossless for what `from_error_code`
    // reads (and degrades to an empty map, i.e. `Custom`, if it ever isn't).
    let mut payload: serde_json::Map<String, serde_json::Value> =
        serde_wasm_bindgen::from_value(failure).unwrap_or_default();
    for key in ["type", "error", "help", "url"] {
        payload.remove(key);
    }
    AuthError::from_error_code(&code, auth_failure_message(&code, message), &payload)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Wasm-side client handle. Wraps the same `ScopedCipher` +
/// `ZeroKMSWithClientKey` pair the Neon side does, parameterised by
/// [`JsAuthStrategy`] instead of `AutoStrategy`.
#[wasm_bindgen]
pub struct WasmClient {
    cipher: Arc<ScopedCipher<JsAuthStrategy>>,
    zerokms: Arc<ZeroKMSWithClientKey<JsAuthStrategy>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
    /// EQL wire version this client emits. Decryption accepts both formats
    /// regardless of this setting.
    eql_version: EqlVersion,
}

/// Hex-encoded secret material that zeroizes its buffer on drop.
///
/// Used as the deserialization target for the client key so the raw hex
/// material lives only inside a zeroize-on-drop wrapper from the moment
/// serde produces it — even if `new_client` panics or returns early before
/// the key is consumed into `SecretKey`. `#[serde(transparent)]` makes a
/// bare JS string deserialize into it without any schema change.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
struct HexSecret(String);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOpts {
    encrypt_config: CanonicalEncryptionConfig,
    /// UUID identifying the client key (workspace's data-encryption keyset).
    /// Typed as `Uuid` so a malformed value fails at deserialization rather
    /// than later inside `from_hex`.
    client_id: Uuid,
    /// Hex-encoded v1 client key. Required — wasm has no
    /// `~/.cipherstash/secretkey.json` fallback. Wrapped in [`HexSecret`]
    /// so the raw hex buffer is zeroized on drop, including on any early
    /// error path before the bytes are moved into `SecretKey`.
    client_key: HexSecret,
    /// Optional keyset identifier (id or name). `None` uses the default
    /// keyset granted to the client.
    keyset: Option<IdentifiedBy>,
    /// EQL wire version to emit: 2 (default) or 3.
    eql_version: Option<u8>,
}

/// Construct a [`WasmClient`].
///
/// `opts.strategy` must be an `@cipherstash/auth`-shaped object — anything
/// with a `getToken(): Promise<{ token: string, ... }>` method works. It is
/// required: wasm has no env / filesystem fallback path.
#[wasm_bindgen(js_name = newClient)]
pub async fn new_client(opts: JsValue) -> Result<WasmClient, JsValue> {
    // Extract `strategy` before serde — the JS function on it can't survive
    // serde_wasm_bindgen, and the rest of the opts has no JS-callable fields.
    let strategy = js_sys::Reflect::get(&opts, &JsValue::from_str("strategy"))
        .map_err(|e| js_error(&format!("opts.strategy lookup failed: {e:?}")))?;
    if strategy.is_undefined() || strategy.is_null() {
        return Err(js_error("opts.strategy is required"));
    }
    let get_token = js_sys::Reflect::get(&strategy, &JsValue::from_str("getToken"))
        .map_err(|e| js_error(&format!("opts.strategy.getToken not found: {e:?}")))?;
    let get_token: js_sys::Function = get_token
        .dyn_into()
        .map_err(|_| js_error("opts.strategy.getToken is not a function"))?;
    let auth = JsAuthStrategy::new(strategy.clone(), get_token);

    let mut opts: NewClientOpts =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;

    // Validate before any network I/O: a bad eqlVersion should fail fast,
    // not after ZeroKMS setup.
    let eql_version = validate_eql_version(opts.eql_version).map_err(error_to_js)?;

    // Decode the hex buffer in place rather than via `SecretKey::from_hex`:
    // `from_hex` takes a `String` for the UUID, which would force an
    // `opts.client_id.to_string()` allocation that the round-trip parses back
    // to `Uuid` — and that allocation is never zeroized. By decoding here we
    // (a) keep the already-parsed `Uuid` and (b) keep the hex bytes inside
    // `HexSecret`, which zeroizes on drop even on the error path.
    let bytes_result = hex::decode(opts.client_key.0.as_bytes());
    opts.client_key.0.zeroize();
    let bytes =
        bytes_result.map_err(|e| js_error(&format!("invalid clientKey: invalid hex: {e}")))?;
    let secret_key = SecretKey::new(opts.client_id, ViturKeyMaterial::from(bytes));

    let zerokms = ZeroKMSBuilder::new(auth)
        .with_key_provider(secret_key)
        .build()
        .await
        .map_err(|e| js_error(&e.to_string()))?;
    let zerokms = Arc::new(zerokms);
    let cipher = ScopedCipher::init(zerokms.clone(), opts.keyset)
        .await
        .map_err(|e| js_error(&e.to_string()))?;

    Ok(WasmClient {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(
            opts.encrypt_config
                .into_config_map()
                .map_err(|e| js_error(&e.to_string()))?,
        ),
        eql_version,
    })
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt JS surface
// ---------------------------------------------------------------------------

// Top-level wasm-bindgen exports mirror the flat function shape of
// `@cipherstash/protect-ffi`'s Neon API (`encrypt(client, opts)`,
// `decrypt(client, opts)`, etc.) so the conditional `exports` map can
// resolve to the wasm output without consumers having to rewrite call
// sites between native and Edge runtimes.

#[wasm_bindgen]
pub async fn encrypt(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts = encode_plaintext(&opts)?;
    let opts: EncryptOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_encrypt(client, opts).await.map_err(error_to_js)?;
    to_js(&out)
}

#[wasm_bindgen(js_name = encryptBulk)]
pub async fn encrypt_bulk(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts = encode_plaintext_list(&opts, "plaintexts")?;
    let opts: EncryptBulkOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_encrypt_bulk(client, opts).await.map_err(error_to_js)?;
    to_js(&out)
}

#[wasm_bindgen(js_name = encryptQuery)]
pub async fn encrypt_query(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts = encode_plaintext(&opts)?;
    let opts: EncryptQueryOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_encrypt_query(client, opts).await.map_err(error_to_js)?;
    to_js(&out)
}

#[wasm_bindgen(js_name = encryptQueryBulk)]
pub async fn encrypt_query_bulk(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts = encode_plaintext_list(&opts, "queries")?;
    let opts: EncryptQueryBulkOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_encrypt_query_bulk(client, opts)
        .await
        .map_err(error_to_js)?;
    to_js(&out)
}

#[wasm_bindgen]
pub async fn decrypt(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts: DecryptOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_decrypt(client, opts).await.map_err(error_to_js)?;
    plaintext_to_js(&out)
}

#[wasm_bindgen(js_name = decryptBulk)]
pub async fn decrypt_bulk(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts: DecryptBulkOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_decrypt_bulk(client, opts).await.map_err(error_to_js)?;
    let arr = js_sys::Array::new();
    for plaintext in &out {
        arr.push(&plaintext_to_js(plaintext)?);
    }
    Ok(arr.into())
}

#[wasm_bindgen(js_name = decryptBulkFallible)]
pub async fn decrypt_bulk_fallible(client: &WasmClient, opts: JsValue) -> Result<JsValue, JsValue> {
    let opts: DecryptBulkOptions =
        serde_wasm_bindgen::from_value(opts).map_err(|e| js_error(&e.to_string()))?;
    let out = do_decrypt_bulk_fallible(client, opts)
        .await
        .map_err(error_to_js)?;
    let arr = js_sys::Array::new();
    for result in &out {
        let obj = js_sys::Object::new();
        match result {
            DecryptResult::Success { data } => {
                set_prop(&obj, "data", &plaintext_to_js(data)?)?;
            }
            DecryptResult::Error { error } => {
                set_prop(&obj, "error", &JsValue::from_str(error))?;
            }
        }
        arr.push(&obj);
    }
    Ok(arr.into())
}

#[wasm_bindgen(js_name = isEncrypted)]
pub fn is_encrypted(raw: JsValue) -> bool {
    let Ok(v) = serde_wasm_bindgen::from_value::<serde_json::Value>(raw) else {
        return false;
    };
    is_encrypted_value(&v)
}

// ---------------------------------------------------------------------------
// Logic helpers — mirror the Neon `#[neon::export]` fn bodies in lib.rs.
// ---------------------------------------------------------------------------

async fn do_encrypt(client: &WasmClient, opts: EncryptOptions) -> Result<EncryptedOutput, Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());
    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
    let plaintext = opts
        .plaintext
        .to_plaintext_with_type(column_config.cast_type)?;
    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        EqlOperation::Store,
    );
    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };
    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    storage_output(
        into_store_ciphertext(encrypted.remove(0))?,
        client.eql_version,
        column_config,
    )
}

async fn do_encrypt_bulk(
    client: &WasmClient,
    opts: EncryptBulkOptions,
) -> Result<Vec<EncryptedOutput>, Error> {
    // Group payloads by lock_context identity_claim — same shape as native.
    // We move the LockContext (no Clone) and extract its identity_claim
    // (Vec<String>, which IS Clone) as the group key.
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, crate::PlaintextPayload)>> = BTreeMap::new();
    for (idx, payload) in opts.plaintexts.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total: usize = groups.values().map(|v| v.len()).sum();
    let mut results: Vec<Option<EncryptedOutput>> = (0..total).map(|_| None).collect();

    for (identity_claim, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut payload_data: Vec<(usize, Identifier)> = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in payloads {
            let ident = Identifier::new(payload.table.clone(), payload.column.clone());
            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
            let plaintext = payload
                .plaintext
                .to_plaintext_with_type(column_config.cast_type)?;
            let eql_ident = EqlIdentifier::new(&payload.table, &payload.column);
            let prepared = PreparedPlaintext::new(
                Cow::Borrowed(column_config),
                eql_ident,
                plaintext,
                EqlOperation::Store,
            );
            prepared_plaintexts.push(prepared);
            payload_data.push((original_idx, ident));
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;
        for (eql_output, (original_idx, ident)) in encrypted.into_iter().zip(payload_data) {
            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
            results[original_idx] = Some(storage_output(
                into_store_ciphertext(eql_output)?,
                client.eql_version,
                column_config,
            )?);
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| Error::InvariantViolation(format!("missing bulk result {i}")))
        })
        .collect()
}

async fn do_encrypt_query(
    client: &WasmClient,
    opts: EncryptQueryOptions,
) -> Result<QueryOutput, Error> {
    let (prepared, column_config) = prepare_query_plaintext(
        &client.encrypt_config,
        &opts.table,
        &opts.column,
        &opts.plaintext,
        &opts.index_type,
        &opts.query_op,
        client.eql_version,
    )?;
    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };
    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    query_output(encrypted.remove(0), client.eql_version, column_config)
}

async fn do_encrypt_query_bulk(
    client: &WasmClient,
    opts: EncryptQueryBulkOptions,
) -> Result<Vec<QueryOutput>, Error> {
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, crate::QueryPayload)>> = BTreeMap::new();
    for (idx, payload) in opts.queries.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total: usize = groups.values().map(|v| v.len()).sum();
    let mut results: Vec<Option<QueryOutput>> = (0..total).map(|_| None).collect();

    for (identity_claim, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut payload_data: Vec<(usize, &ColumnConfig)> = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in &payloads {
            let (prepared, column_config) = prepare_query_plaintext(
                &client.encrypt_config,
                &payload.table,
                &payload.column,
                &payload.plaintext,
                &payload.index_type,
                &payload.query_op,
                client.eql_version,
            )?;
            prepared_plaintexts.push(prepared);
            payload_data.push((*original_idx, column_config));
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;
        // Place results back in original order
        for (eql_output, (original_idx, column_config)) in encrypted.into_iter().zip(payload_data) {
            results[original_idx] =
                Some(query_output(eql_output, client.eql_version, column_config)?);
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| Error::InvariantViolation(format!("missing query result {i}")))
        })
        .collect()
}

async fn do_decrypt(client: &WasmClient, opts: DecryptOptions) -> Result<JsPlaintext, Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let encrypted_record = encrypted_record_from_value(opts.ciphertext, lock_context)?;

    let bytes = client
        .zerokms
        .decrypt_single(encrypted_record, None, opts.unverified_context.as_ref())
        .await
        .map_err(Error::from)?;
    let plaintext = Plaintext::from_slice(bytes.as_slice()).map_err(Error::from)?;
    Ok(JsPlaintext::try_from(plaintext)?)
}

async fn do_decrypt_bulk(
    client: &WasmClient,
    opts: DecryptBulkOptions,
) -> Result<Vec<JsPlaintext>, Error> {
    let encrypted_records: Vec<WithContext<'static>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context: Vec<zerokms::Context> =
                payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let decrypted = client
        .zerokms
        .decrypt(encrypted_records, None, opts.unverified_context.as_ref())
        .await?;

    decrypted
        .into_iter()
        .map(|bytes| Plaintext::from_slice(&bytes).and_then(JsPlaintext::try_from))
        .collect::<Result<Vec<_>, TypeParseError>>()
        .map_err(Error::from)
}

async fn do_decrypt_bulk_fallible(
    client: &WasmClient,
    opts: DecryptBulkOptions,
) -> Result<Vec<DecryptResult>, Error> {
    // Decode each ciphertext independently so a single invalid payload turns
    // into a per-item `DecryptResult::Error` rather than aborting the whole
    // batch — matches the `*Fallible` contract.
    let parsed: Vec<Result<WithContext<'static>, Error>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context: Vec<zerokms::Context> =
                payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect();

    let mut results: Vec<Option<DecryptResult>> = (0..parsed.len()).map(|_| None).collect();
    let mut valid_records: Vec<WithContext<'static>> = Vec::with_capacity(parsed.len());
    let mut valid_indices: Vec<usize> = Vec::with_capacity(parsed.len());

    for (idx, item) in parsed.into_iter().enumerate() {
        match item {
            Ok(record) => {
                valid_records.push(record);
                valid_indices.push(idx);
            }
            Err(e) => {
                results[idx] = Some(DecryptResult::Error {
                    error: e.to_string(),
                });
            }
        }
    }

    let decrypted = client
        .zerokms
        .decrypt_fallible(valid_records, opts.unverified_context.map(Cow::Owned))
        .await?;

    for (item, idx) in decrypted.into_iter().zip(valid_indices) {
        results[idx] = Some(match item {
            Ok(bytes) => match Plaintext::from_slice(&bytes)
                .map_err(Error::from)
                .and_then(|p| JsPlaintext::try_from(p).map_err(Error::from))
            {
                Ok(data) => DecryptResult::Success { data },
                Err(e) => DecryptResult::Error {
                    error: e.to_string(),
                },
            },
            Err(e) => DecryptResult::Error {
                error: e.to_string(),
            },
        });
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("missing decrypt_fallible result at index {i}"))
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Error / value helpers
// ---------------------------------------------------------------------------

fn js_error(msg: &str) -> JsValue {
    js_sys::Error::new(msg).into()
}

fn error_to_js(e: Error) -> JsValue {
    js_error(&e.to_string())
}

fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| js_error(&e.to_string()))
}

fn set_prop(obj: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), value)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plaintext boundary encoding
// ---------------------------------------------------------------------------
//
// Every `plaintext` value is rewritten BEFORE serde_wasm_bindgen runs, for
// two reasons:
//
// 1. BigInt tagging. A JS `bigint` cannot pass through
//    `serde_wasm_bindgen::from_value` into the untagged `JsPlaintext` enum:
//    `deserialize_any` visits BOTH a BigInt and a safe-integer Number as
//    `visit_i64`, so after untagged buffering the two are indistinguishable
//    and a bigint would silently land in the `Number(f64)` arm (losing
//    precision beyond 2^53). Instead, `bigint` plaintexts are detected with
//    `JsValue::is_bigint`, bounds-checked against i64, and swapped for the
//    tagged wire map (`{BIGINT_WIRE_KEY: "<decimal>"}`). This mirrors what
//    `src/index.cts` does for the Neon boundary.
//
// 2. JSON canonicalization. The Neon boundary extracts every options object
//    with `neon::types::extract::Json`, i.e. `JSON.stringify` on the JS
//    side — so Neon plaintexts get JSON.stringify semantics: `toJSON` is
//    honored (a `Date` becomes its ISO string), `undefined` properties are
//    dropped, non-finite numbers become `null`, and anything JSON cannot
//    represent (a bigint nested inside a json-column document, a circular
//    reference) throws a `TypeError`. serde_wasm_bindgen walks the live
//    object instead, so without this step the platforms diverge — most
//    sharply for a nested bigint, which Neon rejects but serde folds into
//    the document as an i64 that later decrypts through f64 (silently
//    rounding above 2^53). Round-tripping every non-bigint plaintext
//    through `JSON.stringify` → `JSON.parse` makes the wasm boundary
//    match Neon exactly, including the thrown `TypeError`.
//
// Rewrites land on a shallow-cloned options object — the caller's object
// is never mutated.

/// Bounds error for a JS `bigint` outside `i64::MIN..=i64::MAX`. Names the
/// bounds and the offending direction; deliberately does not echo the
/// value (it is plaintext being encrypted). A `RangeError` — the class the
/// README and the `JsPlaintext` JSDoc promise, and the class the Neon
/// boundary (`src/bigintWire.ts`) throws.
fn bigint_bounds_error(value: &JsValue) -> JsValue {
    let negative = js_sys::BigInt::new(value)
        .ok()
        .and_then(|b| b.to_string(10).ok())
        .map(|s| String::from(s).starts_with('-'))
        .unwrap_or(false);
    let (direction, bound) = if negative {
        ("below", "minimum")
    } else {
        ("above", "maximum")
    };
    js_sys::RangeError::new(&format!(
        "BigInt plaintext is {direction} the {bound} supported value: \
         encrypted bigint values must fit in a signed 64-bit integer \
         (-9223372036854775808 to 9223372036854775807)"
    ))
    .into()
}

/// Convert a JS `bigint` into the tagged wire map `JsPlaintext`
/// deserializes into `JsPlaintext::BigInt`, erroring (with the i64 bounds
/// and direction) when the value does not fit an i64.
fn tagged_bigint_wire(value: &JsValue) -> Result<JsValue, JsValue> {
    debug_assert!(value.is_bigint());
    let v = i64::try_from(value.clone()).map_err(|_| bigint_bounds_error(value))?;
    let obj = js_sys::Object::new();
    set_prop(&obj, BIGINT_WIRE_KEY, &JsValue::from_str(&v.to_string()))?;
    Ok(obj.into())
}

/// Round-trip a value through `JSON.stringify` → `JSON.parse`, matching
/// the Neon boundary's `neon::types::extract::Json` semantics. Returns
/// `None` when the value has no JSON form (`undefined`, a function, a
/// symbol — `JSON.stringify` returns `undefined` for these): the caller
/// passes the value through untouched so serde reports its usual error,
/// mirroring Neon, where `JSON.stringify` drops the property and serde
/// reports the plaintext as missing. Propagates `JSON.stringify`'s
/// `TypeError` (nested bigint, circular reference) unchanged.
fn json_canonical(value: &JsValue) -> Result<Option<JsValue>, JsValue> {
    let json: JsValue = js_sys::JSON::stringify(value)?.into();
    // `js_sys::JSON::stringify` types its success as `JsString`, but for
    // undefined/function/symbol inputs the underlying JS value is
    // `undefined` — `as_string()` is the honest check.
    let Some(json) = json.as_string() else {
        return Ok(None);
    };
    js_sys::JSON::parse(&json).map(Some)
}

/// The canonical boundary form of one `plaintext` value: a `bigint` becomes
/// the tagged wire map (bounds-checked), everything else is JSON
/// canonicalized. `None` means "leave the value untouched" (no JSON form).
fn boundary_plaintext(value: &JsValue) -> Result<Option<JsValue>, JsValue> {
    if value.is_bigint() {
        return tagged_bigint_wire(value).map(Some);
    }
    json_canonical(value)
}

/// Shallow-clone `opts` with its top-level `plaintext` replaced by the
/// canonical boundary form ([`boundary_plaintext`]). Plaintexts with no
/// canonical form (and non-object `opts`) pass through untouched, so serde
/// reports its usual errors for malformed input.
fn encode_plaintext(opts: &JsValue) -> Result<JsValue, JsValue> {
    let Some(obj) = opts.dyn_ref::<js_sys::Object>() else {
        return Ok(opts.clone());
    };
    let plaintext =
        js_sys::Reflect::get(opts, &JsValue::from_str("plaintext")).unwrap_or(JsValue::UNDEFINED);
    let Some(encoded) = boundary_plaintext(&plaintext)? else {
        return Ok(opts.clone());
    };
    let clone = js_sys::Object::assign(&js_sys::Object::new(), obj);
    set_prop(&clone, "plaintext", &encoded)?;
    Ok(clone.into())
}

/// Bulk variant of [`encode_plaintext`]: shallow-clones `opts`, the payload
/// array at `key`, and each payload whose `plaintext` has a canonical
/// boundary form. Returns `opts` untouched when nothing needed rewriting.
fn encode_plaintext_list(opts: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    let Some(obj) = opts.dyn_ref::<js_sys::Object>() else {
        return Ok(opts.clone());
    };
    let list = js_sys::Reflect::get(opts, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED);
    let Some(arr) = list.dyn_ref::<js_sys::Array>() else {
        return Ok(opts.clone());
    };
    let item_plaintext = |item: &JsValue| {
        js_sys::Reflect::get(item, &JsValue::from_str("plaintext")).unwrap_or(JsValue::UNDEFINED)
    };
    let encoded = js_sys::Array::new();
    let mut changed = false;
    for item in arr.iter() {
        let plaintext = item_plaintext(&item);
        match (
            boundary_plaintext(&plaintext)?,
            item.dyn_ref::<js_sys::Object>(),
        ) {
            (Some(canonical), Some(item_obj)) => {
                let item_clone = js_sys::Object::assign(&js_sys::Object::new(), item_obj);
                set_prop(&item_clone, "plaintext", &canonical)?;
                encoded.push(&item_clone);
                changed = true;
            }
            _ => {
                encoded.push(&item);
            }
        }
    }
    if !changed {
        return Ok(opts.clone());
    }
    let clone = js_sys::Object::assign(&js_sys::Object::new(), obj);
    set_prop(&clone, key, &encoded)?;
    Ok(clone.into())
}

/// Convert a decrypted [`JsPlaintext`] into a JS value. The serde route
/// cannot produce a JS `bigint` (`JsPlaintext::BigInt` serializes as the
/// tagged wire map), so BigInt is constructed directly. Every other
/// variant goes through serde-wasm-bindgen's JSON-compatible serializer:
/// the default serializer emits Rust maps as JS `Map`s and nulls as
/// `undefined`, so a decrypted `JsonB` document would come back as
/// `Map { "score" => undefined }` on wasm while the Neon boundary returns
/// the plain object `{ score: null }` it round-trips through JSON.
fn plaintext_to_js(plaintext: &JsPlaintext) -> Result<JsValue, JsValue> {
    match plaintext {
        JsPlaintext::BigInt(v) => Ok(js_sys::BigInt::from(*v).into()),
        other => other
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|e| js_error(&e.to_string())),
    }
}
