mod js_plaintext;
#[cfg(target_arch = "wasm32")]
mod wasm;

use cipherstash_client::{
    encryption::{EncryptionError, Plaintext, QueryOp, ScopedCipher, TypeParseError},
    eql::{
        encrypt_eql, EqlCiphertext, EqlEncryptOpts, EqlError, EqlOperation, EqlOutput,
        Identifier as EqlIdentifier, PreparedPlaintext,
    },
    schema::{
        column::{Index, IndexType},
        errors::ConfigError,
        CanonicalEncryptionConfig, ColumnConfig, Identifier,
    },
    zerokms::{
        self, FallbackKeyProvider, KeyProvider, RecordDecryptError, SecretKey, WithContext,
        ZeroKMSBuilder, ZeroKMSBuilderError, ZeroKMSWithClientKey,
    },
    AuthError, AutoStrategy, IdentifiedBy, UnverifiedContext,
};
use cts_common::Crn;
use js_plaintext::JsPlaintext;
#[cfg(not(target_arch = "wasm32"))]
use neon::{
    prelude::*,
    types::{
        extract::{Boxed, Json},
        JsFuture,
    },
};
#[cfg(not(target_arch = "wasm32"))]
use stack_auth::{AuthStrategy, SecretToken};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct Client {
    cipher: Arc<ScopedZeroKMS>,
    zerokms: Arc<ZeroKMSWithClientKey<NodeAuthStrategy>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Finalize for Client {}

/// Re-export EqlCiphertext as Encrypted for backward compatibility.
///
/// `EqlCiphertext` is the EQL v2.3 storage payload — a discriminated enum that is either
/// a scalar `Encrypted` payload (`k = "ct"`) or a structured `SteVec` payload (`k = "sv"`).
/// The MessagePack-Base85 ciphertext lives at `c` on the scalar variant, or at `sv[0].c`
/// for the SteVec variant.
pub type Encrypted = EqlCiphertext;

/// What type of value was received in a query
#[derive(Debug, Clone)]
pub enum ReceivedKind {
    String(String),
    Number(f64),
    Boolean(bool),
    JsonObject,
    JsonArray,
    JsonScalar(String),
    Date,
}

impl std::fmt::Display for ReceivedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "String \"{}\"", truncate_for_error(s, 30)),
            Self::Number(n) => write!(f, "Number {}", n),
            Self::Boolean(b) => write!(f, "Boolean {}", b),
            Self::JsonObject => write!(f, "JSON object"),
            Self::JsonArray => write!(f, "JSON array"),
            Self::JsonScalar(s) => write!(f, "JSON scalar {}", s),
            Self::Date => write!(f, "Date"),
        }
    }
}

impl ReceivedKind {
    /// Introspect JSON values so object/array are distinguished.
    pub fn from_json(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Object(_) => Self::JsonObject,
            serde_json::Value::Array(_) => Self::JsonArray,
            serde_json::Value::String(s) => Self::JsonScalar(format!("\"{}\"", s)),
            serde_json::Value::Number(n) => Self::JsonScalar(n.to_string()),
            serde_json::Value::Bool(b) => Self::JsonScalar(b.to_string()),
            serde_json::Value::Null => Self::JsonScalar("null".to_string()),
        }
    }
}

/// What type of value was expected
#[derive(Debug, Clone, Copy)]
pub enum ExpectedKind {
    JsonObjectOrArray,
    StringPathOrJsonObjectOrArray,
}

impl std::fmt::Display for ExpectedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonObjectOrArray => write!(f, "JSON object or array"),
            Self::StringPathOrJsonObjectOrArray => {
                write!(f, "String (JSON path) or JSON object/array")
            }
        }
    }
}

/// Query operation context for errors
#[derive(Debug, Clone, Copy)]
pub enum QueryOpKind {
    SteVecTerm,
    SteVecDefault,
}

impl std::fmt::Display for QueryOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SteVecTerm => write!(f, "ste_vec_term"),
            Self::SteVecDefault => write!(f, "ste_vec (default)"),
        }
    }
}

/// Wrapper for bounded display of potentially large strings
#[derive(Debug, Clone)]
pub struct Truncated<'a> {
    value: std::borrow::Cow<'a, str>,
    max_len: usize,
}

impl<'a> Truncated<'a> {
    pub fn new(value: impl Into<std::borrow::Cow<'a, str>>, max_len: usize) -> Self {
        Self {
            value: value.into(),
            max_len,
        }
    }

    pub fn path(value: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        Self::new(value, 50)
    }
}

impl std::fmt::Display for Truncated<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.chars().count() <= self.max_len {
            write!(f, "{}", self.value)
        } else {
            let truncated: String = self.value.chars().take(self.max_len).collect();
            write!(f, "{}...", truncated)
        }
    }
}

/// Hints for InvalidQueryInput errors
#[derive(Debug, Clone, Copy)]
pub enum QueryInputHint {
    UseSelectorForPath,
    WrapInObject,
    WrapNumberInObject,
    WrapBooleanInObject,
    UsePathOrObject,
}

impl std::fmt::Display for QueryInputHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UseSelectorForPath => write!(f, "For path queries like '$.field', use queryOp: 'ste_vec_selector'. For containment queries, wrap the value in an object: {{\"field\": \"value\"}}."),
            Self::WrapInObject => write!(f, "Wrap the value in a JSON object: {{\"field\": value}}."),
            Self::WrapNumberInObject => write!(f, "Wrap the number in a JSON object to query by value: {{\"field\": <number>}}."),
            Self::WrapBooleanInObject => write!(f, "Wrap the boolean in a JSON object to query by value: {{\"field\": <boolean>}}."),
            Self::UsePathOrObject => write!(f, "Use a JSON path string like '$.field' for path queries, or a JSON object like {{\"field\": value}} for containment queries."),
        }
    }
}

/// Reasons for JSON path errors
#[derive(Debug, Clone, Copy)]
pub enum JsonPathReason {
    Empty,
    MissingDollar,
}

impl std::fmt::Display for JsonPathReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "path cannot be empty"),
            Self::MissingDollar => write!(f, "path must start with '$'"),
        }
    }
}

/// Hints for JSON path errors
#[derive(Debug, Clone)]
pub enum JsonPathHint {
    TryPrefix(String),
}

impl std::fmt::Display for JsonPathHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TryPrefix(path) => write!(f, "Try: '$.{}' or '$[\"{}\"]'.", path, path),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Credential error: {0}")]
    Credentials(String),
    #[error(transparent)]
    ZeroKMSBuilder(#[from] ZeroKMSBuilderError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    ZeroKMS(#[from] zerokms::Error),
    #[error(transparent)]
    TypeParse(#[from] TypeParseError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error(transparent)]
    Eql(#[from] EqlError),
    #[error("protect-ffi invariant violation: {0}. This is a bug in protect-ffi. Please file an issue at https://github.com/cipherstash/protectjs/issues.")]
    InvariantViolation(String),
    #[error("Unknown query operation: '{0}'")]
    UnknownQueryOp(String),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error("column {}.{} not found in Encrypt config", _0.table, _0.column)]
    UnknownColumn(Identifier),
    #[error(transparent)]
    RecordDecryptError(#[from] RecordDecryptError),
    #[error("Column '{column}' does not have a '{index_type}' index configured. {hint}")]
    MissingIndex {
        column: String,
        index_type: String,
        hint: String,
    },
    #[error(
        "Invalid query input for '{query_op}': received {received}, expected {expected}. {hint}"
    )]
    InvalidQueryInput {
        query_op: QueryOpKind,
        received: ReceivedKind,
        expected: ExpectedKind,
        hint: QueryInputHint,
    },
    #[error("Invalid JSON path '{path}': {reason}. {hint}")]
    InvalidJsonPath {
        path: Truncated<'static>,
        reason: JsonPathReason,
        hint: JsonPathHint,
    },
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// JS-backed [`AuthStrategy`] for the Neon build.
///
/// Holds the strategy object and its `getToken` callable as Neon [`Root`]s,
/// plus a [`Channel`] for invoking them from tokio tasks. Mirrors
/// `wasm::JsAuthStrategy` but uses Neon's cross-thread invocation model
/// instead of wasm's single-threaded one.
///
/// `getToken()` is called on every ZeroKMS request — caching is the JS
/// strategy's responsibility, matching the wasm path.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct NeonJsAuthStrategy {
    strategy: Arc<Root<JsObject>>,
    get_token: Arc<Root<JsFunction>>,
    channel: Channel,
}

#[cfg(not(target_arch = "wasm32"))]
impl NeonJsAuthStrategy {
    /// Build from a JS strategy object. Looks up `getToken` on the object
    /// via the shared [`JS_CHANNEL`] so the result is a stable [`Root`] we
    /// can call from any tokio task.
    async fn from_root(strategy: Root<JsObject>) -> Result<Self, Error> {
        let channel = JS_CHANNEL
            .get()
            .ok_or_else(|| Error::Credentials("module not initialized".to_string()))?
            .clone();
        let strategy = Arc::new(strategy);
        let strategy_for_lookup = Arc::clone(&strategy);
        let get_token = channel
            .send(move |mut cx| {
                let obj = strategy_for_lookup.to_inner(&mut cx);
                let func: Handle<JsFunction> = obj.prop(&mut cx, "getToken").get()?;
                Ok(func.root(&mut cx))
            })
            .await
            .map_err(|e| {
                Error::Credentials(format!("strategy.getToken lookup failed: {e}"))
            })?;
        Ok(Self {
            strategy,
            get_token: Arc::new(get_token),
            channel,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthStrategy for &NeonJsAuthStrategy {
    async fn get_token(self) -> Result<stack_auth::ServiceToken, AuthError> {
        let strategy = Arc::clone(&self.strategy);
        let get_token = Arc::clone(&self.get_token);
        let channel = self.channel.clone();

        // Schedule the JS call on the JS thread. The closure returns a
        // `JsFuture<Result<String, String>>`: outer Result distinguishes
        // a resolved token (Ok) from a structurally-bad result or a
        // rejection (Err); inner type carries the token string.
        let js_future: JsFuture<Result<String, String>> = channel
            .send(move |mut cx| {
                let strategy_h = strategy.to_inner(&mut cx);
                let func_h = get_token.to_inner(&mut cx);
                let args: [Handle<JsValue>; 0] = [];
                let result = func_h.call(&mut cx, strategy_h, args)?;
                let promise: Handle<JsPromise> = result.downcast_or_throw(&mut cx)?;
                promise.to_future(&mut cx, |mut cx, settled| match settled {
                    Ok(v) => {
                        let obj = match v.downcast::<JsObject, _>(&mut cx) {
                            Ok(o) => o,
                            Err(_) => {
                                return Ok(Err(
                                    "strategy.getToken did not return an object".to_string(),
                                ))
                            }
                        };
                        let token: Handle<JsString> = match obj.prop(&mut cx, "token").get() {
                            Ok(t) => t,
                            Err(_) => return Ok(Err("missing 'token' field".to_string())),
                        };
                        Ok(Ok(token.value(&mut cx)))
                    }
                    Err(err) => {
                        let msg = err
                            .to_string(&mut cx)
                            .map(|s| s.value(&mut cx))
                            .unwrap_or_else(|_| "strategy.getToken rejected".to_string());
                        Ok(Err(msg))
                    }
                })
            })
            .await
            .map_err(|e| AuthError::Server(format!("strategy callback failed: {e}")))?;

        let token_result = js_future
            .await
            .map_err(|e| AuthError::Server(format!("strategy promise await failed: {e}")))?;

        match token_result {
            Ok(s) => Ok(stack_auth::ServiceToken::new(SecretToken::new(s))),
            Err(msg) => Err(AuthError::Server(msg)),
        }
    }
}

/// Auth strategy held by the Neon-side [`Client`]. Either the
/// filesystem/env-backed [`AutoStrategy`] (built from credentials in opts
/// or the profile store) or a [`NeonJsAuthStrategy`] supplied by the
/// caller via `opts.strategy`.
///
/// `AutoStrategy` is boxed because it's substantially larger than the
/// JS-backed variant — without indirection clippy flags the size
/// imbalance as `large_enum_variant`.
#[cfg(not(target_arch = "wasm32"))]
enum NodeAuthStrategy {
    Auto(Box<AutoStrategy>),
    JsBacked(NeonJsAuthStrategy),
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthStrategy for &NodeAuthStrategy {
    async fn get_token(self) -> Result<stack_auth::ServiceToken, AuthError> {
        match self {
            NodeAuthStrategy::Auto(s) => (&**s).get_token().await,
            NodeAuthStrategy::JsBacked(s) => s.get_token().await,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
type ScopedZeroKMS = ScopedCipher<NodeAuthStrategy>;

/// Credential fields shared by [`ClientOpts`] and [`EnsureKeysetOpts`].
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CredentialOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    client_id: Option<String>,
    client_key: Option<String>,
}

impl CredentialOpts {
    /// Build an [`AutoStrategy`] from optional workspace CRN and access key,
    /// falling back to env vars and profile store for unset fields.
    fn build_strategy(&self) -> Result<AutoStrategy, Error> {
        let mut builder = AutoStrategy::builder();
        if let Some(key) = self.access_key.as_ref() {
            builder = builder.with_access_key(key);
        }
        if let Some(crn) = self.workspace_crn.as_ref() {
            builder = builder.with_workspace_crn(crn.clone());
        }
        Ok(builder.detect()?)
    }

    /// Build an `Option<SecretKey>` from the `client_id` + `client_key` pair.
    ///
    /// Returns `None` if either field is missing (triggers `FallbackKeyProvider` to try the
    /// profile store). Returns `Err` if the values are present but invalid.
    fn secret_key(&self) -> Result<Option<SecretKey>, Error> {
        match (self.client_id.as_ref(), self.client_key.as_ref()) {
            (Some(id), Some(key)) => SecretKey::from_hex(id.clone(), key.clone())
                .map(Some)
                .map_err(|e| Error::Credentials(e.to_string())),
            _ => Ok(None),
        }
    }

    /// Build a key provider that resolves the client key from explicit fields,
    /// falling back to the profile store (`~/.cipherstash/secretkey.json`).
    ///
    /// Note: env vars (`CS_CLIENT_ID`/`CS_CLIENT_KEY`) are read on the JS side
    /// and passed through as explicit fields to support Bun.
    ///
    /// Wasm32 has no filesystem — the wasm binding will pass the client key
    /// inline instead and skip the fallback path entirely.
    #[cfg(not(target_arch = "wasm32"))]
    fn build_key_provider(
        &self,
    ) -> Result<FallbackKeyProvider<Option<SecretKey>, stack_profile::ProfileStore>, Error> {
        Ok(FallbackKeyProvider::new(
            self.secret_key()?,
            stack_profile::ProfileStore::default(),
        ))
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ClientOpts {
    #[serde(flatten)]
    creds: CredentialOpts,
    keyset: Option<IdentifiedBy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnsureKeysetOpts {
    name: String,
    #[serde(flatten)]
    creds: CredentialOpts,
}

#[derive(Serialize)]
struct EnsureKeysetResult {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOptions {
    encrypt_config: CanonicalEncryptionConfig,
    client_opts: Option<ClientOpts>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DecryptResult {
    Success { data: JsPlaintext },
    Error { error: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptOptions {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextPayload {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    /// Lock context for this payload. Payloads with different lock_context values
    /// will be encrypted in separate batches to preserve per-payload context binding.
    lock_context: Option<LockContext>,
}

/// Options for encrypting a query term (search predicate)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptQueryOptions {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    /// The index type to use: "ste_vec", "match", "ore", "unique"
    index_type: String,
    /// The query operation: "default", "ste_vec_selector", "ste_vec_term"
    #[serde(default = "default_query_op")]
    query_op: String,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
}

fn default_query_op() -> String {
    "default".to_string()
}

/// Options for bulk query encryption
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptQueryBulkOptions {
    queries: Vec<QueryPayload>,
    unverified_context: Option<UnverifiedContext>,
}

/// Individual query payload for bulk operations
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryPayload {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    index_type: String,
    #[serde(default = "default_query_op")]
    query_op: String,
    lock_context: Option<LockContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptOptions {
    ciphertext: Encrypted,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkDecryptPayload {
    ciphertext: Encrypted,
    lock_context: Option<LockContext>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockContext {
    identity_claim: Vec<String>,
}

impl From<LockContext> for Vec<zerokms::Context> {
    fn from(val: LockContext) -> Self {
        val.identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect()
    }
}

/// Truncate a string for error messages
fn truncate_for_error(s: &str, max_len: usize) -> String {
    if max_len == 0 {
        return "...".to_string();
    }
    let mut out = String::new();
    let mut iter = s.chars();
    for _ in 0..max_len {
        match iter.next() {
            Some(ch) => out.push(ch),
            None => return s.to_string(),
        }
    }
    if iter.next().is_none() {
        return s.to_string();
    }
    format!("{}...", out)
}

/// Validate a JSON path string
fn validate_json_path(path: &str) -> Result<(), Error> {
    if path.is_empty() {
        return Err(Error::InvalidJsonPath {
            path: Truncated::path(path.to_string()),
            reason: JsonPathReason::Empty,
            hint: JsonPathHint::TryPrefix(path.to_string()),
        });
    }
    if !path.starts_with('$') {
        return Err(Error::InvalidJsonPath {
            path: Truncated::path(path.to_string()),
            reason: JsonPathReason::MissingDollar,
            hint: JsonPathHint::TryPrefix(path.to_string()),
        });
    }
    Ok(())
}

/// Get a description of what an index type is used for
fn index_type_description(index_type: &str) -> &'static str {
    match index_type {
        "ste_vec" => "JSON path and containment queries",
        "ore" => "range comparisons (<, >, <=, >=)",
        "ope" => "range comparisons (<, >, <=, >=)",
        "match" => "full-text search queries",
        "unique" => "exact match queries",
        _ => "unknown query type",
    }
}

/// Format available indexes on a column for error messages
fn format_available_indexes(column_config: &ColumnConfig) -> String {
    let available: Vec<&str> = column_config
        .indexes
        .iter()
        .map(|idx| match &idx.index_type {
            IndexType::SteVec { .. } => "ste_vec",
            IndexType::Match { .. } => "match",
            IndexType::Ore => "ore",
            IndexType::Ope => "ope",
            IndexType::Unique { .. } => "unique",
        })
        .collect();

    if available.is_empty() {
        "No indexes are configured for this column.".to_string()
    } else {
        format!("Available indexes: {}.", available.join(", "))
    }
}

/// Find the matching index from column config by index type name
fn find_index_for_type<'a>(
    column_config: &'a ColumnConfig,
    column_name: &str,
    index_type_name: &str,
) -> Result<&'a Index, Error> {
    column_config
        .indexes
        .iter()
        .find(|idx| {
            matches!(
                (&idx.index_type, index_type_name),
                (IndexType::SteVec { .. }, "ste_vec")
                    | (IndexType::Match { .. }, "match")
                    | (IndexType::Ore, "ore")
                    | (IndexType::Ope, "ope")
                    | (IndexType::Unique { .. }, "unique")
            )
        })
        .ok_or_else(|| {
            let available = format_available_indexes(column_config);
            let description = index_type_description(index_type_name);
            Error::MissingIndex {
                column: column_name.to_string(),
                index_type: index_type_name.to_string(),
                hint: format!(
                    "{} Add an '{}' index to enable {}.",
                    available, index_type_name, description
                ),
            }
        })
}

/// Parse query operation string to QueryOp enum
fn parse_query_op(query_op: &str) -> Result<QueryOp, Error> {
    match query_op {
        "default" => Ok(QueryOp::Default),
        "ste_vec_selector" => Ok(QueryOp::SteVecSelector),
        "ste_vec_term" => Ok(QueryOp::SteVecTerm),
        _ => Err(Error::UnknownQueryOp(query_op.to_string())),
    }
}

/// Inferred operation mode for query encryption.
///
/// This determines which EqlOperation to use:
/// - QueryMode: Use EqlOperation::Query (standard query encryption)
/// - StoreMode: Use EqlOperation::Store (for containment queries that need sv array)
#[derive(Debug, Clone, Copy)]
enum InferredQueryMode {
    /// Use EqlOperation::Query with the given QueryOp
    QueryMode(QueryOp),
    /// Use EqlOperation::Store (for JSON containment queries on ste_vec)
    StoreMode,
}

/// Convert JsPlaintext to Plaintext and infer the appropriate operation mode.
///
/// Returns both the converted Plaintext and the inferred operation mode.
///
/// Query mode has different type semantics than storage mode:
/// - SteVecSelector: Always string (JSON path like "$.user.email") → QueryMode
/// - SteVecTerm: Always JSON (fragment to match with @>) → StoreMode (produces sv array)
/// - Default: For SteVec indexes, infers from plaintext type:
///   - String → QueryMode with SteVecSelector (path queries)
///   - Json (Object/Array) → StoreMode (containment queries need sv array)
///   - Other indexes use column's cast_type and QueryMode with Default
fn to_query_plaintext(
    js_plaintext: &JsPlaintext,
    query_op: QueryOp,
    index_type: &IndexType,
    column_type: cipherstash_client::schema::column::ColumnType,
) -> Result<(Plaintext, InferredQueryMode), Error> {
    use cipherstash_client::schema::column::ColumnType;

    match query_op {
        QueryOp::SteVecSelector => {
            // Selector queries expect a string path like "$.user.email"
            // Validate the path if we have a string
            if let JsPlaintext::String(path) = js_plaintext {
                validate_json_path(path)?;
            }
            // Force Text conversion regardless of column type
            let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Text)?;
            Ok((
                plaintext,
                InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
            ))
        }
        QueryOp::SteVecTerm => {
            // Term queries expect a JSON fragment to match with @>
            // Provide helpful errors for wrong types
            match js_plaintext {
                JsPlaintext::String(s) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::String(s.clone()),
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::UseSelectorForPath,
                    });
                }
                JsPlaintext::Number(n) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::Number(*n),
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::WrapNumberInObject,
                    });
                }
                JsPlaintext::Boolean(b) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::Boolean(*b),
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::WrapBooleanInObject,
                    });
                }
                JsPlaintext::JsonB(_) => {
                    // This is the expected type - proceed
                }
                JsPlaintext::Date(_) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecTerm,
                        received: ReceivedKind::Date,
                        expected: ExpectedKind::JsonObjectOrArray,
                        hint: QueryInputHint::WrapInObject,
                    });
                }
            }
            // Use Store mode to produce sv array for containment matching
            let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Json)?;
            Ok((plaintext, InferredQueryMode::StoreMode))
        }
        QueryOp::Default => {
            // For SteVec indexes with Default queryOp, infer from plaintext type
            if matches!(index_type, IndexType::SteVec { .. }) {
                match js_plaintext {
                    JsPlaintext::String(path) => {
                        // String → selector (path queries like "$.user.email")
                        validate_json_path(path)?;
                        let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Text)?;
                        Ok((
                            plaintext,
                            InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
                        ))
                    }
                    JsPlaintext::JsonB(_) => {
                        // Object/Array → Store mode for containment queries
                        // This produces sv array needed for @> operator matching
                        let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Json)?;
                        Ok((plaintext, InferredQueryMode::StoreMode))
                    }
                    JsPlaintext::Number(n) => Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecDefault,
                        received: ReceivedKind::Number(*n),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                    JsPlaintext::Boolean(b) => Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecDefault,
                        received: ReceivedKind::Boolean(*b),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                    JsPlaintext::Date(_) => Err(Error::InvalidQueryInput {
                        query_op: QueryOpKind::SteVecDefault,
                        received: ReceivedKind::Date,
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                }
            } else {
                // Non-SteVec indexes: use column's storage type (original behavior)
                let plaintext = js_plaintext.to_plaintext_with_type(column_type)?;
                Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::Default)))
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
pub async fn new_client(
    Json(opts): Json<NewClientOptions>,
    strategy: Option<Root<JsObject>>,
) -> Result<Boxed<Client>, neon::types::extract::Error> {
    let client_opts = opts.client_opts.unwrap_or_default();

    let auth = match strategy {
        Some(s) => NodeAuthStrategy::JsBacked(NeonJsAuthStrategy::from_root(s).await?),
        None => NodeAuthStrategy::Auto(Box::new(client_opts.creds.build_strategy()?)),
    };
    let zerokms = ZeroKMSBuilder::new(auth)
        .with_key_provider(client_opts.creds.build_key_provider()?)
        .build()
        .await?;

    let zerokms = Arc::new(zerokms);
    let cipher = ScopedZeroKMS::init(zerokms.clone(), client_opts.keyset).await?;

    let client = Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(opts.encrypt_config.into_config_map()?),
    };

    Ok(Boxed(client))
}

/// Test-only helper: ensures a keyset with the given name exists, creating it if necessary,
/// and grants the current client access.
///
/// This function is designed for **test setup**, not production use. It performs a simple
/// list-then-create which is not safe against concurrent calls (TOCTOU), but that's acceptable
/// because test setup runs sequentially before any test execution.
///
/// The grant step is best-effort: "already granted" errors are expected and ignored,
/// but other grant failures are logged as warnings since they may indicate misconfiguration.
#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
pub async fn ensure_keyset(
    Json(opts): Json<EnsureKeysetOpts>,
) -> Result<Json<EnsureKeysetResult>, neon::types::extract::Error> {
    let strategy = opts.creds.build_strategy()?;

    // Management-only client (no client key needed for list/create)
    let zerokms = ZeroKMSBuilder::new(strategy).build()?;

    let keysets = zerokms.list_keysets(false).await?;

    let (keyset_id, name) = match keysets.iter().find(|ks| ks.name == opts.name) {
        Some(ks) => (ks.id, ks.name.clone()),
        None => {
            let created = zerokms
                .create_keyset(&opts.name, &format!("Auto-created keyset '{}'", opts.name))
                .await?;
            (created.id, created.name)
        }
    };

    // Grant the client access to the keyset.
    // "Already granted" errors are expected and ignored; other failures are logged.
    match opts.creds.build_key_provider()?.client_key().await {
        Ok(client_key) => {
            if let Err(e) = zerokms.grant_keyset(client_key.key_id, keyset_id).await {
                eprintln!("Warning: grant_keyset failed (may be already granted): {e}");
            }
        }
        Err(e) => {
            eprintln!("Warning: could not resolve client key for grant: {e}");
        }
    }

    Ok(Json(EnsureKeysetResult {
        id: keyset_id.to_string(),
        name,
    }))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptOptions>,
) -> Result<Json<Encrypted>, neon::types::extract::Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let plaintext = opts
        .plaintext
        .to_plaintext_with_type(column_config.cast_type)?;

    // Prepare for encrypt_eql
    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        EqlOperation::Store,
    );

    let eql_opts = EqlEncryptOpts {
        keyset_id: None, // Use cipher's default
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    let eql_ciphertext = into_store_ciphertext(encrypted.remove(0))?;

    Ok(Json(eql_ciphertext))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptBulkOptions>,
) -> Result<Json<Vec<Encrypted>>, neon::types::extract::Error> {
    // Group payloads by lock_context for batch processing
    // BTreeMap provides deterministic ordering of groups
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, PlaintextPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.plaintexts.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    // Pre-allocate results vector
    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<EqlCiphertext>> = (0..total_count).map(|_| None).collect();

    // Process each lock_context group
    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        // Build PreparedPlaintext items for this group
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

        // Place results back in original order
        for (eql_output, (original_idx, _ident)) in encrypted.into_iter().zip(payload_data) {
            results[original_idx] = Some(into_store_ciphertext(eql_output)?);
        }
    }

    // Unwrap all results (all should be Some)
    let final_results: Vec<EqlCiphertext> = results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("Missing encryption result for index {}", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(final_results))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt_query(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptQueryOptions>,
) -> Result<Json<EqlOutput>, neon::types::extract::Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    // Find the requested index type from column config
    let index = find_index_for_type(column_config, &opts.column, &opts.index_type)?;
    let query_op = parse_query_op(&opts.query_op)?;

    // Infer type and operation mode from plaintext
    // - String on SteVec → QueryMode with SteVecSelector (path queries)
    // - Object/Array on SteVec → StoreMode (containment queries need sv array)
    let (plaintext, inferred_mode) = to_query_plaintext(
        &opts.plaintext,
        query_op,
        &index.index_type,
        column_config.cast_type,
    )?;

    // Select the appropriate EqlOperation based on inferred mode
    let eql_operation = match inferred_mode {
        InferredQueryMode::QueryMode(qop) => EqlOperation::Query(&index.index_type, qop),
        InferredQueryMode::StoreMode => EqlOperation::Store,
    };

    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        eql_operation,
    );

    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    let eql_output = encrypted.remove(0);

    Ok(Json(eql_output))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt_query_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptQueryBulkOptions>,
) -> Result<Json<Vec<EqlOutput>>, neon::types::extract::Error> {
    // Group payloads by lock_context (same pattern as encrypt_bulk)
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, QueryPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.queries.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<EqlOutput>> = (0..total_count).map(|_| None).collect();

    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut original_indices = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in payloads {
            let ident = Identifier::new(payload.table.clone(), payload.column.clone());
            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

            let index = find_index_for_type(column_config, &payload.column, &payload.index_type)?;
            let query_op = parse_query_op(&payload.query_op)?;

            // Infer type and operation mode from plaintext
            // - String on SteVec → QueryMode with SteVecSelector (path queries)
            // - Object/Array on SteVec → StoreMode (containment queries need sv array)
            let (plaintext, inferred_mode) = to_query_plaintext(
                &payload.plaintext,
                query_op,
                &index.index_type,
                column_config.cast_type,
            )?;

            // Select the appropriate EqlOperation based on inferred mode
            let eql_operation = match inferred_mode {
                InferredQueryMode::QueryMode(qop) => EqlOperation::Query(&index.index_type, qop),
                InferredQueryMode::StoreMode => EqlOperation::Store,
            };

            let eql_ident = EqlIdentifier::new(&payload.table, &payload.column);
            let prepared = PreparedPlaintext::new(
                Cow::Borrowed(column_config),
                eql_ident,
                plaintext,
                eql_operation,
            );

            prepared_plaintexts.push(prepared);
            original_indices.push(original_idx);
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        for (eql_output, original_idx) in encrypted.into_iter().zip(original_indices) {
            results[original_idx] = Some(eql_output);
        }
    }

    let final_results: Vec<EqlOutput> = results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("Missing query result for index {}", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(final_results))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn decrypt(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptOptions>,
) -> Result<Json<JsPlaintext>, neon::types::extract::Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let encrypted_record = encrypted_record_from_mp_base85(opts.ciphertext, lock_context)?;

    let plaintext = client
        .zerokms
        .decrypt_single(
            encrypted_record,
            // Specifying None here will result in the client using the keyset identifier from the client
            None,
            opts.unverified_context.as_ref(),
        )
        .await
        .map_err(Error::from)
        .and_then(|bytes| Plaintext::from_slice(bytes.as_slice()).map_err(Error::from))?;

    JsPlaintext::try_from(plaintext)
        .map(Json)
        .map_err(From::from)
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn decrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<Json<Vec<JsPlaintext>>, neon::types::extract::Error> {
    let ciphertexts: Vec<(Encrypted, Vec<zerokms::Context>)> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            (payload.ciphertext, lock_context)
        })
        .collect();

    let encrypted_records: Vec<WithContext<'static>> = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(ciphertext, encryption_context)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let decrypted = client
        .zerokms
        .decrypt(
            encrypted_records,
            // Specifying None here will result in the client using the keyset identifier from the client
            None,
            opts.unverified_context.as_ref(),
        )
        .await?;

    let plaintexts = decrypted
        .into_iter()
        .map(|bytes| Plaintext::from_slice(&bytes).and_then(JsPlaintext::try_from))
        .collect::<Result<Vec<JsPlaintext>, TypeParseError>>()?;

    Ok(Json(plaintexts))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn decrypt_bulk_fallible(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<Json<Vec<DecryptResult>>, neon::types::extract::Error> {
    // Decode each ciphertext independently so a single invalid payload turns
    // into a per-item `DecryptResult::Error` rather than aborting the whole
    // batch — matches the `*Fallible` contract.
    let parsed: Vec<Result<WithContext<'static>, Error>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_mp_base85(payload.ciphertext, lock_context)
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

    let decrypted: Vec<Result<Vec<u8>, RecordDecryptError>> = client
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

    let results: Vec<DecryptResult> = results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("missing decrypt_fallible result at index {i}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(results))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
fn is_encrypted(Json(raw): Json<serde_json::Value>) -> bool {
    let result: Result<EqlCiphertext, _> = serde_json::from_value(raw);
    result.is_ok()
}

fn encrypted_record_from_mp_base85(
    encrypted: EqlCiphertext,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    // SteVec root invariant: ciphertext is always `sv[0]` (mirrors upstream
    // `SteVec::into_root_ciphertext`, which is not exposed on the wire type).
    let encrypted_record = match encrypted {
        EqlCiphertext::Encrypted(payload) => payload.ciphertext,
        EqlCiphertext::SteVec(payload) => {
            payload
                .ste_vec
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        "Missing root entry in SteVec EQL payload".to_string(),
                    )
                })?
                .ciphertext
        }
    };

    Ok(WithContext {
        record: encrypted_record,
        context: Cow::Owned(encryption_context),
    })
}

/// Extracts the [`EqlCiphertext`] from a Store-mode [`EqlOutput`].
///
/// Used by `encrypt` / `encrypt_bulk`, which always run with `EqlOperation::Store` and
/// therefore must produce storage ciphertexts (never query payloads).
fn into_store_ciphertext(output: EqlOutput) -> Result<EqlCiphertext, Error> {
    match output {
        EqlOutput::Store(ciphertext) => Ok(ciphertext),
        EqlOutput::Query(_) => Err(Error::InvariantViolation(
            "encrypt_eql returned a query payload for a store-mode encryption".to_string(),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

/// Channel captured at module init so [`NeonJsAuthStrategy`] can invoke
/// JS callables from tokio tasks without threading a `Cx` through every
/// call site.
#[cfg(not(target_arch = "wasm32"))]
static JS_CHANNEL: OnceCell<Channel> = OnceCell::new();

#[cfg(not(target_arch = "wasm32"))]
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let runtime = RUNTIME
        .get_or_try_init(Runtime::new)
        .or_else(|err| cx.throw_error(err.to_string()))?;

    let _ = neon::set_global_executor(&mut cx, runtime);
    let _ = JS_CHANNEL.set(cx.channel());

    neon::registered().export(&mut cx)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod truncate_for_error {
        use super::*;

        #[test]
        fn handles_non_ascii_without_panicking() {
            let input = "ééé";
            assert_eq!(truncate_for_error(input, 1), "é...");
        }

        #[test]
        fn returns_ellipsis_when_max_len_zero() {
            assert_eq!(truncate_for_error("abc", 0), "...");
        }
    }

    mod is_encrypted {
        use super::*;
        use cipherstash_client::eql::{
            EncryptedPayload, SteVecEntry, SteVecEntryTerm, SteVecPayload, EQL_SCHEMA_VERSION,
        };
        use cipherstash_client::zerokms::EncryptedRecord;
        use serde_json::json;

        fn dummy_encrypted_record() -> EncryptedRecord {
            EncryptedRecord {
                iv: Default::default(),
                ciphertext: vec![1; 16],
                tag: vec![2; 16],
                descriptor: "users/email".to_string(),
                keyset_id: None,
                decryption_policy: None,
            }
        }

        #[test]
        fn valid_scalar_ciphertext_is_encrypted() {
            let payload = EqlCiphertext::Encrypted(EncryptedPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: dummy_encrypted_record(),
                hmac_256: None,
                bloom_filter: None,
                ore_block_u64_8_256: None,
            });
            let value = serde_json::to_value(&payload).unwrap();
            assert_eq!(value["k"], "ct");
            assert!(is_encrypted(Json(value)));
        }

        #[test]
        fn valid_ste_vec_ciphertext_is_encrypted() {
            let payload = EqlCiphertext::SteVec(SteVecPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                ste_vec: vec![SteVecEntry {
                    selector: "deadbeef".into(),
                    ciphertext: dummy_encrypted_record(),
                    is_array: None,
                    term: SteVecEntryTerm::Hmac {
                        hmac_256: "feedface".into(),
                    },
                }],
            });
            let value = serde_json::to_value(&payload).unwrap();
            assert_eq!(value["k"], "sv");
            assert!(is_encrypted(Json(value)));
        }

        #[test]
        fn invalid_ciphertext_is_not_encrypted() {
            // Random JSON without the EQL discriminator must not be recognized as an
            // encrypted payload.
            let invalid_encrypted = json!({"random": "data"});
            assert!(!is_encrypted(Json(invalid_encrypted)));
        }

        #[test]
        fn missing_discriminator_is_not_encrypted() {
            // EQL v2.3 requires a `k` discriminator at the root ("ct" for scalar
            // payloads, "sv" for SteVec). Payloads without `k` are rejected even if
            // the other required fields are present.
            let no_discriminator = json!({
                "i": {"t": "users", "c": "email"},
                "v": 2
            });
            assert!(!is_encrypted(Json(no_discriminator)));
        }

        #[test]
        fn unknown_discriminator_is_not_encrypted() {
            // Only "ct" and "sv" are valid EQL v2.3 root discriminators.
            let unknown_discriminator = json!({
                "k": "wat",
                "i": {"t": "users", "c": "email"},
                "v": 2
            });
            assert!(!is_encrypted(Json(unknown_discriminator)));
        }
    }

    mod lock_context_grouping {
        use std::collections::BTreeMap;

        // Helper to simulate the grouping logic
        fn group_by_lock_context(
            payloads: Vec<(String, Option<Vec<String>>)>,
        ) -> BTreeMap<Vec<String>, Vec<(usize, String)>> {
            let mut groups: BTreeMap<Vec<String>, Vec<(usize, String)>> = BTreeMap::new();
            for (idx, (data, lock_context)) in payloads.into_iter().enumerate() {
                let key = lock_context.unwrap_or_default();
                groups.entry(key).or_default().push((idx, data));
            }
            groups
        }

        #[test]
        fn same_lock_context_groups_together() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:1".to_string()])),
                ("b".to_string(), Some(vec!["user:1".to_string()])),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            assert_eq!(groups.len(), 1);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 3);
        }

        #[test]
        fn different_lock_contexts_separate_groups() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:1".to_string()])),
                ("b".to_string(), Some(vec!["user:2".to_string()])),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            assert_eq!(groups.len(), 2);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 2);
            assert_eq!(groups[&vec!["user:2".to_string()]].len(), 1);
        }

        #[test]
        fn none_lock_context_groups_together() {
            let payloads = vec![
                ("a".to_string(), None),
                ("b".to_string(), None),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            assert_eq!(groups.len(), 2);
            assert_eq!(groups[&vec![]].len(), 2); // None becomes empty vec
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 1);
        }

        #[test]
        fn preserves_original_indices() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:2".to_string()])),
                ("b".to_string(), Some(vec!["user:1".to_string()])),
                ("c".to_string(), Some(vec!["user:2".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            // user:1 group should have index 1
            let user1_group = &groups[&vec!["user:1".to_string()]];
            assert_eq!(user1_group[0], (1, "b".to_string()));

            // user:2 group should have indices 0 and 2
            let user2_group = &groups[&vec!["user:2".to_string()]];
            assert_eq!(user2_group[0], (0, "a".to_string()));
            assert_eq!(user2_group[1], (2, "c".to_string()));
        }
    }

    mod query_op_parsing {
        use super::*;

        #[test]
        fn parse_query_op_default() {
            let result = parse_query_op("default");
            assert!(matches!(result, Ok(QueryOp::Default)));
        }

        #[test]
        fn parse_query_op_ste_vec_selector() {
            let result = parse_query_op("ste_vec_selector");
            assert!(matches!(result, Ok(QueryOp::SteVecSelector)));
        }

        #[test]
        fn parse_query_op_ste_vec_term() {
            let result = parse_query_op("ste_vec_term");
            assert!(matches!(result, Ok(QueryOp::SteVecTerm)));
        }

        #[test]
        fn parse_query_op_unknown_returns_error() {
            let result = parse_query_op("unknown");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Unknown query operation"));
        }
    }

    mod find_index_for_type_tests {
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn make_column_config_with_indexes(indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type: cipherstash_client::schema::column::ColumnType::Text,
                indexes,
                in_place: false,
                mode: cipherstash_client::schema::column::ColumnMode::Encrypted,
            }
        }

        #[test]
        fn find_ste_vec_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::SteVec {
                prefix: "test".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            })]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::SteVec { .. }
            ));
        }

        #[test]
        fn find_ore_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "ore");
            assert!(result.is_ok());
            assert!(matches!(result.unwrap().index_type, IndexType::Ore));
        }

        #[test]
        fn find_unique_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Unique {
                token_filters: vec![],
            })]);
            let result = find_index_for_type(&config, "test_column", "unique");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Unique { .. }
            ));
        }

        #[test]
        fn find_match_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 3,
                m: 2048,
                include_original: false,
            })]);
            let result = find_index_for_type(&config, "test_column", "match");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Match { .. }
            ));
        }

        #[test]
        fn missing_index_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("does not have"));
            assert!(err.to_string().contains("test_column"));
        }

        #[test]
        fn unknown_index_type_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "invalid_type");
            assert!(result.is_err());
        }

        #[test]
        fn missing_index_error_includes_column_and_suggestions() {
            let config = make_column_config_with_indexes(vec![
                Index::new(IndexType::Ore),
                Index::new(IndexType::Match {
                    tokenizer: Tokenizer::Standard,
                    token_filters: vec![],
                    k: 6,
                    m: 2048,
                    include_original: false,
                }),
            ]);
            let result = find_index_for_type(&config, "email", "ste_vec");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            // Should include column name
            assert!(
                err_msg.contains("email"),
                "Error should include column name: {}",
                err_msg
            );
            // Should include index type
            assert!(
                err_msg.contains("ste_vec"),
                "Error should include requested index type: {}",
                err_msg
            );
            // Should show available indexes
            assert!(
                err_msg.contains("ore"),
                "Error should show available ore index: {}",
                err_msg
            );
            assert!(
                err_msg.contains("match"),
                "Error should show available match index: {}",
                err_msg
            );
        }
    }

    mod query_inference_tests {
        use super::*;
        use cipherstash_client::encryption::Plaintext;
        use cipherstash_client::schema::column::Tokenizer;
        use cipherstash_client::schema::column::{ColumnType, IndexType};

        #[test]
        fn test_ste_vec_default_with_string_infers_selector() {
            let js_plaintext = JsPlaintext::String("$.user.email".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
            );

            // String on SteVec should infer QueryMode with SteVecSelector
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_object_infers_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"role": "admin"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
            );

            // Object on SteVec should infer StoreMode (produces sv array for containment)
            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_array_infers_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!(["admin", "user"]));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
            );

            // Array on SteVec should infer StoreMode (produces sv array for containment)
            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_number_returns_error() {
            let js_plaintext = JsPlaintext::Number(42.0);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
            );

            // Numbers should return error for SteVec queries
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Invalid query input"),
                "Error message should mention invalid input: {}",
                err_msg
            );
        }

        #[test]
        fn test_ste_vec_default_with_boolean_returns_error() {
            let js_plaintext = JsPlaintext::Boolean(true);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
            );

            // Booleans should return error for SteVec queries
            assert!(result.is_err());
        }

        #[test]
        fn test_explicit_ste_vec_selector_uses_query_mode() {
            let js_plaintext = JsPlaintext::String("$.name".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::Json,
            );

            // Explicit SteVecSelector should use QueryMode
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_explicit_ste_vec_term_uses_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"key": "value"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::Json,
            );

            // Explicit SteVecTerm uses StoreMode to produce sv array for containment
            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_non_ste_vec_default_uses_column_type() {
            let js_plaintext = JsPlaintext::String("search term".to_string());
            let index_type = IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: true,
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Text,
            );

            // Non-SteVec with Default should use column type and QueryMode with Default
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::Default)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_term_with_string_error_is_helpful() {
            let js_plaintext = JsPlaintext::String("admin".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::Json,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            // Should mention it's for ste_vec_term
            assert!(
                err_msg.contains("ste_vec_term"),
                "Error should mention ste_vec_term: {}",
                err_msg
            );
            // Should say what was received
            assert!(
                err_msg.contains("String"),
                "Error should mention received String: {}",
                err_msg
            );
            // Should suggest using ste_vec_selector for paths
            assert!(
                err_msg.contains("ste_vec_selector") || err_msg.contains("path"),
                "Error should suggest ste_vec_selector for paths: {}",
                err_msg
            );
        }

        #[test]
        fn test_invalid_json_path_error() {
            let js_plaintext = JsPlaintext::String("user.email".to_string()); // Missing $ prefix
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::Json,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            // Should mention the invalid path
            assert!(
                err_msg.contains("user.email"),
                "Error should show the invalid path: {}",
                err_msg
            );
            // Should suggest the correct format
            assert!(
                err_msg.contains("$.user.email") || err_msg.contains("$"),
                "Error should suggest correct format with $: {}",
                err_msg
            );
        }
    }
}
