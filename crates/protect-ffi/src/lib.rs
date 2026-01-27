mod encrypt_config;
mod js_plaintext;

use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, errors::ConfigError,
        zero_kms_config::ZeroKMSConfig, CipherStashConfigFile, CipherStashSecretConfigFile,
        EnvSource, FileSource,
    },
    credentials::{ServiceCredentials, ServiceToken},
    encryption::{EncryptionError, Plaintext, QueryOp, ScopedCipher, TypeParseError},
    eql::{
        encrypt_eql, EqlCiphertext, EqlEncryptOpts, EqlError, EqlOperation,
        Identifier as EqlIdentifier, PreparedPlaintext,
    },
    schema::{
        column::{Index, IndexType},
        ColumnConfig,
    },
    zerokms::{self, RecordDecryptError, WithContext, ZeroKMSWithClientKey},
    IdentifiedBy, UnverifiedContext,
};
use cts_common::Crn;
use encrypt_config::{EncryptConfig, Identifier};
use js_plaintext::JsPlaintext;
use neon::{
    prelude::*,
    types::extract::{Boxed, Json},
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::runtime::Runtime;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[derive(Clone)]
struct Client {
    cipher: Arc<ScopedZeroKMSNoRefresh>,
    zerokms: Arc<ZeroKMSWithClientKey<ServiceCredentials>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
}

impl Finalize for Client {}

/// Re-export EqlCiphertext as Encrypted for backward compatibility.
///
/// This is a unified structure that contains the identifier, version, and the encrypted body
/// with all associated cryptographic searchable encrypted metadata (SEM).
///
/// Note: The ciphertext field (c) is serialized in MessagePack Base85 format.
pub type Encrypted = EqlCiphertext;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] ConfigError),
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
    #[error("{0}")]
    Base85(String),
    #[error("unimplemented: {0} not supported yet by protect-ffi")]
    Unimplemented(String),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error("column {}.{} not found in Encrypt config", _0.table, _0.column)]
    UnknownColumn(Identifier),
    #[error(transparent)]
    RecordDecryptError(#[from] RecordDecryptError),
    #[error("index type '{0}' not configured for this column")]
    MissingIndex(String),
}

type ScopedZeroKMSNoRefresh = ScopedCipher<ServiceCredentials>;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ClientOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    client_id: Option<String>,
    client_key: Option<String>,
    keyset: Option<IdentifiedBy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOptions {
    encrypt_config: EncryptConfig,
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
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    service_token: Option<ServiceToken>,
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
    service_token: Option<ServiceToken>,
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
    service_token: Option<ServiceToken>,
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
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    service_token: Option<ServiceToken>,
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

/// Find the matching index from column config by index type name
fn find_index_for_type<'a>(
    column_config: &'a ColumnConfig,
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
                    | (IndexType::Unique { .. }, "unique")
            )
        })
        .ok_or_else(|| Error::MissingIndex(index_type_name.to_string()))
}

/// Parse query operation string to QueryOp enum
fn parse_query_op(query_op: &str) -> Result<QueryOp, Error> {
    match query_op {
        "default" => Ok(QueryOp::Default),
        "ste_vec_selector" => Ok(QueryOp::SteVecSelector),
        "ste_vec_term" => Ok(QueryOp::SteVecTerm),
        _ => Err(Error::Unimplemented(format!(
            "Unknown query_op: {}",
            query_op
        ))),
    }
}

/// Inferred operation mode for query encryption.
///
/// This determines which EqlOperation to use:
/// - QueryMode: Use EqlOperation::Query (standard query encryption)
/// - StoreMode: Use EqlOperation::Store (for containment queries that need sv array)
#[derive(Debug)]
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
///   - JsonB (Object/Array) → StoreMode (containment queries need sv array)
///   - Other indexes use column's cast_type and QueryMode with Default
fn to_query_plaintext(
    js_plaintext: &JsPlaintext,
    query_op: QueryOp,
    index_type: &IndexType,
    column_type: cipherstash_client::schema::column::ColumnType,
) -> Result<(Plaintext, InferredQueryMode), TypeParseError> {
    use cipherstash_client::schema::column::ColumnType;

    match query_op {
        QueryOp::SteVecSelector => {
            // Selector queries expect a string path like "$.user.email"
            // Force Utf8Str conversion regardless of column type
            let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Utf8Str)?;
            Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::SteVecSelector)))
        }
        QueryOp::SteVecTerm => {
            // Term queries expect a JSON fragment to match with @>
            // Use Store mode to produce sv array for containment matching
            let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::JsonB)?;
            Ok((plaintext, InferredQueryMode::StoreMode))
        }
        QueryOp::Default => {
            // For SteVec indexes with Default queryOp, infer from plaintext type
            if matches!(index_type, IndexType::SteVec { .. }) {
                match js_plaintext {
                    JsPlaintext::String(_) => {
                        // String → selector (path queries like "$.user.email")
                        let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Utf8Str)?;
                        Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::SteVecSelector)))
                    }
                    JsPlaintext::JsonB(_) => {
                        // Object/Array → Store mode for containment queries
                        // This produces sv array needed for @> operator matching
                        let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::JsonB)?;
                        Ok((plaintext, InferredQueryMode::StoreMode))
                    }
                    _ => {
                        // Numbers and booleans don't make sense for SteVec queries
                        Err(TypeParseError(format!(
                            "Cannot use {} as SteVec query - use string for path queries or object/array for containment",
                            js_plaintext::js_plaintext_type_name(js_plaintext)
                        )))
                    }
                }
            } else {
                // Non-SteVec indexes: use column's storage type (original behavior)
                let plaintext = js_plaintext.to_plaintext_with_type(column_type)?;
                Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::Default)))
            }
        }
    }
}

#[neon::export]
pub async fn new_client(
    Json(opts): Json<NewClientOptions>,
) -> Result<Boxed<Client>, neon::types::extract::Error> {
    let client_opts = opts.client_opts.unwrap_or_default();
    let console_config = ConsoleConfig::builder().with_env().build()?;
    let cts_config = CtsConfig::builder().with_env().build()?;

    let zerokms_config_builder = {
        let mut zerokms_config_builder = ZeroKMSConfig::builder()
            .add_source(EnvSource::default())
            // Both files are optional and ignored if the file doesn't exist
            .add_source(FileSource::<CipherStashSecretConfigFile>::default().optional())
            .add_source(FileSource::<CipherStashConfigFile>::default().optional())
            .console_config(&console_config)
            .cts_config(&cts_config);

        if let Some(workspace_crn) = client_opts.workspace_crn {
            zerokms_config_builder = zerokms_config_builder.workspace_crn(workspace_crn);
        }

        if let Some(access_key) = client_opts.access_key {
            zerokms_config_builder = zerokms_config_builder.access_key(access_key);
        }

        if let Some(client_id) = client_opts.client_id {
            zerokms_config_builder = zerokms_config_builder.try_with_client_id(&client_id)?;
        }

        if let Some(client_key) = client_opts.client_key {
            zerokms_config_builder = zerokms_config_builder.try_with_client_key(&client_key)?;
        }

        zerokms_config_builder
    };

    let zerokms_config = zerokms_config_builder.build_with_client_key()?;

    let zerokms = Arc::new(zerokms_config.create_client());

    let cipher = ScopedZeroKMSNoRefresh::init(zerokms.clone(), client_opts.keyset).await?;

    let client = Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(opts.encrypt_config.into_config_map()),
    };

    Ok(Boxed(client))
}

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
        service_token: opts.service_token.map(Cow::Owned),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    let eql_ciphertext = encrypted.remove(0);

    Ok(Json(eql_ciphertext))
}

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
            service_token: opts.service_token.as_ref().map(Cow::Borrowed),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        // Place results back in original order
        for (eql_ciphertext, (original_idx, _ident)) in encrypted.into_iter().zip(payload_data) {
            results[original_idx] = Some(eql_ciphertext);
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

#[neon::export]
async fn encrypt_query(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptQueryOptions>,
) -> Result<Json<EqlCiphertext>, neon::types::extract::Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    // Find the requested index type from column config
    let index = find_index_for_type(column_config, &opts.index_type)?;
    let query_op = parse_query_op(&opts.query_op)?;

    // Infer type and operation mode from plaintext
    // - String on SteVec → QueryMode with SteVecSelector (path queries)
    // - Object/Array on SteVec → StoreMode (containment queries need sv array)
    let (plaintext, inferred_mode) = to_query_plaintext(&opts.plaintext, query_op, &index.index_type, column_config.cast_type)?;

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
        service_token: opts.service_token.map(Cow::Owned),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
    };

    let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
    let eql_ciphertext = encrypted.remove(0);

    Ok(Json(eql_ciphertext))
}

#[neon::export]
async fn encrypt_query_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptQueryBulkOptions>,
) -> Result<Json<Vec<EqlCiphertext>>, neon::types::extract::Error> {
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
    let mut results: Vec<Option<EqlCiphertext>> = (0..total_count).map(|_| None).collect();

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

            let index = find_index_for_type(column_config, &payload.index_type)?;
            let query_op = parse_query_op(&payload.query_op)?;

            // Infer type and operation mode from plaintext
            // - String on SteVec → QueryMode with SteVecSelector (path queries)
            // - Object/Array on SteVec → StoreMode (containment queries need sv array)
            let (plaintext, inferred_mode) =
                to_query_plaintext(&payload.plaintext, query_op, &index.index_type, column_config.cast_type)?;

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
            service_token: opts.service_token.as_ref().map(Cow::Borrowed),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
        };

        let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

        for (eql_ciphertext, original_idx) in encrypted.into_iter().zip(original_indices) {
            results[original_idx] = Some(eql_ciphertext);
        }
    }

    let final_results: Vec<EqlCiphertext> = results
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
            opts.service_token.map(Cow::Owned),
            opts.unverified_context.as_ref(),
        )
        .await
        .map_err(Error::from)
        .and_then(|bytes| Plaintext::from_slice(bytes.as_slice()).map_err(Error::from))?;

    JsPlaintext::try_from(plaintext)
        .map(Json)
        .map_err(From::from)
}

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
            opts.service_token.map(Cow::Owned),
            opts.unverified_context.as_ref(),
        )
        .await?;

    let plaintexts = decrypted
        .into_iter()
        .map(|bytes| Plaintext::from_slice(&bytes).and_then(JsPlaintext::try_from))
        .collect::<Result<Vec<JsPlaintext>, TypeParseError>>()?;

    Ok(Json(plaintexts))
}

#[neon::export]
async fn decrypt_bulk_fallible(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<Json<Vec<DecryptResult>>, neon::types::extract::Error> {
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

    let decrypted: Vec<Result<Vec<u8>, RecordDecryptError>> = client
        .zerokms
        .decrypt_fallible(
            encrypted_records,
            opts.service_token.map(Cow::Owned),
            opts.unverified_context.map(Cow::Owned),
        )
        .await?;

    let plaintexts: Vec<Result<JsPlaintext, Error>> = decrypted
        .into_iter()
        .map(|item: Result<Vec<u8>, RecordDecryptError>| {
            item.map_err(Error::from).and_then(|bytes| {
                Plaintext::from_slice(&bytes)
                    .map_err(Error::from)
                    .and_then(|e| JsPlaintext::try_from(e).map_err(Error::from))
            })
        })
        .collect();

    let results = plaintexts
        .into_iter()
        .map(|result| match result {
            Ok(data) => DecryptResult::Success { data },
            Err(err) => DecryptResult::Error {
                error: err.to_string(),
            },
        })
        .collect();

    Ok(Json(results))
}

#[neon::export]
fn is_encrypted(Json(raw): Json<serde_json::Value>) -> bool {
    let result: Result<EqlCiphertext, _> = serde_json::from_value(raw);
    result.is_ok()
}

fn encrypted_record_from_mp_base85(
    encrypted: EqlCiphertext,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    // EqlCiphertext.body.ciphertext is already deserialized from mp_base85 by serde
    let encrypted_record = encrypted.body.ciphertext.ok_or_else(|| {
        Error::InvariantViolation("Missing ciphertext in EQL payload".to_string())
    })?;

    Ok(WithContext {
        record: encrypted_record,
        context: Cow::Owned(encryption_context),
    })
}

static RUNTIME: OnceCell<Runtime> = OnceCell::new();

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let runtime = RUNTIME
        .get_or_try_init(Runtime::new)
        .or_else(|err| cx.throw_error(err.to_string()))?;

    let _ = neon::set_global_executor(&mut cx, runtime);

    neon::registered().export(&mut cx)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod is_encrypted {
        use super::*;
        use serde_json::json;

        #[test]
        fn valid_eql_ciphertext_is_encrypted() {
            // EqlCiphertext with minimal required fields (no ciphertext needed for validation)
            let valid_encrypted = json!({
                "i": {"t": "users", "c": "email"},
                "v": 2
            });

            assert!(is_encrypted(Json(valid_encrypted)));
        }

        #[test]
        fn valid_eql_ciphertext_with_ste_vec_is_encrypted() {
            // EqlCiphertext with SteVec entries (no ciphertext values needed)
            let valid_encrypted = json!({
                "i": {"t": "users", "c": "profile"},
                "v": 2,
                "sv": [
                    {"s": "deadbeef"}
                ]
            });

            assert!(is_encrypted(Json(valid_encrypted)));
        }

        #[test]
        fn invalid_ciphertext_is_not_encrypted() {
            // Missing required fields
            let invalid_encrypted = json!({"random": "data"});
            assert!(!is_encrypted(Json(invalid_encrypted)));
        }

        #[test]
        fn old_format_with_k_field_is_still_valid() {
            // Prior to cipherstash-client 0.32.0, protect-ffi used a discriminated union
            // with a "k" tag field ("ct" for ciphertext, "sv" for ste_vec). The new
            // EqlCiphertext format is a unified flat structure without the discriminant.
            //
            // The "k" field should be silently ignored by serde (no deny_unknown_fields),
            // allowing old format data to be recognized as valid encrypted data.
            // Only the required fields (i, v) need to be present.
            let old_format = json!({
                "k": "ct",  // Should be silently ignored
                "i": {"t": "users", "c": "email"},
                "v": 2
                // Note: "c" is optional, so minimal valid payload works
            });
            assert!(is_encrypted(Json(old_format)));
        }

        #[test]
        fn old_ste_vec_format_with_k_field_is_still_valid() {
            // Old SteVec format used "k": "sv" discriminant
            let old_format = json!({
                "k": "sv",  // Should be silently ignored
                "i": {"t": "users", "c": "profile"},
                "v": 2
            });
            assert!(is_encrypted(Json(old_format)));
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
            assert!(err.to_string().contains("Unknown query_op"));
        }
    }

    mod find_index_for_type_tests {
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn make_column_config_with_indexes(indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type: cipherstash_client::schema::column::ColumnType::Utf8Str,
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
            })]);
            let result = find_index_for_type(&config, "ste_vec");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::SteVec { .. }
            ));
        }

        #[test]
        fn find_ore_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "ore");
            assert!(result.is_ok());
            assert!(matches!(result.unwrap().index_type, IndexType::Ore));
        }

        #[test]
        fn find_unique_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Unique {
                token_filters: vec![],
            })]);
            let result = find_index_for_type(&config, "unique");
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
            let result = find_index_for_type(&config, "match");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Match { .. }
            ));
        }

        #[test]
        fn missing_index_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "ste_vec");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("not configured"));
        }

        #[test]
        fn unknown_index_type_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "invalid_type");
            assert!(result.is_err());
        }
    }

    mod query_inference_tests {
        use super::*;
        use cipherstash_client::encryption::Plaintext;
        use cipherstash_client::schema::column::{ColumnType, IndexType};
        use cipherstash_client::schema::column::Tokenizer;

        #[test]
        fn test_ste_vec_default_with_string_infers_selector() {
            let js_plaintext = JsPlaintext::String("$.user.email".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            // String on SteVec should infer QueryMode with SteVecSelector
            assert!(matches!(result, Ok((Plaintext::Utf8Str(Some(_)), InferredQueryMode::QueryMode(QueryOp::SteVecSelector)))));
        }

        #[test]
        fn test_ste_vec_default_with_object_infers_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"role": "admin"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            // Object on SteVec should infer StoreMode (produces sv array for containment)
            assert!(matches!(result, Ok((Plaintext::JsonB(Some(_)), InferredQueryMode::StoreMode))));
        }

        #[test]
        fn test_ste_vec_default_with_array_infers_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!(["admin", "user"]));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            // Array on SteVec should infer StoreMode (produces sv array for containment)
            assert!(matches!(result, Ok((Plaintext::JsonB(Some(_)), InferredQueryMode::StoreMode))));
        }

        #[test]
        fn test_ste_vec_default_with_number_returns_error() {
            let js_plaintext = JsPlaintext::Number(42.0);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            // Numbers should return error for SteVec queries
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot use"));
        }

        #[test]
        fn test_ste_vec_default_with_boolean_returns_error() {
            let js_plaintext = JsPlaintext::Boolean(true);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::JsonB,
            );

            // Booleans should return error for SteVec queries
            assert!(result.is_err());
        }

        #[test]
        fn test_explicit_ste_vec_selector_still_works() {
            let js_plaintext = JsPlaintext::String("$.name".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::JsonB,
            );

            // Explicit SteVecSelector should use QueryMode
            assert!(matches!(result, Ok((Plaintext::Utf8Str(Some(_)), InferredQueryMode::QueryMode(QueryOp::SteVecSelector)))));
        }

        #[test]
        fn test_explicit_ste_vec_term_uses_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"key": "value"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::JsonB,
            );

            // Explicit SteVecTerm uses StoreMode to produce sv array for containment
            assert!(matches!(result, Ok((Plaintext::JsonB(Some(_)), InferredQueryMode::StoreMode))));
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
                ColumnType::Utf8Str,
            );

            // Non-SteVec with Default should use column type and QueryMode with Default
            assert!(matches!(result, Ok((Plaintext::Utf8Str(Some(_)), InferredQueryMode::QueryMode(QueryOp::Default)))));
        }
    }
}
