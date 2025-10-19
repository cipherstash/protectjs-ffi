mod encrypt_config;
mod eql;
mod js_plaintext;
mod query;

use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, errors::ConfigError,
        zero_kms_config::ZeroKMSConfig, CipherStashConfigFile, CipherStashSecretConfigFile,
        EnvSource, FileSource,
    },
    credentials::{ServiceCredentials, ServiceToken},
    encryption::{
        self, EncryptionError, IndexTerm, Plaintext, PlaintextTarget, QueryOp, Queryable,
        ReferencedPendingPipeline, ScopedCipher, SteVec, TypeParseError,
    },
    schema::{operator::Operator, ColumnConfig},
    zerokms::{self, EncryptedRecord, RecordDecryptError, WithContext, ZeroKMSWithClientKey},
    Crn, IdentifiedBy, UnverifiedContext,
};
use encrypt_config::{EncryptConfig, Identifier};
use eql::Encrypted;
use js_plaintext::JsPlaintext;
use neon::{
    prelude::*,
    types::extract::{Boxed, Json},
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
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
struct QueryOptions {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    #[serde(deserialize_with = "deserialize_operator")]
    operator: Operator,
}

fn deserialize_operator<'de, D>(deserializer: D) -> Result<Operator, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
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
    let ident = Identifier::new(opts.table, opts.column);

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let mut plaintext_target = PlaintextTarget::new(opts.plaintext, column_config.clone());
    plaintext_target.context = opts.lock_context.map(Into::into).unwrap_or_default();

    let mut pipeline = ReferencedPendingPipeline::new(client.cipher);

    pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, 0)?;

    let mut source_encrypted = pipeline
        .encrypt(opts.service_token, opts.unverified_context)
        .await?;

    let encrypted = source_encrypted.remove(0).ok_or_else(|| {
        Error::InvariantViolation(
            "`encrypt` expected a single result in the pipeline, but there were none".to_string(),
        )
    })?;

    Ok(Json(to_eql_encrypted(encrypted, &ident)?))
}

#[neon::export]
async fn encrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptBulkOptions>,
) -> Result<Json<Vec<Encrypted>>, neon::types::extract::Error> {
    let plaintext_targets = opts
        .plaintexts
        .into_iter()
        .map(|payload| {
            let ident = Identifier::new(payload.table, payload.column);

            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

            let mut plaintext_target =
                PlaintextTarget::new(payload.plaintext, column_config.clone());
            plaintext_target.context = payload.lock_context.map(Into::into).unwrap_or_default();

            Ok((plaintext_target, ident))
        })
        .collect::<Result<Vec<(PlaintextTarget, Identifier)>, Error>>()?;

    let len = plaintext_targets.len();
    let mut pipeline = ReferencedPendingPipeline::new(client.cipher);
    let (plaintext_targets, identifiers): (Vec<PlaintextTarget>, Vec<Identifier>) =
        plaintext_targets.into_iter().unzip();

    for (i, plaintext_target) in plaintext_targets.into_iter().enumerate() {
        pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, i)?;
    }

    let mut source_encrypted = pipeline
        .encrypt(opts.service_token, opts.unverified_context)
        .await?;

    let mut results: Vec<Encrypted> = Vec::with_capacity(len);

    for i in 0..len {
        let encrypted = source_encrypted.remove(i).ok_or_else(|| {
            Error::InvariantViolation(format!(
                "`encrypt_bulk` expected a result in the pipeline at index {i}, but there was none"
            ))
        })?;

        let ident = identifiers.get(i).ok_or_else(|| {
            Error::InvariantViolation(format!(
                "`encrypt_bulk` expected an identifier to exist for index {i}, but there was none"
            ))
        })?;

        let eql_payload = to_eql_encrypted(encrypted, ident)?;

        results.push(eql_payload);
    }

    Ok(Json(results))
}

#[neon::export]
async fn encrypt_query(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<QueryOptions>,
) -> Result<Json<IndexTerm>, neon::types::extract::Error> {
    let ident = Identifier::new(opts.table, opts.column);

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let plaintext: Plaintext = opts.plaintext.into();
    let index = column_config.index_for_operator(&opts.operator).unwrap(); // TODO: Handle no index found
    let term = (index, plaintext).build_queryable(client.cipher, QueryOp::Default)?;

    Ok(Json(term))
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
            None,
            opts.service_token,
            opts.unverified_context,
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

    let encrypted_records = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(ciphertext, encryption_context)
        })
        .collect::<Result<Vec<WithContext>, Error>>()?;

    let decrypted = client
        .zerokms
        .decrypt(
            encrypted_records,
            None,
            opts.service_token,
            opts.unverified_context,
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

    let encrypted_records: Result<Vec<WithContext>, Error> = ciphertexts
        .into_iter()
        .map(|(ciphertext, encryption_context)| {
            encrypted_record_from_mp_base85(ciphertext, encryption_context)
        })
        .collect();

    let encrypted_records = encrypted_records?;

    let decrypted = client
        .zerokms
        .decrypt_fallible(
            encrypted_records,
            opts.service_token,
            opts.unverified_context,
        )
        .await?;

    let plaintexts: Vec<Result<JsPlaintext, _>> = decrypted
        .into_iter()
        .map(|item| {
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
fn is_encrypted(
    Json(raw): Json<serde_json::Value>,
) -> bool {
    let result: Result<Encrypted, _> = serde_json::from_value(raw);
    result.is_ok()
}

fn encrypted_record_from_mp_base85(
    encrypted: Encrypted,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext, Error> {
    let encrypted_record = match encrypted {
        Encrypted::Ciphertext { ciphertext, .. } => EncryptedRecord::from_mp_base85(&ciphertext)
            // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
            // Instead, we use `map_err`.
            .map_err(|err| Error::Base85(err.to_string()))?,
        Encrypted::SteVec { ste_vec_index, .. } => {
            ste_vec_index.into_root_ciphertext().map_err(Error::from)?
        }
    };

    Ok(WithContext {
        record: encrypted_record,
        context: encryption_context,
    })
}

// Refactoring shim to extract EQL logic into a separate module (and eventually crate)
#[inline]
fn to_eql_encrypted(
    encrypted: encryption::Encrypted,
    identifier: &Identifier,
) -> Result<Encrypted, Error> {
    (encrypted, identifier).try_into()
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
        use serde_json::json;
        use super::*;

        #[test]
        fn valid_ciphertext_is_encrypted() {
            let encrypted: Encrypted = Encrypted::Ciphertext {
                ciphertext: "3q2+7w==".to_string(),
                ore_index: None,
                match_index: None,
                unique_index: None,
                identifier: crate::encrypt_config::Identifier {
                    table: "users".to_string(),
                    column: "email".to_string(),
                },
                version: 2,
            };

            let valid_encrypted = serde_json::to_value(&encrypted).unwrap();
            assert!(is_encrypted(Json(valid_encrypted)));
        }

        #[test]
        fn invalid_ciphertext_is_not_encrypted() {
            let invalid_encrypted = json!({"k":"invalid","c":"3q2+7w==","i":{"t":"users","c":"email"},"v":2});
            assert!(!is_encrypted(Json(invalid_encrypted)));
        }
    }
}
