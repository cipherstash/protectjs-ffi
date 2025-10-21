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
        self, EncryptionError, Plaintext, PlaintextTarget, QueryOp, Queryable, ReferencedPendingPipeline, ScopedCipher, TypeParseError
    },
    schema::{column::IndexType, operator::{Operator, STEVecOperator}, ColumnConfig},
    zerokms::{self, RecordDecryptError, WithContext, ZeroKMSWithClientKey},
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

use crate::query::Query;

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
    #[error("no index found for column {}.{} supporting operator {}", _0.table, _0.column, _1)]
    MissingIndexForOperator(Identifier, Operator),
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
    #[serde(flatten)]
    plaintext: PlaintextPayload,
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
    #[serde(default)]
    lock_context: Vec<zerokms::Context>
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DecryptOptions {
    #[serde(flatten)]
    ciphertext: WithContext<Encrypted>,
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptBulkOptions {
    ciphertexts: Vec<WithContext<Encrypted>>,
    service_token: Option<ServiceToken>,
    unverified_context: Option<UnverifiedContext>,
}

// TODO: Remove
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
    let ident = Identifier::new(opts.plaintext.table, opts.plaintext.column);

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let mut plaintext_target = PlaintextTarget::new(opts.plaintext.plaintext, column_config.clone());
    plaintext_target.context = opts.plaintext.lock_context;

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
            plaintext_target.context = payload.lock_context; //.map(Into::into).unwrap_or_default();

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
) -> Result<Json<Query>, neon::types::extract::Error> {
    let ident = Identifier::new(opts.table, opts.column);

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let plaintext: Plaintext = opts.plaintext.into();
    let index = column_config.index_for_operator(&opts.operator)
        .ok_or_else(|| Error::MissingIndexForOperator(ident, opts.operator))?;

    let query_op = if let IndexType::SteVec { .. } = index.index_type {
        // NOTE: We don't currently use the QueryOp::SteVecTerm variant because a simpler approach was taken for proxy
        match opts.operator {
            Operator::STEVecOperator(STEVecOperator::Selector) => QueryOp::SteVecSelector,
            _ => QueryOp::Default,
        }
    } else {
        QueryOp::Default
    };

    let query: Query = (index, plaintext)
        .build_queryable(client.cipher, query_op).map_err(|e| Error::Unimplemented(format!("build queryable failed: {e}")))?
        .try_into()?;

    Ok(Json(query))
}

#[neon::export]
async fn decrypt(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptOptions>,
) -> Result<Json<JsPlaintext>, neon::types::extract::Error> {
    let DecryptOptions {
        ciphertext,
        service_token,
        unverified_context,
    } = opts;

    let plaintext = client
        .zerokms
        .decrypt_single(
            ciphertext,
            None,
            service_token,
            unverified_context,
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

    let decrypted = client
        .zerokms
        .decrypt(
            opts.ciphertexts,
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
    let decrypted = client
        .zerokms
        .decrypt_fallible(
            opts.ciphertexts,
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
    use cipherstash_client::{encryption::{JsonIndexer, JsonIndexerOptions, SteVec}, zerokms::{DataKey, DataKeyWithTag, EncryptedRecord}};
    use super::*;

    fn make_encrypted_record() -> EncryptedRecord {
        EncryptedRecord {
            keyset_id: None,
            iv: [1; 16],
            tag: vec![0, 1, 2, 3],
            descriptor: "users/email".to_string(),
            ciphertext: vec![0, 1, 2, 3],
        }
    }

    fn make_ste_vec(json: serde_json::Value) -> anyhow::Result<SteVec<16>> {
        let index_key = [0u8; 32];
        let data_key = DataKey { iv: [0u8; 16], key: [0u8; 32] };
        let data_key_with_tag = DataKeyWithTag {
            key: data_key,
            tag: vec![0u8; 16],
        };
        let opts = JsonIndexerOptions {
            prefix: "users".to_string(),
        };
        let indexer = JsonIndexer::new(opts);
        indexer.index(json, &index_key.into())?.encrypt(data_key_with_tag).map_err(|e| e.into())
    }

    mod is_encrypted {
        use serde_json::json;
        use super::*;

        #[test]
        fn valid_ciphertext_is_encrypted() {
            let encrypted: Encrypted = Encrypted::Ciphertext {
                ciphertext: make_encrypted_record(),
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

    #[test]
    fn test_deserialize_encrypted_with_context() {
        let ct = make_encrypted_record().to_mp_base85().unwrap();
        let json_data = serde_json::json!({
            "lockContext": [
                { "IdentityClaim": "sub" },
            ],
            "k": "ct",
            "c": ct,
            "i": { "t": "users", "c": "email" },
            "v": 2
        });

        let result: Result<WithContext<Encrypted>, _> = serde_json::from_value(json_data);
        assert!(result.is_ok());

        let with_context = result.unwrap();
        assert_eq!(with_context.context.len(), 1);
        match &with_context.context[0] {
            zerokms::Context::IdentityClaim(claim) => assert_eq!(claim, "sub"),
            _ => panic!("Expected IdentityClaim context"),
        }
    }

    #[test]
    fn test_deserialize_encrypted_with_context_lower() {
        let ct = make_encrypted_record().to_mp_base85().unwrap();
        let json_data = serde_json::json!({
            "lockContext": [
                { "identityClaim": "sub" },
            ],
            "k": "ct",
            "c": ct,
            "i": { "t": "users", "c": "email" },
            "v": 2
        });

        let result: Result<WithContext<Encrypted>, _> = serde_json::from_value(json_data);
        assert!(result.is_ok());

        let with_context = result.unwrap();
        assert_eq!(with_context.context.len(), 1);
        match &with_context.context[0] {
            zerokms::Context::IdentityClaim(claim) => assert_eq!(claim, "sub"),
            _ => panic!("Expected IdentityClaim context"),
        }
    }

    mod decrypt_options {
        use super::*;

        #[test]
        fn test_deserialize_ciphertext() {
            let ct = make_encrypted_record().to_mp_base85().unwrap();
            let json_data = serde_json::json!({
                "ciphertext": {
                    "k": "ct",
                    "c": ct,
                    "i": { "t": "users", "c": "email" },
                    "v": 2
                },
            });

            let result: Result<DecryptOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());

            let decrypt_options = result.unwrap();
            assert!(decrypt_options.ciphertext.context.is_empty());
            assert!(decrypt_options.service_token.is_none());
        }

        #[test]
        fn test_deserialize_ste_vec() -> anyhow::Result<()> {
            let ste_vec = make_ste_vec(serde_json::json!({"email":"foo@bar.com"}))?;

            let json_data = serde_json::json!({
                "ciphertext": {
                    "k": "sv",
                    "sv": ste_vec,
                    "i": { "t": "users", "c": "email" },
                    "v": 2
                },
            });


            let result: Result<DecryptOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());

            let decrypt_options = result.unwrap();
            assert!(decrypt_options.ciphertext.context.is_empty());
            assert!(decrypt_options.service_token.is_none());

            Ok(())
        }
    }

    mod bulk_decrypt_options {
        use super::*;

        #[test]
        fn test_deserialize_multiple_ciphertexts() {
            let ct1 = make_encrypted_record().to_mp_base85().unwrap();
            let ct2 = make_encrypted_record().to_mp_base85().unwrap();
            let json_data = serde_json::json!({
                "ciphertexts": [
                    {
                        "ciphertext": {
                            "k": "ct",
                            "c": ct1,
                            "i": { "t": "users", "c": "email" },
                            "v": 2
                        }
                    },
                    {
                        "ciphertext": {
                            "k": "ct",
                            "c": ct2,
                            "i": { "t": "users", "c": "email" },
                            "v": 2
                        }
                    }
                ],
            });

            let result: Result<DecryptBulkOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());

            let decrypt_options = result.unwrap();
            assert_eq!(decrypt_options.ciphertexts.len(), 2);
            assert!(decrypt_options.ciphertexts[0].context.is_empty());
            assert!(decrypt_options.ciphertexts[1].context.is_empty());
            assert!(decrypt_options.service_token.is_none());
        }

        #[test]
        fn test_deserialize_multiple_ste_vecs() -> anyhow::Result<()> {
            let ste_vec1 = make_ste_vec(serde_json::json!({"email":"foo@bar.com"}))?;
            let ste_vec2 = make_ste_vec(serde_json::json!({"email":"bar@foo.com"}))?;

            let json_data = serde_json::json!({
                "ciphertexts": [
                    {
                        "ciphertext": {
                            "k": "sv",
                            "sv": ste_vec1,
                            "i": { "t": "users", "c": "email" },
                            "v": 2
                        }
                    },
                    {
                        "ciphertext": {
                            "k": "sv",
                            "sv": ste_vec2,
                            "i": { "t": "users", "c": "email" },
                            "v": 2
                        }
                    }
                ],
            });

            let result: Result<DecryptBulkOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());

            let decrypt_options = result.unwrap();
            assert_eq!(decrypt_options.ciphertexts.len(), 2);
            assert!(decrypt_options.ciphertexts[0].context.is_empty());
            assert!(decrypt_options.ciphertexts[1].context.is_empty());
            assert!(decrypt_options.service_token.is_none());

            Ok(())
        }

        #[test]
        fn test_mutiple_encrypted_entries() -> anyhow::Result<()> {
            let ste_vec = make_ste_vec(serde_json::json!({"email":"bar@foo.com", "name":"Bar Foo"}))?;
            let entries = ste_vec.into_iter().collect::<Vec<_>>();

            let json_data = serde_json::json!({
                "ciphertexts": [
                    {
                        "ciphertext": {
                            "k": "sve",
                            "sve": entries[0],
                        }
                    },
                    {
                        "ciphertext": {
                            "k": "sve",
                            "sve": entries[1],
                        }
                    },
                ],
            });

            println!("json_data: {}", serde_json::to_string_pretty(&json_data)?);

            let result: Result<DecryptBulkOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());

            Ok(())
        }
    }

    mod query_options {
        use cipherstash_client::schema::operator;
        use super::*;

        #[test]
        fn test_deserialize_operator_selector() {
            let json_data = serde_json::json!({
                "plaintext": "$.foo",
                "column": "profile",
                "table": "users",
                "operator": "->"
            });

            let result: Result<QueryOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());
            let query_options = result.unwrap();
            assert_eq!(query_options.plaintext, JsPlaintext::String("$.foo".to_string()));
            assert_eq!(query_options.column, "profile");
            assert_eq!(query_options.table, "users");
            assert_eq!(query_options.operator, Operator::STEVecOperator(operator::STEVecOperator::Selector));
        }

        #[test]
        fn test_deserialize_operator_contains() {
            let json_data = serde_json::json!({
                "plaintext": {"foo": "bar"},
                "column": "profile",
                "table": "users",
                "operator": "@>"
            });

            let result: Result<QueryOptions, _> = serde_json::from_value(json_data);
            assert!(result.is_ok());
            let query_options = result.unwrap();
            assert_eq!(query_options.plaintext, JsPlaintext::JsonB(serde_json::json!({"foo": "bar"})));
            assert_eq!(query_options.column, "profile");
            assert_eq!(query_options.table, "users");
            assert_eq!(query_options.operator, Operator::STEVecOperator(operator::STEVecOperator::LeftContainsRight));
        }
    }
}