use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, errors::ConfigError,
        zero_kms_config::ZeroKMSConfig, CipherStashConfigFile, CipherStashSecretConfigFile,
        EnvSource, FileSource,
    },
    credentials::{ServiceCredentials, ServiceToken},
    encryption::{
        self, EncryptionError, IndexTerm, Plaintext, PlaintextTarget, ReferencedPendingPipeline,
        ScopedCipher, SteVec, TypeParseError,
    },
    schema::ColumnConfig,
    zerokms::{self, EncryptedRecord, RecordDecryptError, WithContext, ZeroKMSWithClientKey},
};
use cts_common::Crn;
use encrypt_config::{EncryptConfig, Identifier};
use neon::{
    prelude::*,
    types::extract::{Boxed, Json},
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr};
use tokio::runtime::Runtime;

mod encrypt_config;

// Return a global tokio runtime or create one if it doesn't exist.
// Throws a JavaScript exception if the `Runtime` fails to create.
fn runtime<'a, C: Context<'a>>(cx: &mut C) -> NeonResult<&'static Runtime> {
    static RUNTIME: OnceCell<Runtime> = OnceCell::new();

    RUNTIME.get_or_try_init(|| Runtime::new().or_else(|err| cx.throw_error(err.to_string())))
}

#[derive(Clone)]
struct Client {
    cipher: Arc<ScopedZeroKMSNoRefresh>,
    zerokms: Arc<ZeroKMSWithClientKey<ServiceCredentials>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
}

impl Finalize for Client {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "k")]
pub enum Encrypted {
    #[serde(rename = "ct")]
    Ciphertext {
        #[serde(rename = "c")]
        ciphertext: String,
        #[serde(rename = "ob")]
        ore_index: Option<Vec<String>>,
        #[serde(rename = "bf")]
        match_index: Option<Vec<u16>>,
        #[serde(rename = "hm")]
        unique_index: Option<String>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },
    #[serde(rename = "sv")]
    SteVec {
        #[serde(rename = "sv")]
        ste_vec_index: SteVec<16>,
        #[serde(rename = "i")]
        identifier: Identifier,
        #[serde(rename = "v")]
        version: u16,
    },
}

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
struct ClientOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    client_id: Option<String>,
    client_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOptions {
    encrypt_config: String,
    client_opts: Option<ClientOpts>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DecryptResult {
    Success { data: String },
    Error { error: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptOptions {
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<LockContext>,
    service_token: Option<ServiceToken>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    service_token: Option<ServiceToken>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextPayload {
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<LockContext>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptOptions {
    ciphertext: String,
    lock_context: Option<LockContext>,
    service_token: Option<ServiceToken>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    service_token: Option<ServiceToken>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkDecryptPayload {
    ciphertext: String,
    lock_context: Option<LockContext>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockContext {
    identity_claim: Vec<String>,
}

impl Into<Vec<zerokms::Context>> for LockContext {
    fn into(self) -> Vec<zerokms::Context> {
        self.identity_claim
            .into_iter()
            .map(|claim| zerokms::Context::IdentityClaim(claim))
            .collect()
    }
}

#[neon::export]
async fn new_client(
    Json(opts): Json<NewClientOptions>,
) -> Result<Boxed<Client>, neon::types::extract::Error> {
    // TODO: pass in EncryptConfig object instead of string.
    let encrypt_config = EncryptConfig::from_str(&opts.encrypt_config)?;
    let client = new_client_inner(encrypt_config, opts.client_opts.unwrap_or_default()).await?;

    Ok(Boxed(client))
}

async fn new_client_inner(
    encrypt_config: EncryptConfig,
    client_opts: ClientOpts,
) -> Result<Client, Error> {
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

    let cipher = ScopedZeroKMSNoRefresh::init(zerokms.clone(), None).await?;

    Ok(Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config: Arc::new(encrypt_config.into_config_map()),
    })
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

    let encrypted = encrypt_inner(client, plaintext_target, ident, opts.service_token).await?;
    Ok(Json(encrypted))
}

async fn encrypt_inner(
    client: Client,
    plaintext_target: PlaintextTarget,
    ident: Identifier,
    service_token: Option<ServiceToken>,
) -> Result<Encrypted, Error> {
    let mut pipeline = ReferencedPendingPipeline::new(client.cipher);

    pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, 0)?;

    let mut source_encrypted = pipeline.encrypt(service_token).await?;

    let encrypted = source_encrypted.remove(0).ok_or_else(|| {
        Error::InvariantViolation(
            "`encrypt` expected a single result in the pipeline, but there were none".to_string(),
        )
    })?;

    to_eql_encrypted(encrypted, &ident)
}

#[neon::export]
async fn encrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptBulkOptions>,
) -> Result<Json<Vec<Encrypted>>, neon::types::extract::Error> {
    let mut plaintext_targets = Vec::with_capacity(opts.plaintexts.len());

    for payload in opts.plaintexts {
        let ident = Identifier::new(payload.table, payload.column);

        let column_config = client
            .encrypt_config
            .get(&ident)
            .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

        let mut plaintext_target = PlaintextTarget::new(payload.plaintext, column_config.clone());
        plaintext_target.context = payload.lock_context.map(Into::into).unwrap_or_default();

        plaintext_targets.push((plaintext_target, ident));
    }

    let encrypted_vec = encrypt_bulk_inner(client, plaintext_targets, opts.service_token).await?;
    Ok(Json(encrypted_vec))
}

async fn encrypt_bulk_inner(
    client: Client,
    plaintext_targets: Vec<(PlaintextTarget, Identifier)>,
    service_token: Option<ServiceToken>,
) -> Result<Vec<Encrypted>, Error> {
    let len = plaintext_targets.len();
    let mut pipeline = ReferencedPendingPipeline::new(client.cipher);
    let (plaintext_targets, identifiers): (Vec<PlaintextTarget>, Vec<Identifier>) =
        plaintext_targets.into_iter().unzip();

    for (i, plaintext_target) in plaintext_targets.into_iter().enumerate() {
        pipeline.add_with_ref::<PlaintextTarget>(plaintext_target, i)?;
    }

    let mut source_encrypted = pipeline.encrypt(service_token).await?;

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

    Ok(results)
}

#[neon::export]
async fn decrypt(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptOptions>,
) -> Result<String, neon::types::extract::Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let plaintext =
        decrypt_inner(client, opts.ciphertext, lock_context, opts.service_token).await?;
    Ok(plaintext)
}

async fn decrypt_inner(
    client: Client,
    ciphertext: String,
    encryption_context: Vec<zerokms::Context>,
    service_token: Option<ServiceToken>,
) -> Result<String, Error> {
    let encrypted_record = encrypted_record_from_mp_base85(&ciphertext, encryption_context)?;

    let decrypted = client
        .zerokms
        .decrypt_single(encrypted_record, service_token)
        .await?;

    plaintext_str_from_bytes(decrypted)
}

#[neon::export]
async fn decrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<Json<Vec<String>>, neon::types::extract::Error> {
    let mut ciphertexts = Vec::with_capacity(opts.ciphertexts.len());

    for payload in opts.ciphertexts {
        let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
        ciphertexts.push((payload.ciphertext, lock_context));
    }

    let plaintexts = decrypt_bulk_inner(client, ciphertexts, opts.service_token).await?;
    Ok(Json(plaintexts))
}

async fn decrypt_bulk_inner(
    client: Client,
    ciphertexts: Vec<(String, Vec<zerokms::Context>)>,
    service_token: Option<ServiceToken>,
) -> Result<Vec<String>, Error> {
    let len = ciphertexts.len();
    let mut encrypted_records: Vec<WithContext> = Vec::with_capacity(ciphertexts.len());

    for (ciphertext, encryption_context) in ciphertexts {
        let encrypted_record = encrypted_record_from_mp_base85(&ciphertext, encryption_context)?;
        encrypted_records.push(encrypted_record);
    }

    let decrypted = client
        .zerokms
        .decrypt(encrypted_records, service_token)
        .await?;

    let mut plaintexts: Vec<String> = Vec::with_capacity(len);

    for item in decrypted {
        plaintexts.push(plaintext_str_from_bytes(item)?);
    }

    Ok(plaintexts)
}

#[neon::export]
async fn decrypt_bulk_fallible(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<Json<Vec<DecryptResult>>, neon::types::extract::Error> {
    let mut ciphertexts = Vec::with_capacity(opts.ciphertexts.len());

    for payload in opts.ciphertexts {
        let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
        ciphertexts.push((payload.ciphertext, lock_context));
    }

    let results = decrypt_bulk_fallible_inner(client, ciphertexts, opts.service_token).await?;

    let json_results: Vec<DecryptResult> = results
        .into_iter()
        .map(|result| match result {
            Ok(data) => DecryptResult::Success { data },
            Err(err) => DecryptResult::Error {
                error: err.to_string(),
            },
        })
        .collect();

    Ok(Json(json_results))
}

async fn decrypt_bulk_fallible_inner(
    client: Client,
    ciphertexts: Vec<(String, Vec<zerokms::Context>)>,
    service_token: Option<ServiceToken>,
) -> Result<Vec<Result<String, Error>>, Error> {
    let len = ciphertexts.len();
    let mut encrypted_records: Vec<WithContext> = Vec::with_capacity(ciphertexts.len());

    for (ciphertext, encryption_context) in ciphertexts {
        let encrypted_record = encrypted_record_from_mp_base85(&ciphertext, encryption_context)?;
        encrypted_records.push(encrypted_record);
    }

    let decrypted = client
        .zerokms
        .decrypt_fallible(encrypted_records, service_token)
        .await?;

    let mut plaintexts = Vec::with_capacity(len);

    for item in decrypted {
        plaintexts.push(item.map_err(Error::from).and_then(plaintext_str_from_bytes));
    }

    Ok(plaintexts)
}

fn encrypted_record_from_mp_base85(
    base85str: &str,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext, Error> {
    let encrypted_record = EncryptedRecord::from_mp_base85(base85str)
        // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
        // Instead, we use `map_err`.
        .map_err(|err| Error::Base85(err.to_string()))?;

    Ok(WithContext {
        record: encrypted_record,
        context: encryption_context,
    })
}

fn plaintext_str_from_bytes(bytes: Vec<u8>) -> Result<String, Error> {
    let plaintext = Plaintext::from_slice(bytes.as_slice())?;

    match plaintext {
        Plaintext::Utf8Str(Some(ref inner)) => Ok(inner.clone()),
        _ => Err(Error::Unimplemented(
            "data types other than `Utf8Str`".to_string(),
        )),
    }
}

fn to_eql_encrypted(
    encrypted: encryption::Encrypted,
    identifier: &Identifier,
) -> Result<Encrypted, Error> {
    match encrypted {
        encryption::Encrypted::Record(ciphertext, terms) => {
            struct Indexes {
                match_index: Option<Vec<u16>>,
                ore_index: Option<Vec<String>>,
                unique_index: Option<String>,
            }

            let mut indexes = Indexes {
                match_index: None,
                ore_index: None,
                unique_index: None,
            };

            for index_term in terms {
                match index_term {
                    IndexTerm::Binary(bytes) => {
                        indexes.unique_index = Some(format_index_term_binary(&bytes))
                    }
                    IndexTerm::BitMap(inner) => indexes.match_index = Some(inner),
                    IndexTerm::OreArray(vec_of_bytes) => {
                        indexes.ore_index = Some(format_index_term_ore_array(&vec_of_bytes));
                    }
                    IndexTerm::OreFull(bytes) => {
                        indexes.ore_index = Some(format_index_term_ore(&bytes));
                    }
                    IndexTerm::OreLeft(bytes) => {
                        indexes.ore_index = Some(format_index_term_ore(&bytes));
                    }
                    IndexTerm::Null => {}
                    term => return Err(Error::Unimplemented(format!("index term `{term:?}`"))),
                };
            }

            let ciphertext = ciphertext
                .to_mp_base85()
                // The error type from `to_mp_base85` isn't public, so we don't derive an error for this one.
                // Instead, we use `map_err`.
                .map_err(|err| Error::Base85(err.to_string()))?;

            Ok(Encrypted::Ciphertext {
                ciphertext,
                identifier: identifier.to_owned(),
                match_index: indexes.match_index,
                ore_index: indexes.ore_index,
                unique_index: indexes.unique_index,
                version: 2,
            })
        }
        encryption::Encrypted::SteVec(ste_vec_index) => Ok(Encrypted::SteVec {
            identifier: identifier.to_owned(),
            ste_vec_index,
            version: 2,
        }),
    }
}

fn format_index_term_binary(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

fn format_index_term_ore_bytea(bytes: &Vec<u8>) -> String {
    hex::encode(bytes)
}

///
/// Formats a Vec<Vec<u8>> into a Vec<String>
///
fn format_index_term_ore_array(vec_of_bytes: &[Vec<u8>]) -> Vec<String> {
    vec_of_bytes
        .iter()
        .map(format_index_term_ore_bytea)
        .collect()
}

///
/// Formats a Vec<Vec<u8>> into a single elenent Vec<String>
///
fn format_index_term_ore(bytes: &Vec<u8>) -> Vec<String> {
    vec![format_index_term_ore_bytea(bytes)]
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let runtime = runtime(&mut cx)?;
    let _ = neon::set_global_executor(&mut cx, runtime);

    neon::registered().export(&mut cx)?;

    Ok(())
}
