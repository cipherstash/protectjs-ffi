mod encrypt_config;
mod js_plaintext;

use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, errors::ConfigError,
        zero_kms_config::ZeroKMSConfig, CipherStashConfigFile, CipherStashSecretConfigFile,
        EnvSource, FileSource,
    },
    credentials::{ServiceCredentials, ServiceToken},
    encryption::{EncryptionError, Plaintext, ScopedCipher, TypeParseError},
    eql::{
        encrypt_eql, EqlCiphertext, EqlEncryptOpts, EqlError, EqlOperation,
        Identifier as EqlIdentifier, PreparedPlaintext,
    },
    schema::ColumnConfig,
    zerokms::{self, EncryptedRecord, RecordDecryptError, WithContext, ZeroKMSWithClientKey},
    IdentifiedBy, UnverifiedContext,
};
use std::{borrow::Cow, collections::BTreeMap};
use cts_common::Crn;
use encrypt_config::{EncryptConfig, Identifier};
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

/// Entry in an SteVec (structured encryption vector) for JSON field encryption.
/// Each entry represents an encrypted path/value pair in the JSON structure.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SteVecEntry {
    /// Entry ciphertext (mp_base85 encoded)
    #[serde(rename = "c")]
    pub ciphertext: String,
    /// Tokenized selector (hex encoded)
    #[serde(rename = "s", skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// Blake3 hash for exact matches
    #[serde(rename = "b3", skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
    /// ORE fixed-width for numeric comparisons
    #[serde(rename = "ocf", skip_serializing_if = "Option::is_none")]
    pub ore_fixed: Option<String>,
    /// ORE variable-width for string comparisons
    #[serde(rename = "ocv", skip_serializing_if = "Option::is_none")]
    pub ore_variable: Option<String>,
    /// Whether entry is in an array
    #[serde(rename = "a", skip_serializing_if = "Option::is_none")]
    pub is_array_item: Option<bool>,
}

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
        /// The root ciphertext (encrypted JSON value, mp_base85 encoded)
        #[serde(rename = "c")]
        ciphertext: String,
        /// The SteVec entries in EQL format
        #[serde(rename = "sv")]
        ste_vec_entries: Vec<SteVecEntry>,
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

    Ok(Json(eql_ciphertext_to_encrypted(eql_ciphertext, &ident)?))
}

#[neon::export]
async fn encrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptBulkOptions>,
) -> Result<Json<Vec<Encrypted>>, neon::types::extract::Error> {
    let mut prepared_plaintexts = Vec::with_capacity(opts.plaintexts.len());
    let mut identifiers = Vec::with_capacity(opts.plaintexts.len());

    for payload in opts.plaintexts {
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
        identifiers.push(ident);
    }

    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Borrowed(&[]),
        service_token: opts.service_token.map(Cow::Owned),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
    };

    let encrypted = encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;

    let results: Vec<Encrypted> = encrypted
        .into_iter()
        .zip(identifiers.iter())
        .map(|(eql, ident)| eql_ciphertext_to_encrypted(eql, ident))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(results))
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
    let result: Result<Encrypted, _> = serde_json::from_value(raw);
    result.is_ok()
}

fn encrypted_record_from_mp_base85(
    encrypted: Encrypted,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    let encrypted_record = match encrypted {
        Encrypted::Ciphertext { ciphertext, .. } => EncryptedRecord::from_mp_base85(&ciphertext)
            .map_err(|err| Error::Base85(err.to_string()))?,
        Encrypted::SteVec { ciphertext, .. } => {
            // For SteVec, use the root ciphertext for decryption
            EncryptedRecord::from_mp_base85(&ciphertext)
                .map_err(|err| Error::Base85(err.to_string()))?
        }
    };

    Ok(WithContext {
        record: encrypted_record,
        context: Cow::Owned(encryption_context),
    })
}

/// Converts an `EqlCiphertext` (from `encrypt_eql`) to protect-ffi's `Encrypted` format.
fn eql_ciphertext_to_encrypted(
    eql: EqlCiphertext,
    ident: &Identifier,
) -> Result<Encrypted, Error> {
    // Check if this is an SteVec (has ste_vec in sem)
    if let Some(ste_vec_bodies) = eql.body.sem.ste_vec {
        // Get root ciphertext
        let root_ciphertext = eql
            .body
            .ciphertext
            .ok_or_else(|| {
                Error::InvariantViolation("Missing root ciphertext in SteVec".to_string())
            })?
            .to_mp_base85()
            .map_err(|err| Error::Base85(err.to_string()))?;

        // Convert EqlCiphertextBody entries to SteVecEntry
        let entries: Vec<SteVecEntry> = ste_vec_bodies
            .into_iter()
            .map(|body| -> Result<SteVecEntry, Error> {
                let ciphertext = body
                    .ciphertext
                    .ok_or_else(|| {
                        Error::InvariantViolation("Missing ciphertext in SteVec entry".to_string())
                    })?
                    .to_mp_base85()
                    .map_err(|err| Error::Base85(err.to_string()))?;

                Ok(SteVecEntry {
                    ciphertext,
                    selector: body.sem.selector,
                    blake3: body.sem.blake3,
                    ore_fixed: body.sem.ore_cllw_u64_8,
                    ore_variable: body.sem.ore_cllw_var_8,
                    is_array_item: body.is_array_item,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        return Ok(Encrypted::SteVec {
            ciphertext: root_ciphertext,
            ste_vec_entries: entries,
            identifier: ident.clone(),
            version: 2,
        });
    }

    // Standard ciphertext case
    let ciphertext = eql
        .body
        .ciphertext
        .ok_or_else(|| {
            Error::InvariantViolation("Missing ciphertext in EQL result".to_string())
        })?
        .to_mp_base85()
        .map_err(|err| Error::Base85(err.to_string()))?;

    Ok(Encrypted::Ciphertext {
        ciphertext,
        ore_index: eql.body.sem.ore_block_u64_8_256,
        match_index: eql.body.sem.bloom_filter,
        unique_index: eql.body.sem.hmac_256,
        identifier: ident.clone(),
        version: 2,
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
            let invalid_encrypted =
                json!({"k":"invalid","c":"3q2+7w==","i":{"t":"users","c":"email"},"v":2});
            assert!(!is_encrypted(Json(invalid_encrypted)));
        }
    }
}
