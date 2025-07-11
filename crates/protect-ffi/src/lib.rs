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

#[derive(Debug, Deserialize, Serialize, Default)]
struct ClientOpts {
    workspace_crn: Option<Crn>,
    access_key: Option<String>,
    client_id: Option<String>,
    client_key: Option<String>,
}

// Option structs for the new export macro-based functions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct NewClientOptions {
    encrypt_config: String,
    client_opts: Option<ClientOpts>,
}

#[derive(Deserialize)]
struct EncryptOptions {
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<Vec<zerokms::Context>>,
    service_token: Option<ServiceToken>,
}

#[derive(Deserialize)]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    service_token: Option<ServiceToken>,
}

#[derive(Debug, Deserialize)]
struct PlaintextPayload {
    plaintext: String,
    column: String,
    table: String,
    lock_context: Option<Vec<zerokms::Context>>,
}

#[derive(Deserialize)]
struct DecryptOptions {
    ciphertext: String,
    lock_context: Option<Vec<zerokms::Context>>,
    service_token: Option<ServiceToken>,
}

#[derive(Deserialize)]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    service_token: Option<ServiceToken>,
}

#[derive(Debug, Deserialize)]
struct BulkDecryptPayload {
    ciphertext: String,
    lock_context: Option<Vec<zerokms::Context>>,
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
    
    let column_config = client.encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let mut plaintext_target = PlaintextTarget::new(opts.plaintext, column_config.clone());
    plaintext_target.context = opts.lock_context.unwrap_or_default();

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
        
        let column_config = client.encrypt_config
            .get(&ident)
            .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

        let mut plaintext_target = PlaintextTarget::new(payload.plaintext, column_config.clone());
        plaintext_target.context = payload.lock_context.unwrap_or_default();
        
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
    let lock_context = opts.lock_context.unwrap_or_default();
    let plaintext = decrypt_inner(client, opts.ciphertext, lock_context, opts.service_token).await?;
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

fn decrypt_bulk(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let client = (**cx.argument::<JsBox<Client>>(0)?).clone();
    let ciphertexts = ciphertexts_from_js_array(cx.argument::<JsArray>(1)?, &mut cx)?;
    let service_token = service_token_from_js_value(cx.argument_opt(2), &mut cx)?;

    let rt = runtime(&mut cx)?;
    let channel = cx.channel();

    let (deferred, promise) = cx.promise();

    rt.spawn(async move {
        let plaintexts_result = decrypt_bulk_inner(client, ciphertexts, service_token).await;

        deferred.settle_with(&channel, move |mut cx| {
            let plaintexts = plaintexts_result.or_else(|err| cx.throw_error(err.to_string()))?;
            js_array_from_string_vec(plaintexts, &mut cx)
        });
    });

    Ok(promise)
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

fn decrypt_bulk_fallible(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let client = (**cx.argument::<JsBox<Client>>(0)?).clone();
    let ciphertexts = ciphertexts_from_js_array(cx.argument::<JsArray>(1)?, &mut cx)?;
    let service_token = service_token_from_js_value(cx.argument_opt(2), &mut cx)?;

    let rt = runtime(&mut cx)?;
    let channel = cx.channel();

    let (deferred, promise) = cx.promise();

    rt.spawn(async move {
        let plaintexts_result =
            decrypt_bulk_fallible_inner(client, ciphertexts, service_token).await;

        deferred.settle_with(&channel, move |mut cx| {
            let plaintexts = plaintexts_result.or_else(|err| cx.throw_error(err.to_string()))?;
            js_array_decrypt_results_from_string_vec(plaintexts, &mut cx)
        });
    });

    Ok(promise)
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

fn encryption_context_from_js_value(
    value: Option<Handle<JsValue>>,
    cx: &mut FunctionContext,
) -> NeonResult<Vec<zerokms::Context>> {
    let mut encryption_context: Vec<zerokms::Context> = Vec::new();

    if let Some(lock_context) = value {
        let lock_context: Handle<JsObject> = lock_context.downcast_or_throw(cx)?;

        let identity_claim: Option<Handle<JsArray>> = lock_context.get_opt(cx, "identityClaim")?;

        if let Some(identity_claim) = identity_claim {
            let identity_claims: Vec<Handle<JsValue>> = identity_claim.to_vec(cx)?;

            for claim in identity_claims {
                let claim = claim
                    .downcast_or_throw::<JsString, FunctionContext>(cx)?
                    .value(cx);

                encryption_context.push(zerokms::Context::new_identity_claim(&claim));
            }
        }
    }

    Ok(encryption_context)
}

fn service_token_from_js_value(
    value: Option<Handle<JsValue>>,
    cx: &mut FunctionContext,
) -> NeonResult<Option<ServiceToken>> {
    match value {
        Some(service_token) if is_defined(service_token, cx) => {
            let service_token: Handle<JsObject> = service_token.downcast_or_throw(cx)?;

            let token = service_token
                .get::<JsString, _, _>(cx, "accessToken")?
                .value(cx);

            let expiry = service_token.get::<JsNumber, _, _>(cx, "expiry")?.value(cx);

            Ok(Some(ServiceToken::new(token, expiry as u64)))
        }
        _ => Ok(None),
    }
}

fn plaintext_targets_from_js_array(
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
    js_array: Handle<'_, JsArray>,
    cx: &mut FunctionContext,
) -> NeonResult<Vec<(PlaintextTarget, Identifier)>> {
    let js_values: Vec<Handle<JsValue>> = js_array.to_vec(cx)?;
    let mut plaintext_targets: Vec<(PlaintextTarget, Identifier)> =
        Vec::with_capacity(js_values.len());

    for js_value in js_values {
        let obj: Handle<JsObject> = js_value.downcast_or_throw(cx)?;
        let (plaintext_target, ident) = plaintext_target_from_js_object(obj, &encrypt_config, cx)?;

        plaintext_targets.push((plaintext_target, ident));
    }

    Ok(plaintext_targets)
}

fn plaintext_target_from_js_object(
    value: Handle<'_, JsObject>,
    encrypt_config: &Arc<HashMap<Identifier, ColumnConfig>>,
    cx: &mut FunctionContext,
) -> NeonResult<(PlaintextTarget, Identifier)> {
    let plaintext = value.get::<JsString, _, _>(cx, "plaintext")?.value(cx);

    let column = value.get::<JsString, _, _>(cx, "column")?.value(cx);
    let table = value.get::<JsString, _, _>(cx, "table")?.value(cx);

    let lock_context = value.get_opt::<JsValue, _, _>(cx, "lockContext")?;
    let lock_context = encryption_context_from_js_value(lock_context, cx)?;

    let ident = Identifier::new(table, column);

    let column_config = encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))
        .or_else(|err| cx.throw_error(err.to_string()))?;

    let mut plaintext_target = PlaintextTarget::new(plaintext, column_config.clone());
    plaintext_target.context = lock_context;

    Ok((plaintext_target, ident))
}

fn ciphertexts_from_js_array(
    js_array: Handle<'_, JsArray>,
    cx: &mut FunctionContext,
) -> NeonResult<Vec<(String, Vec<zerokms::Context>)>> {
    let js_values: Vec<Handle<JsValue>> = js_array.to_vec(cx)?;
    let mut ciphertexts: Vec<(String, Vec<zerokms::Context>)> = Vec::with_capacity(js_values.len());

    for js_value in js_values {
        let obj: Handle<JsObject> = js_value.downcast_or_throw(cx)?;

        let ciphertext = obj.get::<JsString, _, _>(cx, "ciphertext")?.value(cx);

        let lock_context = obj.get_opt::<JsValue, _, _>(cx, "lockContext")?;
        let lock_context = encryption_context_from_js_value(lock_context, cx)?;

        ciphertexts.push((ciphertext, lock_context));
    }

    Ok(ciphertexts)
}

fn js_array_decrypt_results_from_string_vec<'a, C: Context<'a>>(
    vec: Vec<Result<String, Error>>,
    cx: &mut C,
) -> NeonResult<Handle<'a, JsArray>> {
    let js_array = JsArray::new(cx, vec.len());

    for (i, value) in vec.iter().enumerate() {
        let obj: Handle<JsObject> = cx.empty_object();

        match value {
            Ok(decrypted) => {
                let js_string = cx.string(decrypted);
                obj.set(cx, "data", js_string)?;
            }
            Err(e) => {
                let message = cx.string(e.to_string());
                obj.set(cx, "error", message)?;
            }
        }

        js_array.set(cx, i as u32, obj)?;
    }

    Ok(js_array)
}

fn js_array_from_string_vec<'a, C: Context<'a>>(
    vec: Vec<String>,
    cx: &mut C,
) -> NeonResult<Handle<'a, JsArray>> {
    let js_array = JsArray::new(cx, vec.len());

    for (i, value) in vec.iter().enumerate() {
        let js_string = cx.string(value);
        js_array.set(cx, i as u32, js_string)?;
    }

    Ok(js_array)
}

fn js_array_from_u16_vec<'a, C: Context<'a>>(
    vec: Vec<u16>,
    cx: &mut C,
) -> NeonResult<Handle<'a, JsArray>> {
    let js_array = JsArray::new(cx, vec.len());

    for (i, value) in vec.iter().enumerate() {
        let js_number = cx.number(*value);
        js_array.set(cx, i as u32, js_number)?;
    }

    Ok(js_array)
}

fn js_array_from_eql_encrypted_vec<'a, C: Context<'a>>(
    vec: Vec<Encrypted>,
    cx: &mut C,
) -> NeonResult<Handle<'a, JsArray>> {
    let js_array = JsArray::new(cx, vec.len());

    for (i, value) in vec.into_iter().enumerate() {
        let js_obj = eql_encrypted_to_js(value, cx)?;
        js_array.set(cx, i as u32, js_obj)?;
    }

    Ok(js_array)
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

fn eql_encrypted_to_js<'cx, C: Context<'cx>>(
    encrypted: Encrypted,
    cx: &mut C,
) -> NeonResult<Handle<'cx, JsObject>> {
    let obj: Handle<JsObject> = cx.empty_object();

    let Encrypted::Ciphertext {
        ciphertext,
        ore_index,
        match_index,
        unique_index,
        identifier,
        version,
    } = encrypted
    else {
        return cx
            .throw_error(Error::Unimplemented("encrypted JSON columns".to_string()).to_string());
    };

    let k = cx.string("ct");
    obj.set(cx, "k", k)?;

    let c = cx.string(ciphertext);
    obj.set(cx, "c", c)?;

    if let Some(ore_index) = ore_index {
        let o = js_array_from_string_vec(ore_index, cx)?;
        obj.set(cx, "ob", o)?;
    } else {
        let o = cx.null();
        obj.set(cx, "ob", o)?;
    }

    if let Some(match_index) = match_index {
        let m = js_array_from_u16_vec(match_index, cx)?;
        obj.set(cx, "bf", m)?;
    } else {
        let m = cx.null();
        obj.set(cx, "bf", m)?;
    }

    if let Some(unique_index) = unique_index {
        let u = cx.string(unique_index);
        obj.set(cx, "hm", u)?;
    } else {
        let u = cx.null();
        obj.set(cx, "hm", u)?;
    }

    let i = cx.empty_object();

    let col = cx.string(identifier.column);
    i.set(cx, "c", col)?;

    let t = cx.string(identifier.table);
    i.set(cx, "t", t)?;

    obj.set(cx, "i", i)?;

    let v = cx.number(version);
    obj.set(cx, "v", v)?;

    Ok(obj)
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

fn is_defined(js_value: Handle<'_, JsValue>, cx: &mut FunctionContext) -> bool {
    !js_value.is_a::<JsUndefined, _>(cx)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let runtime = runtime(&mut cx)?;
    let _ = neon::set_global_executor(&mut cx, runtime);

    neon::registered().export(&mut cx)?;

    cx.export_function("decryptBulk", decrypt_bulk)?;
    cx.export_function("decryptBulkFallible", decrypt_bulk_fallible)?;

    Ok(())
}
