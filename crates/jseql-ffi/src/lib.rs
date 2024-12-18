use cipherstash_client::{
    config::{
        console_config::ConsoleConfig, cts_config::CtsConfig, zero_kms_config::ZeroKMSConfig,
    },
    credentials::service_credentials::ServiceCredentials,
    encryption::{Encrypted, Plaintext, PlaintextTarget, ReferencedPendingPipeline, ScopedCipher},
    schema::ColumnConfig,
    zerokms::EncryptedRecord,
};
use neon::prelude::*;
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Return a global tokio runtime or create one if it doesn't exist.
// Throws a JavaScript exception if the `Runtime` fails to create.
fn runtime<'a, C: Context<'a>>(cx: &mut C) -> NeonResult<&'static Runtime> {
    static RUNTIME: OnceCell<Runtime> = OnceCell::new();

    RUNTIME.get_or_try_init(|| Runtime::new().or_else(|err| cx.throw_error(err.to_string())))
}

#[derive(Clone)]
struct Client {
    cipher: Arc<ScopedZeroKMSNoRefresh>,
}

impl Finalize for Client {}

type ScopedZeroKMSNoRefresh = ScopedCipher<ServiceCredentials>;

fn new_client(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let rt = runtime(&mut cx)?;
    let channel = cx.channel();

    let (deferred, promise) = cx.promise();

    rt.spawn(async move {
        // TODO: don't unwrap
        let console_config = ConsoleConfig::builder().with_env().build().unwrap();

        // TODO: don't unwrap
        let cts_config = CtsConfig::builder().with_env().build().unwrap();

        let zerokms_config = ZeroKMSConfig::builder()
            .console_config(&console_config)
            .cts_config(&cts_config)
            .with_env()
            .build_with_client_key()
            // TODO: don't unwrap
            .unwrap();

        let zerokms = zerokms_config.create_client();

        let cipher = ScopedZeroKMSNoRefresh::init(Arc::new(zerokms), None)
            .await
            // TODO: don't unwrap
            .unwrap();

        let client = Client {
            cipher: Arc::new(cipher),
        };

        deferred.settle_with(&channel, move |mut cx| Ok(cx.boxed(client)));
    });

    Ok(promise)
}

fn encrypt(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let plaintext = cx.argument::<JsString>(0)?.value(&mut cx);
    let column_name = cx.argument::<JsString>(1)?.value(&mut cx);
    let client = (&**cx.argument::<JsBox<Client>>(2)?).clone();

    let rt = runtime(&mut cx)?;
    let channel = cx.channel();

    // Create a JavaScript promise and a `deferred` handle for resolving it.
    // It is important to be careful not to perform failable actions after
    // creating the promise to avoid an unhandled rejection.
    let (deferred, promise) = cx.promise();

    // Spawn an `async` task on the tokio runtime. Only Rust types that are
    // `Send` may be moved into this block. `Context` may not be passed and all
    // JavaScript values must first be converted to Rust types.
    //
    // This task will _not_ block the JavaScript main thread.
    rt.spawn(async move {
        let column_config = ColumnConfig::build(column_name);
        let mut pipeline = ReferencedPendingPipeline::new(client.cipher);
        let encryptable = PlaintextTarget::new(plaintext, column_config.clone(), None);

        pipeline
            .add_with_ref::<PlaintextTarget>(encryptable, 0)
            .unwrap();

        let mut source_encrypted = pipeline.encrypt().await.unwrap();

        let encrypted = source_encrypted.remove(0).unwrap();

        let ciphertext = match encrypted {
            Encrypted::Record(ciphertext, _terms) => ciphertext.to_mp_base85().unwrap(),
            _ => todo!(),
        };

        // Settle the promise from the result of a closure. JavaScript exceptions
        // will be converted to a Promise rejection.
        //
        // This closure will execute on the JavaScript main thread. It should be
        // limited to converting Rust types to JavaScript values. Expensive operations
        // should be performed outside of it.
        deferred.settle_with(&channel, move |mut cx| Ok(cx.string(ciphertext)));
    });

    Ok(promise)
}

fn decrypt(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let ciphertext = cx.argument::<JsString>(0)?.value(&mut cx);
    let client = (&**cx.argument::<JsBox<Client>>(1)?).clone();

    let rt = runtime(&mut cx)?;
    let channel = cx.channel();

    let (deferred, promise) = cx.promise();

    rt.spawn(async move {
        let encrypted_record = EncryptedRecord::from_mp_base85(&ciphertext).unwrap();
        let decrypted = client.cipher.decrypt([encrypted_record]).await.unwrap();
        let plaintext = Plaintext::from_slice(&decrypted[0][..]).unwrap();

        let plaintext = match plaintext {
            Plaintext::Utf8Str(Some(ref inner)) => inner.clone(),
            _ => todo!(),
        };

        deferred.settle_with(&channel, move |mut cx| Ok(cx.string(plaintext)));
    });

    Ok(promise)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("newClient", new_client)?;
    cx.export_function("encrypt", encrypt)?;
    cx.export_function("decrypt", decrypt)?;

    Ok(())
}
