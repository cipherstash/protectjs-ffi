use neon::prelude::*;

fn create_eql_payload(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let value = cx.argument::<JsString>(0)?.value(&mut cx);
    let table: Handle<JsString> = cx.argument(1)?;
    let column: Handle<JsString> = cx.argument(2)?;

    let callback = cx.argument::<JsFunction>(3)?.root(&mut cx);
    let channel = cx.channel();

    println!("value: {:?}", value);
    println!("table: {:?}", table);
    println!("column: {:?}", column);

    std::thread::spawn(move || {
        // Do the heavy lifting inside the background thread.
        do_encrypt(value, callback, channel);
    });

    Ok(cx.undefined())
}

fn do_encrypt<'a>(value: String, callback: Root<JsFunction>, channel: Channel) {
    // TODO: Do the actual encryption and creation of the Eql Encrypted payload here
    // uppercase is not a very strong cipher :)
    let result = value.to_uppercase();

    // Send the result back to the main thread.
    channel.send(move |mut cx| {
        let this = cx.undefined();

        let callback = callback.into_inner(&mut cx);
        let result = cx.string(result);
        callback.call(&mut cx, this, vec![result.upcast::<JsValue>()])?;

        Ok(())
    });
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("createEqlPayload", create_eql_payload)?;
    Ok(())
}
