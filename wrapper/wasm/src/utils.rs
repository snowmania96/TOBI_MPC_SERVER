// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use js_sys::Uint8Array;
use rand::Rng;
use wasm_bindgen::JsError;

use crate::wasm_bindgen;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    // tracing_wasm::set_as_global_default();
}

#[wasm_bindgen(js_name = genPartyKey)]
pub fn gen_party_key() -> Result<js_sys::Uint8Array, JsError> {
    let key = gen_party_key_inner()?;
    Ok(key)
}

pub fn gen_party_key_inner() -> Result<Uint8Array, JsError> {
    let mut rng = rand::thread_rng();
    let secret: &[u8; 32] = &rng.gen();

    Ok(Uint8Array::from(secret.as_ref()))
}
