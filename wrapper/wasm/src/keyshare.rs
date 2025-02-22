use std::{ops::Deref, sync::Arc};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use k256::elliptic_curve::group::GroupEncoding;

use dkls23::keygen;

#[wasm_bindgen(module = "/js/keyshare-cast.js")]
extern "C" {
    #[wasm_bindgen(js_name = keyshareCast)]
    pub fn keyshareCast(value: JsValue) -> Keyshare;
}

#[wasm_bindgen]
pub struct Keyshare {
    share: Arc<keygen::Keyshare>,
}

impl Keyshare {
    pub fn new(share: keygen::Keyshare) -> Self {
        Self {
            share: Arc::new(share),
        }
    }

    pub fn clone_inner(&self) -> Arc<keygen::Keyshare> {
        self.share.clone()
    }
}

impl Deref for Keyshare {
    type Target = Arc<keygen::Keyshare>;

    fn deref(&self) -> &Self::Target {
        &self.share
    }
}

#[wasm_bindgen]
impl Keyshare {
    /// Return public key as compressed encoding of the public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.share.public_key().to_affine().to_bytes().as_slice())
    }

    /// Return key Id.
    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> Uint8Array {
        Uint8Array::from(self.share.key_id.as_slice())
    }

    /// Serialize the keyshare into array of bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.share.as_slice())
    }

    /// Deserialize keyshare from the array of bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Uint8Array) -> Result<Keyshare, JsValue> {
        let bytes: Vec<u8> = bytes.to_vec();
        let share =
            keygen::Keyshare::from_vec(bytes).map_err(|_| JsValue::from_str("Keyshare decode error"))?;

        Ok(Keyshare {
            share: Arc::new(share),
        })
    }
}
