use std::{ops::Deref, sync::Arc};

use ed25519_dalek::Digest;
use js_sys::Uint8Array;
use k256::{elliptic_curve::group::GroupEncoding, sha2};
use wasm_bindgen::prelude::*;

use crate::EdKeyshareInner;

#[wasm_bindgen(module = "/js/keyshare-cast.js")]
extern "C" {
    #[wasm_bindgen(js_name = keyshareCast)]
    pub fn keyshareCast(value: JsValue) -> EdKeyshare;
}

#[wasm_bindgen]
pub struct EdKeyshare {
    share: Arc<EdKeyshareInner>,
}

impl EdKeyshare {
    pub fn new(share: EdKeyshareInner) -> Self {
        Self {
            share: Arc::new(share),
        }
    }

    pub fn clone_inner(&self) -> Arc<EdKeyshareInner> {
        self.share.clone()
    }
}

impl Deref for EdKeyshare {
    type Target = Arc<EdKeyshareInner>;

    fn deref(&self) -> &Self::Target {
        &self.share
    }
}

#[wasm_bindgen]
impl EdKeyshare {
    /// Return public key as compressed encoding of the public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.share.public_key().compress().to_bytes().as_slice())
    }

    /// Return key Id.
    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> Uint8Array {
        Uint8Array::from(self.share.key_id.as_slice())
    }

    /// Serialize the keyshare into array of bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Uint8Array {
        let bytes = bincode::serde::encode_to_vec(self.share.as_ref(), bincode::config::legacy())
            .expect_throw("serialize error");
        Uint8Array::from(bytes.as_slice())
    }

    /// Deserialize keyshare from the array of bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Uint8Array) -> Result<EdKeyshare, JsValue> {
        let bytes: Vec<u8> = bytes.to_vec();
        let (share, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
            .expect_throw("deserialize error");

        Ok(EdKeyshare {
            share: Arc::new(share),
        })
    }

    /// Deserialize legacy key share
    #[wasm_bindgen(js_name = fromLegacyBytes)]
    pub fn from_legacy_bytes(bytes: Vec<u8>) -> Result<EdKeyshare, JsError> {
        let share = legacy_keyshare::schnorr::load_schnorr_keyshare(&bytes)
            .ok_or_else(|| JsError::new("can't decode legacy EdDSA key share"))?;
        let key_id = sha2::Sha256::digest(share.public_key.0.to_bytes()).into();
        let new_share = legacy_keyshare::schnorr::NewKeyshare::from_legacy(share, key_id);
        let bytes = bincode::serde::encode_to_vec(&new_share, bincode::config::legacy())
            .expect_throw("serialize error");

        let (share, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
            .expect_throw("deserialize error");

        Ok(EdKeyshare {
            share: Arc::new(share),
        })
    }
}
