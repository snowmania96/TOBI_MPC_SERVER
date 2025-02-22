use std::{ops::Deref, sync::Arc};

use dkls23::keygen::key_refresh::KeyshareForRefresh;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use k256::{elliptic_curve::group::GroupEncoding, ProjectivePoint};

use legacy_keyshare::LegacyKeyshare as LegacyInner;

#[wasm_bindgen(module = "/js/keyshare-cast.js")]
extern "C" {
    #[wasm_bindgen(js_name = keyshareCast)]
    pub fn keyshareCast(value: JsValue) -> LegacyKeyshare;
}

#[wasm_bindgen]
pub struct LegacyKeyshare {
    share: Arc<LegacyInner>,
}

impl LegacyKeyshare {
    pub fn new(share: LegacyInner) -> Self {
        Self {
            share: Arc::new(share),
        }
    }

    pub fn clone_inner(&self) -> Arc<LegacyInner> {
        self.share.clone()
    }
}

impl Deref for LegacyKeyshare {
    type Target = Arc<LegacyInner>;

    fn deref(&self) -> &Self::Target {
        &self.share
    }
}

#[wasm_bindgen]
impl LegacyKeyshare {
    /// Return public key as compressed encoding of the public key.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(self.share.public_key.to_affine().to_bytes().as_slice())
    }

    /// Serialize the keyshare into array of bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Uint8Array {
        let bytes = bincode::encode_to_vec(&self.share, bincode::config::standard()).unwrap_throw();
        Uint8Array::from(bytes.as_slice())
    }

    /// Deserialize keyshare from the array of bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Uint8Array) -> Result<LegacyKeyshare, JsValue> {
        let bytes: Vec<u8> = bytes.to_vec();

        let (share, _) = bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap_throw();
        Ok(LegacyKeyshare {
            share: Arc::new(share),
        })
    }
}

// #[wasm_bindgen(js_name = startRecoveryForLost)]
// pub fn start_recovery_for_lost(
//     t: u8,
//     public_key: Uint8Array,
//     party_id: u8,
// ) -> Result<KeyshareForRefreshData, JsValue> {
//     let public_key = public_key.to_vec();
//     let opt = ProjectivePoint::from_bytes(public_key.as_slice().into());
//     if opt.is_none().into() {
//         return Err(JsValue::from_str("Invalid public key"));
//     }
//     KeyshareForRefresh::from_lost_keyshare(rank_list, threshold, public_key, lost_party_ids, party_id)
//
//     Ok(KeyshareForRefreshData { data: data.into() })
// }

#[wasm_bindgen]
pub struct KeyshareForRefreshData {
    pub(crate) data: Arc<KeyshareForRefresh>,
}

impl Deref for KeyshareForRefreshData {
    type Target = Arc<KeyshareForRefresh>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
