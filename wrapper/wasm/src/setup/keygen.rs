// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::mem;

use js_sys::Uint8Array;
use wasm_bindgen::{prelude::*, throw_str};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{keyshare::Keyshare, log};
use dkls23::setup;
use simple_setup_msg::{find_tags, keygen, tags};
use sl_mpc_mate::message::*;

#[wasm_bindgen]
pub struct KeygenSetupBuilder {
    builder: keygen::SetupBuilder,
}

#[wasm_bindgen]
impl KeygenSetupBuilder {
    #[wasm_bindgen(constructor)]
    pub fn ctor() -> Self {
        Self {
            builder: keygen::SetupBuilder::new(),
        }
    }

    /// Add party with verifying key `vk` and rank `rank`.
    #[wasm_bindgen(js_name = "addParty")]
    pub fn add_party(&mut self, vk: &[u8], rank: Option<u8>) {
        let vk = vk.try_into().expect_throw("invalid size of verifying key");
        let vk = VerifyingKey::from_bytes(&vk).expect_throw("invalid verifying key");

        self.builder = core::mem::take(&mut self.builder).add_party(rank.unwrap_or(0), &vk);
    }

    #[wasm_bindgen(js_name = "addTag")]
    pub fn add_tag(&mut self, tag: u16, value: &[u8]) {
        if value.is_empty() {
            throw_str("empty value");
        }

        self.builder = mem::take(&mut self.builder).add_tag(tag, Some(value));
    }

    #[wasm_bindgen(js_name = "refresh")]
    pub fn refresh(&mut self, share: &Keyshare) {
        self.add_tag(tags::KEY_ID, &share.key_id);
    }

    #[wasm_bindgen]
    pub fn build(self, instance: &[u8], ttl: u32, t: u8, sk: &[u8]) -> Vec<u8> {
        let instance: [u8; 32] = instance.try_into().expect_throw("instance-id: invalid size");
        let instance = InstanceId::from(instance);

        let sk = sk.try_into().expect_throw("signing key: invalid size");
        let sk = SigningKey::from_bytes(&sk);
        let vk = sk.verifying_key();

        let msg_id = MsgId::new(&instance, vk.as_bytes(), None, setup::SETUP_MESSAGE_TAG);

        self.builder
            .build(&msg_id, ttl, t, &sk)
            .expect_throw("keygen setup: invalid params")
    }
}

/// Extract key ID from encoded setup message.
#[wasm_bindgen(js_name = setupMsgDecodeKeyId)]
pub fn decode_key_id(setup: &[u8]) -> Option<Uint8Array> {
    setup
        .get(MESSAGE_HEADER_SIZE..)
        .and_then(|setup| find_tags(setup, tags::KEY_ID).next())
        .map(Uint8Array::from)
}
