// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use core::mem;

use wasm_bindgen::{prelude::*, throw_str};

use dkls23::setup;
use ed25519_dalek::{SigningKey, VerifyingKey};
use simple_setup_msg::finish;
use sl_mpc_mate::message::*;

#[wasm_bindgen]
pub struct FinishSetupBuilder {
    builder: finish::SetupBuilder,
}

#[wasm_bindgen]
impl FinishSetupBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(session_id: &[u8]) -> Self {
        let session_id =
            session_id.try_into().expect_throw("invalid session-id");
        Self {
            builder: finish::SetupBuilder::new(session_id),
        }
    }

    /// Add party with verifying key `vk` and rank `rank`.
    #[wasm_bindgen(js_name = "addParty")]
    pub fn add_party(&mut self, vk: &[u8]) {
        let vk = vk.try_into().expect_throw("invalid size of verifying key");
        let vk = VerifyingKey::from_bytes(&vk)
            .expect_throw("invalid verifying key");

        self.builder = mem::take(&mut self.builder).add_party(Some(&vk));
    }

    #[wasm_bindgen(js_name = "addTag")]
    pub fn add_tag(&mut self, tag: u16, value: &[u8]) {
        if value.is_empty() {
            throw_str("empty value");
        }

        self.builder = mem::take(&mut self.builder).add_tag(tag, Some(value));
    }

    #[wasm_bindgen(js_name = "withHash")]
    pub fn with_hash(&mut self, value: &[u8]) {
        let hash: [u8; 32] =
            value.try_into().expect_throw("invalid hash size");

        self.builder = mem::take(&mut self.builder).with_hash(hash);
    }

    #[wasm_bindgen(js_name = "withHashSha256")]
    pub fn with_sha256(&mut self, value: &[u8]) {
        self.builder = mem::take(&mut self.builder).with_sha256(value);
    }

    #[wasm_bindgen(js_name = "withHashSha256d")]
    pub fn with_sha256d(&mut self, value: &[u8]) {
        self.builder = mem::take(&mut self.builder).with_sha256d(value);
    }

    #[wasm_bindgen]
    pub fn build(self, instance: &[u8], ttl: u32, sk: &[u8]) -> Vec<u8> {
        let instance: [u8; 32] = instance
            .try_into()
            .expect_throw("instance-id: invalid size");
        let instance = InstanceId::from(instance);

        let sk = sk.try_into().expect_throw("signing key: invalid size");
        let sk = SigningKey::from_bytes(&sk);
        let vk = sk.verifying_key();

        let msg_id = MsgId::new(
            &instance,
            vk.as_bytes(),
            None,
            setup::SETUP_MESSAGE_TAG,
        );

        self.builder
            .build(&msg_id, ttl, &sk)
            .expect_throw("keygen setup: invalid params")
    }
}
