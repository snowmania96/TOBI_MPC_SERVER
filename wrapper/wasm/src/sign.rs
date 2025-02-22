// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    cell::RefCell,
    ops::Deref,
    rc::Rc,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{SigningKey, VerifyingKey};

use wasm_bindgen::{prelude::*, throw_str, throw_val};
use wasm_bindgen_futures::JsFuture;

use js_sys::Promise;

use dkls23::{
    keygen,
    setup::{ProtocolParticipant, SETUP_MESSAGE_TAG},
    sign,
    sign::{PreSign, RecoveryId, Signature},
};

use simple_setup_msg as setup;

type DecodedSetup = setup::sign::DecodedSetup;
type ValidatedSetup = setup::sign::ValidatedSetup;

use crate::{
    abort::AbortGuard,
    keyshare::Keyshare,
    relay::{msg_relay_connect, MsgRelay},
    utils::set_panic_hook,
};

use super::*;

#[wasm_bindgen(typescript_custom_section)]
const SignValidatorType: &'static str = r#"
type SignValidator = (SignSetup) => Promise<Keyshare | boolean>;
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "SignValidator")]
    pub type SignValidator;
}

// We need small temporary storage for PreSignsture.
static PRE_SIGN: Mutex<Vec<PreSign>> = Mutex::new(Vec::new());

#[wasm_bindgen]
pub struct SignSetup {
    setup: Rc<RefCell<Option<DecodedSetup>>>,
}

#[wasm_bindgen]
impl SignSetup {
    #[wasm_bindgen]
    pub fn threshold(&self) -> u8 {
        self.setup.borrow_mut().as_ref().unwrap_throw().threshold()
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self, party: u32) -> Result<Uint8Array, JsError> {
        let vk = self
            .setup
            .borrow()
            .as_ref()
            .unwrap_throw()
            .party_verifying_key(party as usize)
            .map(Uint8Array::from)
            .ok_or_else(|| JsError::new("invalid party"))?;

        Ok(vk)
    }

    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> Uint8Array {
        let kid = self.setup.borrow().as_ref().unwrap_throw().key_id();

        Uint8Array::from(kid.as_slice())
    }

    #[wasm_bindgen(js_name = isPreSign)]
    pub fn is_pre_sign(&self) -> bool {
        self.setup.borrow().as_ref().unwrap_throw().is_pre_sign()
    }

    #[wasm_bindgen(js_name = message)]
    pub fn message(&self) -> Uint8Array {
        let msg = self.setup.borrow();

        Uint8Array::from(msg.as_ref().unwrap_throw().message())
    }

    #[wasm_bindgen(js_name = chainPath)]
    pub fn chain_path(&self) -> String {
        self.setup
            .borrow()
            .as_ref()
            .unwrap_throw()
            .chain_path()
            .to_string()
    }
}

fn sign_with_recid(sign: &Signature, recid: RecoveryId) -> Uint8Array {
    let mut bytes = [0u8; 64 + 1];
    let recid: u8 = recid.into();

    bytes[..64].copy_from_slice(&sign.to_bytes());
    bytes[64] = recid + 27;

    Uint8Array::from(bytes.as_slice())
}

async fn validate_setup<R: Relay>(
    msg_relay: &mut BufferedMsgRelay<R>,
    instance: InstanceId,
    setup_vk: &VerifyingKey,
    validate: &js_sys::Function,
) -> (DecodedSetup, Arc<keygen::Keyshare>) {
    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    let setup_msg = msg_relay.recv(&msg_id, 10).await.expect_throw("recv setup msg");

    let decoded_setup =
        DecodedSetup::decode(instance, setup_msg, setup_vk).expect_throw("decode setup message");

    let cell = Rc::new(RefCell::new(Some(decoded_setup)));

    let js_decoded_setup = From::<SignSetup>::from(SignSetup {
        setup: Rc::clone(&cell), // create second reference
    });

    let share = JsFuture::from(
        validate
            .call1(&JsValue::null(), &js_decoded_setup)
            .expect_throw("validator failed")
            .dyn_into::<Promise>()
            .expect_throw("validator should return Promise"),
    )
    .await;

    let share = match share {
        Err(err) => throw_val(err),
        Ok(v) if v.is_falsy() => throw_str("validation failed"),
        Ok(share) => keyshare::keyshareCast(share),
    };

    let decoded = cell.replace(None).unwrap_throw();

    (decoded, share.clone_inner())
}

pub fn parse_params(
    instance: &[u8],
    setup_vk: &[u8],
    signing_key: &[u8],
    seed: &[u8],
) -> Result<(InstanceId, VerifyingKey, Arc<SigningKey>, [u8; 32]), JsError> {
    let instance: [u8; 32] = instance.try_into().expect_throw("instance-id: invalid size");
    let instance = InstanceId::from(instance);

    let setup_vk: [u8; 32] = setup_vk.try_into()?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)?;
    let signing_key = SigningKey::from_bytes(signing_key.try_into()?);
    let seed = seed.try_into().expect_throw("invalid seed size");

    Ok((instance, setup_vk, Arc::new(signing_key), seed))
}

/// Initialize execution of the DSG protocol.
///
/// - connect to the message relay
/// - send the setup message to all other parties
/// - start execution of the protocol for this participant
///
#[wasm_bindgen]
pub async fn init_dsg(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    keyshare: &Keyshare,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();

    let (instance, setup_vk, signing_key, seed) = parse_params(instance, setup_vk, signing_key, seed)?;

    let mut abort = AbortGuard::new();

    let ws = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws);

    let decoded =
        DecodedSetup::decode(instance, setup_msg, &setup_vk).expect_throw("Setup message decode error");

    let setup = ValidatedSetup::from_decoded(decoded, signing_key, keyshare.clone_inner()).unwrap();

    abort.deadline(setup.ttl().as_millis() as u32);

    let (sign, recid) = sign::run(setup, seed, msg_relay).await?;

    Ok(sign_with_recid(&sign, recid))
}

fn put_pre_sign(pre: PreSign) {
    PRE_SIGN.lock().unwrap().push(pre);
}

fn get_pre_sign(pre_id: &[u8]) -> Option<PreSign> {
    let mut lock = PRE_SIGN.lock().unwrap();
    let idx = lock
        .iter()
        .position(|pre: &PreSign| pre.final_session_id == pre_id)?;

    Some(lock.swap_remove(idx))
}

#[wasm_bindgen]
pub async fn init_pre(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    keyshare: &Keyshare,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();

    let (instance, setup_vk, signing_key, seed) = parse_params(instance, setup_vk, signing_key, seed)?;

    let mut abort = AbortGuard::new();

    let ws = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws);

    let decoded = setup::presign::DecodedSetup::decode(instance, setup_msg, &setup_vk)
        .expect_throw("Setup message decode error");

    let setup =
        setup::presign::ValidatedSetup::from_decoded(decoded, signing_key, keyshare.clone_inner()).unwrap();

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let pre_sign = sign::pre_signature(setup, seed, msg_relay).await?;
    let pre_id = pre_sign.final_session_id;

    put_pre_sign(pre_sign);

    Ok(Uint8Array::from(pre_id.as_slice()))
}

#[wasm_bindgen]
pub async fn init_finish(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();

    let (instance, setup_vk, signing_key, _seed) = parse_params(instance, setup_vk, signing_key, &[0; 32])?;

    let decoded = setup::finish::DecodedSetup::decode(instance, setup_msg, &setup_vk)
        .expect_throw("Setup message decode error");

    let pre_sign = get_pre_sign(&decoded.session_id()).expect_throw("Missing PreSignature");

    let setup = setup::finish::ValidatedSetup::from_decoded(decoded, signing_key, pre_sign).unwrap();

    let mut abort = AbortGuard::new();

    let ws = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws);

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let (sign, recid) = sign::finish(setup, msg_relay).await?;

    Ok(sign_with_recid(&sign, recid))
}

/// Join execution of DSG protocol.
///
/// - connect to the message relay
/// - recevice the setup message
/// -
///
#[wasm_bindgen]
pub async fn join_dsg(
    instance: &[u8],
    setup_vk: &[u8],
    signing_key: &[u8],
    endpoint: &str,
    seed: &[u8],
    validate: SignValidator,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();

    let (instance, setup_vk, signing_key, seed) = parse_params(instance, setup_vk, signing_key, seed)?;

    let mut abort = AbortGuard::new();

    let ws_conn = msg_relay_connect(endpoint, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let validate = validate.dyn_ref().expect_throw("expect validation function");

    let (decoded, share) = validate_setup(&mut msg_relay, instance, &setup_vk, validate).await;

    let setup = ValidatedSetup::from_decoded(decoded, signing_key, share).unwrap_throw();

    abort.deadline(setup.ttl().as_millis() as u32);

    let (sign, recid) = sign::run(setup, seed, msg_relay).await.unwrap_throw();

    Ok(sign_with_recid(&sign, recid))
}

#[wasm_bindgen]
pub async fn join_dsg_local(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    endpoint: &str,
    seed: &[u8],
    share: &Keyshare,
) -> Result<Uint8Array, JsError> {
    set_panic_hook();

    let (instance, setup_vk, signing_key, seed) = parse_params(instance, setup_vk, signing_key, seed)?;

    let mut abort = AbortGuard::new();

    let ws_conn = msg_relay_connect(endpoint, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    let decoded =
        DecodedSetup::decode(instance, setup_msg, &setup_vk).expect_throw("Setup message decode error");
    let setup = ValidatedSetup::from_decoded(decoded, signing_key, share.deref().clone()).unwrap_throw();

    abort.deadline(setup.ttl().as_millis() as u32);

    let (sign, recid) = sign::run(setup, seed, msg_relay).await.unwrap_throw();

    Ok(sign_with_recid(&sign, recid))
}
