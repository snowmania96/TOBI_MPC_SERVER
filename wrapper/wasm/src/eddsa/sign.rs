use std::rc::Rc;
use std::sync::Arc;
use std::{cell::RefCell, ops::Deref};

use ed25519_dalek::{SigningKey, VerifyingKey};

use js_sys::{Promise, Uint8Array};
use keyshare::{keyshareCast, EdKeyshare};
use schnorr_relay::{multi_party_schnorr::curve25519_dalek::EdwardsPoint, setup::keygen::KeygenSetupMsg};
use sl_mpc_mate::coord::BufferedMsgRelay;
use wasm_bindgen::{prelude::*, throw_str, throw_val};
use wasm_bindgen_futures::JsFuture;

use dkls23::{
    keygen::{self, key_refresh::KeyshareForRefresh},
    setup::{ProtocolParticipant, SETUP_MESSAGE_TAG},
    InstanceId,
};
use simple_setup_msg::tags;

type DecodedSetup = schnorr_relay::setup::sign::DecodedSetup;
type ValidatedSetup = schnorr_relay::setup::sign::SignSetupMsg<EdwardsPoint>;

use crate::{
    abort::AbortGuard,
    keyshare::Keyshare,
    relay::{msg_relay_connect, MsgRelay},
    sign::parse_params,
    utils::set_panic_hook,
};

use super::*;

/// Initialize execution of the DSG protocol.
///
/// - connect to the message relay
/// - send the setup message to all other parties
/// - start execution of the protocol for this participant
///
#[wasm_bindgen]
pub async fn init_eddsa_dsg(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    keyshare: &EdKeyshare,
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

    let sign = schnorr_relay::dsg::eddsa::run(setup, seed, msg_relay).await?;

    Ok(Uint8Array::from(sign.to_bytes().as_ref()))
}

#[wasm_bindgen]
pub async fn join_eddsa_dsg_local(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    endpoint: &str,
    seed: &[u8],
    share: &EdKeyshare,
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

    let sign = schnorr_relay::dsg::eddsa::run(setup, seed, msg_relay)
        .await
        .unwrap_throw();

    Ok(Uint8Array::from(sign.to_bytes().as_ref()))
}
