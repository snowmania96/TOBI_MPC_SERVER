use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};

use js_sys::Promise;
use keyshare::{keyshareCast, EdKeyshare};
use schnorr_relay::setup::keygen::KeygenSetupMsg;
use sl_mpc_mate::coord::BufferedMsgRelay;
use wasm_bindgen::{prelude::*, throw_str, throw_val};
use wasm_bindgen_futures::JsFuture;

use dkls23::{
    keygen::{self, key_refresh::KeyshareForRefresh},
    setup::{ProtocolParticipant, SETUP_MESSAGE_TAG},
    InstanceId,
};
use simple_setup_msg::tags;

type DecodedSetup = simple_setup_msg::keygen::DecodedSetup;
type ValidatedSetup = simple_setup_msg::keygen::ValidatedSetup;

use crate::{
    abort::AbortGuard,
    keyshare::Keyshare,
    relay::{msg_relay_connect, MsgRelay},
    utils::set_panic_hook,
};

use super::*;

/// Initialize execution of DKG protocol.
///
/// Given instance-id and encoded setup message, connect to of message relay
/// client, publish the setup message and begin excution of the protocol.
///
/// If passed setup message contains KEY_ID then pass parameter must
/// appropriate key share.
///
/// Key share is consumed by the call if passed.
///
/// # Arguments
///
/// * `instance`    - Instance ID
/// * `setup_msg`   - Encodeded setup message
/// * `setup_vk`    - Verifying key for the setup message
/// * `signing_key` - Signing key for this participant
/// * `msg_relay`   - URL of message relay
/// * `seed`        - seed for CPRNG
/// * `old_share`   - optional key share to initialize key refresh.
///
/// # Returns
///
/// Keyshare object
///
#[wasm_bindgen]
pub async fn init_eddsa_dkg(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    old_share: Option<EdKeyshare>,
) -> Result<EdKeyshare, JsError> {
    set_panic_hook();

    let instance: [u8; 32] = instance.try_into().expect_throw("instance-id: invalid size");
    let instance = InstanceId::from(instance);

    let setup_vk: [u8; 32] = setup_vk.try_into()?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)?;
    let signing_key = Arc::new(SigningKey::from_bytes(signing_key.try_into()?));
    let seed = seed.try_into().expect_throw("invalid seed size");

    let decoded =
        DecodedSetup::decode(instance, setup_msg, &setup_vk).expect_throw("Setup message decode error");

    // look up an optoinal KEY_ID
    let setup_key_id = decoded.tags().find_map(|(t, v)| (t == tags::KEY_ID).then_some(v));

    let share_key_id = old_share.as_ref().map(|v| v.key_id.as_slice());

    // make sure we use the right key share
    if setup_key_id != share_key_id {
        throw_str("inconsistent key-ind setup-msg and key share ");
    }

    let setup = KeygenSetupMsg::from_decoded(decoded, signing_key).expect_throw("Validation setup error");

    let mut abort = AbortGuard::new();

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);

    let keyshare = schnorr_relay::dkg::run(setup, seed, msg_relay, None).await?;

    Ok(EdKeyshare::new(keyshare))
}

#[wasm_bindgen]
pub async fn join_eddsa_dkg_local(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
) -> Result<EdKeyshare, JsError> {
    set_panic_hook();

    let mut abort = AbortGuard::new();

    let instance: [u8; 32] = instance.try_into().expect_throw("instance-id: invalid size");
    let instance = InstanceId::from(instance);

    let setup_vk: [u8; 32] = setup_vk.try_into()?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)?;

    let signing_key = SigningKey::from_bytes(signing_key.try_into()?);
    let seed = seed.try_into().expect_throw("invalid seed size");

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    let decoded =
        DecodedSetup::decode(instance, setup_msg, &setup_vk).expect_throw("Setup message decode error");

    let setup =
        KeygenSetupMsg::from_decoded(decoded, Arc::new(signing_key)).expect_throw("Validation setup error");

    abort.deadline(setup.message_ttl().as_millis() as u32);
    let keyshare = schnorr_relay::dkg::run(setup, seed, msg_relay, None).await?;

    Ok(EdKeyshare::new(keyshare))
}
