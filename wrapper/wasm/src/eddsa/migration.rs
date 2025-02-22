use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};

use js_sys::Promise;
use k256::{elliptic_curve::group::GroupEncoding, ProjectivePoint};
use keyshare::{keyshareCast, EdKeyshare};
use legacy_keyshare::TOBI_EDDSA_PUBLIC_KEY;
use schnorr_relay::{
    multi_party_schnorr::{curve25519_dalek::EdwardsPoint, keygen::KeyRefreshData},
    setup::keygen::KeygenSetupMsg,
};
use sl_mpc_mate::coord::BufferedMsgRelay;
use wasm_bindgen::{prelude::*, throw_str, throw_val};

use dkls23::{
    keygen::{self, key_refresh::KeyshareForRefresh},
    setup::{ProtocolParticipant, SETUP_MESSAGE_TAG},
    InstanceId,
};

type DecodedSetup = simple_setup_msg::keygen::DecodedSetup;
type ValidatedSetup = simple_setup_msg::keygen::ValidatedSetup;

use crate::{
    abort::AbortGuard,
    log,
    relay::{msg_relay_connect, MsgRelay},
    utils::set_panic_hook,
};

use super::*;

#[wasm_bindgen]
pub async fn init_eddsa_migration(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    old_share: EdKeyshare,
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

    // Look for the public key in the setup message
    let setup_key_id = decoded
        .tags()
        .find_map(|(t, v)| (t == TOBI_EDDSA_PUBLIC_KEY).then_some(v));

    if setup_key_id.is_none() {
        throw_str("missing public key in setup message for key migration");
    }

    let setup = KeygenSetupMsg::from_decoded(decoded, signing_key).expect_throw("Validation setup error");

    let mut abort = AbortGuard::new();

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);

    let share = schnorr_relay::dkg::run(
        setup,
        seed,
        msg_relay,
        Some(old_share.get_refresh_data(Some(vec![1]))),
    )
    .await?;

    Ok(EdKeyshare::new(share))
}

#[wasm_bindgen]
pub async fn join_eddsa_migration_local(
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

    // Look for the public key in the setup message
    let public_key = decoded
        .tags()
        .find_map(|(t, v)| (t == TOBI_EDDSA_PUBLIC_KEY).then_some(v));

    if public_key.is_none() {
        throw_str("missing public key in setup message for key migration");
    }

    let public_key = public_key.unwrap();

    let public_key: [u8; 32] = public_key.try_into().ok().expect_throw("invalid public key");
    log(&format!("Legacy EdDSA public_key: {:?}", public_key));
    let opt = EdwardsPoint::from_bytes(&public_key);
    if opt.is_none().into() {
        throw_str("invalid public key in setup message for key migration");
    }

    let public_key = opt.unwrap();

    let setup =
        KeygenSetupMsg::from_decoded(decoded, Arc::new(signing_key)).expect_throw("Validation setup error");

    let data = KeyRefreshData::recovery_data_for_lost(vec![1], public_key, 1, 2, 3);

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let share = schnorr_relay::dkg::run(setup, seed, msg_relay, Some(data)).await?;

    Ok(EdKeyshare::new(share))
}
