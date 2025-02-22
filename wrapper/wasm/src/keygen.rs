// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};

use eddsa::keyshare::EdKeyshare;
use futures::future;
use js_sys::Promise;
use k256::{elliptic_curve::group::GroupEncoding, schnorr, ProjectivePoint};
use keyshare::keyshareCast;
use legacy_keyshare::{TOBI_ECDSA_PUBLIC_KEY, TOBI_EDDSA_PUBLIC_KEY};
use legacy_share::LegacyKeyshare;
use schnorr_relay::{multi_party_schnorr::keygen::KeyRefreshData, setup::keygen::KeygenSetupMsg};
use wasm_bindgen::{prelude::*, throw_str, throw_val};
use wasm_bindgen_futures::JsFuture;

use dkls23::{
    keygen::{self, key_refresh::KeyshareForRefresh},
    setup::{ProtocolParticipant, SETUP_MESSAGE_TAG},
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

#[wasm_bindgen]
pub struct Keyshares {
    ec_share: Keyshare,
    ed_share: EdKeyshare,
}

#[wasm_bindgen(typescript_custom_section)]
const KeygenValidatorType: &'static str = r#"
type KeygenValidator = (KeygenSetup) => Promise<Keyshare | boolean>;
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "KeygenValidator")]
    pub type KeygenValidator;
}

#[wasm_bindgen]
pub struct KeygenSetup {
    setup: Rc<RefCell<Option<DecodedSetup>>>,
}

#[wasm_bindgen]
impl KeygenSetup {
    fn _ref<R>(&self, f: impl FnOnce(&DecodedSetup) -> R) -> R {
        let r = RefCell::borrow(&self.setup);
        f(r.as_ref().unwrap_throw())
    }

    #[wasm_bindgen]
    pub fn threshold(&self) -> u8 {
        self._ref(|d| d.threshold())
    }

    #[wasm_bindgen]
    pub fn participants(&self) -> u8 {
        self._ref(|d| d.participants())
    }

    #[wasm_bindgen(js_name = verifyingKey)]
    pub fn verifying_key(&self, party: u8) -> Result<Uint8Array, JsError> {
        let vk = self
            ._ref(|d| d.party_verifying_key(party).map(Uint8Array::from))
            .ok_or_else(|| JsError::new("invalid party"))?;

        Ok(vk)
    }

    #[wasm_bindgen]
    pub fn rank(&self, party: u8) -> Result<u8, JsError> {
        self._ref(|d| d.party_rank(party))
            .ok_or_else(|| JsError::new("invalid party id"))
    }

    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> Result<Uint8Array, JsError> {
        let key_id = self
            ._ref(|d| {
                d.tags()
                    .find_map(|(t, v)| (t == tags::KEY_ID).then_some(v))
                    .map(Uint8Array::from)
            })
            .ok_or_else(|| JsError::new("missing key_id"))?;

        Ok(key_id)
    }
}

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
pub async fn init_dkg(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    old_share: Option<Keyshare>,
) -> Result<Keyshare, JsError> {
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

    let setup = ValidatedSetup::from_decoded(decoded, signing_key).expect_throw("Validation setup error");

    let mut abort = AbortGuard::new();

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);

    let keyshare = if let Some(old_share) = old_share {
        keygen::key_refresh::run(
            setup,
            seed,
            msg_relay,
            KeyshareForRefresh::from_keyshare(&old_share, None),
        )
        .await?
    } else {
        keygen::run(setup, seed, msg_relay).await?
    };

    Ok(Keyshare::new(keyshare))
}

#[wasm_bindgen]
pub async fn init_ecdsa_migration(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    old_share: LegacyKeyshare,
) -> Result<Keyshare, JsError> {
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
        .find_map(|(t, v)| (t == TOBI_ECDSA_PUBLIC_KEY).then_some(v));

    if setup_key_id.is_none() {
        throw_str("missing public key in setup message for key migration");
    }

    let setup = ValidatedSetup::from_decoded(decoded, signing_key).expect_throw("Validation setup error");

    let mut abort = AbortGuard::new();

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);

    let share = keygen::key_refresh::run(setup, seed, msg_relay, old_share.recovery_data(vec![1])).await?;

    Ok(Keyshare::new(share))
}

#[wasm_bindgen]
pub async fn init_migration(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    ec_seed: &[u8],
    ed_seed: &[u8],
    old_ecdsa_share: LegacyKeyshare,
    old_eddsa_share: EdKeyshare,
) -> Result<Keyshares, JsError> {
    set_panic_hook();

    let instance: [u8; 32] = instance.try_into().expect_throw("instance-id: invalid size");
    let instance = InstanceId::from(instance);

    let setup_vk: [u8; 32] = setup_vk.try_into()?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)?;
    let signing_key = Arc::new(SigningKey::from_bytes(signing_key.try_into()?));
    let ec_seed = ec_seed.try_into().expect_throw("invalid seed size");
    let ed_seed = ed_seed.try_into().expect_throw("invalid seed size");

    let decoded =
        DecodedSetup::decode(instance, setup_msg, &setup_vk).expect_throw("Setup message decode error");

    // Look for the public key in the setup message
    let ecdsa_pubkey = decoded
        .tags()
        .find_map(|(t, v)| (t == TOBI_ECDSA_PUBLIC_KEY).then_some(v));

    let eddsa_pubkey = decoded
        .tags()
        .find_map(|(t, v)| (t == TOBI_EDDSA_PUBLIC_KEY).then_some(v));

    if ecdsa_pubkey.is_none() || eddsa_pubkey.is_none() {
        throw_str("missing public key in setup message for key migration");
    }

    let setup = ValidatedSetup::from_decoded(decoded.clone(), signing_key.clone())
        .expect_throw("Validation setup error");
    let ed_setup =
        KeygenSetupMsg::from_decoded(decoded, signing_key).expect_throw("Validation setup error");

    let mut abort = AbortGuard::new();

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let ws_conn2 = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);
    let ed_msg_relay = MsgRelay::new(ws_conn2);

    let (res1, res2) = futures::future::join(
        keygen::key_refresh::run(
            setup.clone(),
            ec_seed,
            msg_relay,
            old_ecdsa_share.recovery_data(vec![1]),
        ),
        schnorr_relay::dkg::run(
            ed_setup,
            ed_seed,
            ed_msg_relay,
            Some(old_eddsa_share.get_refresh_data(Some(vec![1]))),
        ),
    )
    .await;
    let ec_share = res1.expect_throw("failed ECDSA migration");
    let ed_share = res2.expect_throw("failed EdDSA migration");

    Ok(Keyshares {
        ec_share: Keyshare::new(ec_share),
        ed_share: EdKeyshare::new(ed_share),
    })
}

// Receive a setup message from pased message relay, decode it and invoke a passed
// user defined validator.
async fn call_validator<R: Relay>(
    msg_relay: &mut BufferedMsgRelay<R>,
    instance: InstanceId,
    setup_vk: &VerifyingKey,
    validator: Option<&js_sys::Function>,
) -> (DecodedSetup, Option<Keyshare>) {
    let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);

    // throw_str("waiting for setup");
    let setup_msg = msg_relay.recv(&msg_id, 50).await.expect_throw("recv setup msg");

    let decoded_setup =
        DecodedSetup::decode(instance, setup_msg, setup_vk).expect_throw("decode setup message");

    if let Some(validate) = validator {
        let cell = Rc::new(RefCell::new(Some(decoded_setup)));

        let js_decoded_setup = JsValue::from(KeygenSetup {
            setup: Rc::clone(&cell), // create second reference
        });

        let result = JsFuture::from(
            validate
                .call1(&JsValue::null(), &js_decoded_setup)
                .expect_throw("validation failed")
                .dyn_into::<Promise>()
                .expect_throw("validator should return Promise"),
        )
        .await;

        let old_share = match result {
            Err(err) => throw_val(err),
            Ok(v) if v.is_falsy() => throw_str("validation failed"),
            Ok(v) if v == true => None,
            Ok(old_share) => Some(keyshareCast(old_share)),
        };

        (cell.replace(None).expect_throw("internal error"), old_share)
    } else {
        (decoded_setup, None)
    }
}

/// Join execution of DKG protocol.
///
/// Connect to the message relay, receive a setup message,
/// decode and validate it and begin execution of the protocol.
///
/// To validate the setup message, `validator` async callback is
/// called with the decoded setup `KeygenSetup`. If validation is
/// failed then throw an error or return `false`. Otherwise return
/// `true` for normal key generation or return Keyshare for key
/// refresh.
///
/// # Arguments
///
/// * `instance`    - Instance ID
/// * `setup_vk`    - Verifying key for a setup message
/// * `signing_key` - Signing key for this participant
/// * `msg_relay`   - URL of message relay service
/// * `seed`        - seed of CPRNG
/// * `validator`   - optional setup message validator
///
#[wasm_bindgen]
pub async fn join_dkg(
    instance: &[u8],
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
    validator: Option<KeygenValidator>,
) -> Result<Keyshare, JsError> {
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
    let mut msg_relay = BufferedMsgRelay::new(msg_relay);

    let (decoded, old_share) = call_validator(
        &mut msg_relay,
        instance,
        &setup_vk,
        validator.as_ref().and_then(|v| v.dyn_ref()),
    )
    .await;

    let setup =
        ValidatedSetup::from_decoded(decoded, Arc::new(signing_key)).expect_throw("Validation setup error");

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let keyshare = if let Some(old_share) = old_share {
        keygen::key_refresh::run(
            setup,
            seed,
            msg_relay,
            KeyshareForRefresh::from_keyshare(&old_share, None),
        )
        .await?
    } else {
        keygen::run(setup, seed, msg_relay).await?
    };

    Ok(Keyshare::new(keyshare))
}

#[wasm_bindgen]
pub async fn join_dkg_local(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
) -> Result<Keyshare, JsError> {
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
        ValidatedSetup::from_decoded(decoded, Arc::new(signing_key)).expect_throw("Validation setup error");

    abort.deadline(setup.message_ttl().as_millis() as u32);
    let keyshare = keygen::run(setup, seed, msg_relay).await?;

    // let keyshare = if let Some(old_share) = old_share {
    //     keygen::key_refresh::run(
    //         setup,
    //         seed,
    //         msg_relay,
    //         KeyshareForRefresh::from_keyshare(&old_share, None),
    //     )
    //     .await?
    // } else {
    //     keygen::run(setup, seed, msg_relay).await?
    // };

    Ok(Keyshare::new(keyshare))
}

#[wasm_bindgen]
pub async fn join_ecdsa_migration_local(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    seed: &[u8],
) -> Result<Keyshare, JsError> {
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
        .find_map(|(t, v)| (t == TOBI_ECDSA_PUBLIC_KEY).then_some(v));

    if public_key.is_none() {
        throw_str("missing public key in setup message for key migration");
    }

    let public_key = public_key.unwrap();

    let opt = ProjectivePoint::from_bytes(public_key.into());
    if opt.is_none().into() {
        throw_str("invalid public key in setup message for key migration");
    }

    let public_key = opt.unwrap();

    let setup =
        ValidatedSetup::from_decoded(decoded, Arc::new(signing_key)).expect_throw("Validation setup error");

    let data = KeyshareForRefresh::from_lost_keyshare(vec![0, 0, 0], 2, public_key, vec![1], 1);

    abort.deadline(setup.message_ttl().as_millis() as u32);
    let keyshare = keygen::key_refresh::run(setup, seed, msg_relay, data).await?;

    Ok(Keyshare::new(keyshare))
}

#[wasm_bindgen]
pub async fn join_migration_local(
    instance: &[u8],
    setup_msg: Vec<u8>,
    setup_vk: &[u8],
    signing_key: &[u8],
    msg_relay: &str,
    ec_seed: &[u8],
    ed_seed: &[u8],
) -> Result<Keyshares, JsError> {
    set_panic_hook();

    let mut abort = AbortGuard::new();

    let instance: [u8; 32] = instance.try_into().expect_throw("instance-id: invalid size");
    let instance = InstanceId::from(instance);

    let setup_vk: [u8; 32] = setup_vk.try_into()?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)?;

    let signing_key = SigningKey::from_bytes(signing_key.try_into()?);
    let ec_seed = ec_seed.try_into().expect_throw("invalid seed size");
    let ed_seed = ed_seed.try_into().expect_throw("invalid seed size");

    let ws_conn = msg_relay_connect(msg_relay, abort.signal()).await?;
    let ws_conn2 = msg_relay_connect(msg_relay, abort.signal()).await?;
    let msg_relay = MsgRelay::new(ws_conn);
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    let ed_msg_relay = MsgRelay::new(ws_conn2);
    let ed_msg_relay = BufferedMsgRelay::new(ed_msg_relay);

    let decoded =
        DecodedSetup::decode(instance, setup_msg, &setup_vk).expect_throw("Setup message decode error");

    // Look for the public key in the setup message
    let ec_public_key = decoded
        .tags()
        .find_map(|(t, v)| (t == TOBI_ECDSA_PUBLIC_KEY).then_some(v));

    let ed_public_key = decoded
        .tags()
        .find_map(|(t, v)| (t == TOBI_EDDSA_PUBLIC_KEY).then_some(v));

    if ec_public_key.is_none() || ed_public_key.is_none() {
        throw_str("missing public key in setup message for key migration");
    }

    let ec_public_key = ec_public_key.unwrap();
    let ed_public_key: [u8; 32] = ed_public_key
        .and_then(|v| v.try_into().ok())
        .expect_throw("expected EdDSA public key to be 32 bytes");

    let opt = ProjectivePoint::from_bytes(ec_public_key.into());
    if opt.is_none().into() {
        throw_str("invalid public key in setup message for key migration");
    }
    let ec_public_key = opt.unwrap();
    let ed_public_key = EdwardsPoint::from_bytes(&ed_public_key)
        .into_option()
        .expect_throw("Invalid EdDSA public key");
    let sk = Arc::new(signing_key);

    let setup =
        ValidatedSetup::from_decoded(decoded.clone(), sk.clone()).expect_throw("Validation setup error");

    let ed_setup = KeygenSetupMsg::from_decoded(decoded, sk).expect_throw("Validation setup error");
    let data = KeyshareForRefresh::from_lost_keyshare(vec![0, 0, 0], 2, ec_public_key, vec![1], 1);
    let ed_data = KeyRefreshData::recovery_data_for_lost(vec![1], ed_public_key, 1, 2, 3);

    abort.deadline(setup.message_ttl().as_millis() as u32);

    let (res1, res2) = futures::future::join(
        keygen::key_refresh::run(setup.clone(), ec_seed, msg_relay, data),
        schnorr_relay::dkg::run(ed_setup, ed_seed, ed_msg_relay, Some(ed_data)),
    )
    .await;
    let ec_share = res1.expect_throw("failed ECDSA migration");
    let ed_share = res2.expect_throw("failed EdDSA migration");

    Ok(Keyshares {
        ec_share: Keyshare::new(ec_share),
        ed_share: EdKeyshare::new(ed_share),
    })
}
