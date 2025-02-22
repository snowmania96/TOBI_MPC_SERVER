#![allow(dead_code)]

use std::borrow::Cow;
use std::env;
use std::future::IntoFuture;
use std::net::ToSocketAddrs;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::async_trait;
use derivation_path::DerivationPath;
use dkls23::sign::SignError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::TryFutureExt;
use legacy_keyshare::schnorr::NewKeyshare;
use schnorr_relay::dkg::ProtocolError;
use schnorr_relay::setup::keygen::KeygenSetupMsg;
use schnorr_relay::setup::sign::SignSetupMsg;
use sha2::Digest;
use simple_cloud_node::storage::{BaseReader, BaseWriter, FileStorage};
use simple_setup_msg::{find_tags, HashAlgo};
use simple_setup_msg::{
    keygen::{DecodedSetup, ValidatedSetup},
    sign::DecodedSetup as SignDecodedSetup,
    sign::ValidatedSetup as SignValidatedSetup,
};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;

use axum::{
    error_handling::HandleErrorLayer,
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    BoxError, Router,
};

use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use k256::{elliptic_curve::group::GroupEncoding, AffinePoint, CompressedPoint};
use rand::Rng;

use serde::{Deserialize, Serialize};

use dkls23::{keygen, sign};
use msg_relay_client::{Endpoint, MsgRelayClient, MsgRelayMux};

use sl_mpc_mate::{
    coord::{stats::*, *},
    message::*,
};
use tracing::Level;

use crate::crypto::EncryptDecryptor;
use crate::flags;
use crate::trace::DefaultMakeSpan;
use crate::validators::post_keygen;

use crate::cache::Cache;
use crate::storage::{BoxedStorage, EddsaKeyshare, GcpClient, GcpStorage, Storage};

use crate::auth::{validate_user, UserInfo};

use crate::error::{AppError, ErrCode};

use dkls23::keygen::Keyshare;
use legacy_keyshare::{LegacyKeyshare, TOBI_ECDSA_PUBLIC_KEY, TOBI_EDDSA_PUBLIC_KEY};

#[async_trait]
impl Storage for FileStorage {
    async fn put_keyshare(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        self.write(key.as_bytes(), "keyshare", &data).await
    }

    async fn get_keyshare(&self, key: String) -> anyhow::Result<Keyshare> {
        let data = self.read(key.as_bytes(), "keyshare").await?;
        Keyshare::from_vec(data).map_err(|_| anyhow::Error::msg("invalid keyshare"))
    }

    async fn put_party_sk(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        self.write(key.as_bytes(), "party_sk", &data).await
    }

    async fn get_party_sk(&self, key: String) -> anyhow::Result<SigningKey> {
        let data = self.read(key.as_bytes(), "party_sk").await?;
        let sk = SigningKey::from_bytes(&data.try_into().unwrap());
        Ok(sk)
    }

    async fn get_eddsa_keyshare(&self, key: String) -> anyhow::Result<EddsaKeyshare> {
        let data = self.read(key.as_bytes(), "keyshare").await?;
        let (share, _) = bincode::serde::decode_from_slice(&data, bincode::config::legacy())?;
        return Ok(share);
    }

    async fn get_legacy_keyshare(&self, public_key: String) -> anyhow::Result<LegacyKeyshare> {
        let data = std::fs::read(format!("./legacy_keyshare_data/{}.keyshare", public_key))?;

        let c = EncryptDecryptor::from(Some(&data), &[public_key.clone()])?;
        // if c.should_upgrade_to_latest() {
        //     self.put_keyshare(public_key, data.clone()).await?;
        // }
        let data = c.decrypt(data)?;
        let (share, _) = bincode::decode_from_slice(&data, bincode::config::standard())?;
        return Ok(share);
    }

    // Implemetation only for testing
    async fn get_legacy_eddsa_keyshare(&self, _key: String) -> anyhow::Result<EddsaKeyshare> {
        let data = std::fs::read("./legacy_keyshare_data/EDDSA_KEYSHARE.keyshare")?;
        //
        // let c = EncryptDecryptor::from(Some(&data), &[key.clone()])?;
        // // if c.should_upgrade_to_latest() {
        // //     self.put_keyshare(public_key, data.clone()).await?;
        // // }
        // let data = c.decrypt(data)?;
        let mut share: legacy_keyshare::schnorr::Keyshare =
            bincode::decode_from_slice(&data, bincode::config::standard())?.0;
        tracing::info!("legacy party_id: {:?}", share.party_id);
        tracing::info!("Legacy eddsa public_key: {:?}", share.public_key.to_bytes());
        share.party_id = 2;
        let key_id = sha2::Sha256::digest(share.public_key.to_bytes()).into();
        let bytes = bincode::serde::encode_to_vec(
            NewKeyshare::from_legacy(share, key_id),
            bincode::config::legacy(),
        )
        .unwrap();
        let share = bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
            .unwrap()
            .0;

        return Ok(share);
    }
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(key: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(key))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = base64::decode(<&str>::deserialize(d)?).map_err(serde::de::Error::custom)?;

        Ok(v)
    }
}

#[derive(Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

impl Deref for AppState {
    type Target = Arc<Inner>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Inner {
    mux: MsgRelayMux,
    storage: BoxedStorage,
}

impl Inner {
    fn new(mux: MsgRelayMux, storage: Box<dyn Storage + Send + Sync>) -> Self {
        Self { mux, storage }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Party {
    rank: u8,
    #[serde(with = "hex::serde")]
    public_key: Vec<u8>,
}

impl Party {
    /// When called on a vector of Vec<Party>, return the data in a tuple format
    pub fn tuple_fmt(parties: &[Party]) -> Vec<(u8, VerifyingKey)> {
        parties
            .iter()
            .filter_map(|party| {
                // TODO: I don't think this clone is wholly necessary - can we remove it?
                let pk: [u8; 32] = party
                    .public_key
                    .clone()
                    .try_into()
                    .expect("The length of the public key is incorrect");
                VerifyingKey::from_bytes(&pk).ok().map(|vk| (party.rank, vk))
            })
            .collect()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let pk: [u8; 32] = self
            .public_key
            .clone()
            .try_into()
            .expect("The length of the public key is incorrect");
        VerifyingKey::from_bytes(&pk).expect("Failed to decode Verifying Key")
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeygenOpts {
    auth_token: String,
    t: u8,
    parties: Vec<Party>,
}

impl KeygenOpts {
    pub fn threshold(&self) -> u8 {
        self.t
    }

    pub fn auth_token(&self) -> String {
        self.auth_token.clone()
    }

    pub fn parties_tuple(&self) -> Vec<(u8, VerifyingKey)> {
        Party::tuple_fmt(&self.parties)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeygenSetupJSON {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,
    ttl: u8,
    setup: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeygenParams {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_vk: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<SetupMsg>,

    #[serde(skip_serializing_if = "Option::is_none")]
    opts: Option<KeygenSetupJSON>,
}

impl KeygenParams {
    pub fn new(inst: &[u8; 32], s_vk: &[u8; 32], p_vk: &[u8]) -> Self {
        Self {
            instance: inst.to_vec(),
            setup_vk: s_vk.to_vec(),
            party_vk: p_vk.to_vec(),
            setup: None,
            opts: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EddsaKeygenParams {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_enc_key: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<SetupMsg>,

    #[serde(skip_serializing_if = "Option::is_none")]
    opts: Option<KeygenSetupJSON>,
}

impl EddsaKeygenParams {
    pub fn new(inst: &[u8; 32], s_vk: &[u8; 32], p_vk: &[u8], enc_key: &[u8]) -> Self {
        Self {
            instance: inst.to_vec(),
            setup_vk: s_vk.to_vec(),
            party_vk: p_vk.to_vec(),
            party_enc_key: enc_key.to_vec(),
            setup: None,
            opts: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyRefreshParams {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    address: Vec<u8>,

    lost_party_ids: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<SetupMsg>,

    #[serde(skip_serializing_if = "Option::is_none")]
    opts: Option<KeygenSetupJSON>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EddsaKeyRefreshParams {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_enc_key: Vec<u8>,

    address: String,

    lost_party_ids: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<SetupMsg>,

    #[serde(skip_serializing_if = "Option::is_none")]
    opts: Option<KeygenSetupJSON>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeygenResponse {
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,

    pub total_send: u32,
    pub total_recv: u32,
    pub total_wait: u32,
    pub total_time: u32, // execution time in milliseconds
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MigrationResponse {
    #[serde(with = "hex::serde")]
    pub ecdsa_public_key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub eddsa_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignParams {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_vk: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<SetupMsg>,

    #[serde(skip_serializing_if = "Option::is_none")]
    opts: Option<SignOpts>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSetup {
    #[serde(with = "hex::serde")]
    public_key: Vec<u8>,
    auth_token: String,
    parties: Vec<Party>,
    #[serde(with = "hex::serde")]
    message: Vec<u8>, // This will hold the message to be signed
    raw_message: Option<String>,
    chain_path: Option<String>,
    hash_algo: Option<String>,
}

impl SignSetup {
    /// Parse the chain path from an Option<String> to DerivationPath, defaulting to "m" if None
    pub fn chain_path(&self) -> DerivationPath {
        self.chain_path
            .as_ref()
            .map(|cp_str| {
                cp_str
                    .parse()
                    .expect("Failed to parse chain path into DerivationPath")
            })
            .unwrap_or_else(|| "m".parse().expect("Failed to parse default chain path"))
    }

    pub fn message(&self) -> &Vec<u8> {
        &self.message
    }

    pub fn raw_message(&self) -> &Option<String> {
        &self.raw_message
    }

    pub fn auth_token(&self) -> String {
        self.auth_token.clone()
    }

    pub fn parties_tuple(&self) -> Vec<(u8, VerifyingKey)> {
        Party::tuple_fmt(&self.parties)
    }

    pub fn parties_verifying_keys(&self) -> Vec<VerifyingKey> {
        self.parties.iter().map(|party| party.verifying_key()).collect()
    }

    pub fn public_key(&self) -> AffinePoint {
        let pk: [u8; 33] = self
            .public_key
            .clone()
            .try_into()
            .expect("The length of the public key is incorrect");

        let bytes = CompressedPoint::from(pk);

        AffinePoint::from_bytes(&bytes).expect("Failed to deserialize public key")
    }

    pub fn hash_algo(&self) -> HashAlgo {
        match self.hash_algo.as_deref().unwrap_or("sha256") {
            "sha256" => HashAlgo::Sha256,
            "sha256d" => HashAlgo::Sha256D,
            "keccak256" => HashAlgo::Keccak256,
            "hashu32" => HashAlgo::HashU32,
            _ => HashAlgo::Sha256,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignOpts {
    setup: SignSetup,
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,
    ttl: u64,
}

impl SignParams {
    pub fn new(inst: &[u8; 32], s_vk: &[u8; 32], p_vk: &[u8]) -> Self {
        Self {
            instance: inst.to_vec(),
            setup_vk: s_vk.to_vec(),
            party_vk: p_vk.to_vec(),
            setup: None,
            opts: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignResponse {
    #[serde(with = "hex::serde")]
    pub sign: Vec<u8>,
    pub recid: u8,

    pub total_send: u32,
    pub total_recv: u32,
    pub total_wait: u32,
    pub total_time: u32, // execution time in milliseconds

    #[serde(skip_serializing_if = "Option::is_none")]
    pub times: Option<Vec<(u32, Duration)>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupMsg {
    #[serde(with = "hex::serde")]
    instance: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    party_vk: Vec<u8>,

    #[serde(with = "hex::serde")]
    setup_msg: Vec<u8>,
}

async fn handle_keygen(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<KeygenResponse>, AppError> {
    let start = Instant::now();

    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-keygen: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-keygen: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-keygen: party_vk {:?}", party_vk_hex);

    let party_sk = storage
        .get_party_sk(party_vk_hex)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
    let party_sk = Arc::new(party_sk);

    // Set up the connection to the message relay service
    let msg_relay = state.mux.connect(100);

    let stats = Stats::alloc();
    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    // If the POST request contains a setup, use it by default
    // Otherwise, check the message relay service for a relevant message that would contain the setup
    // keyed by this instance ID
    tracing::debug!("Received setup message from request. Decoding that...");

    let given_setup = payload.setup_msg;

    // tracing::debug!("Received auth token: {:?}", given_setup.auth_token());

    let setup = DecodedSetup::decode(instance, given_setup, &setup_vk).unwrap();

    tracing::debug!("Setup constructed");

    let ttl = setup.ttl();
    tracing::debug!("Time to live: {:?}", ttl);

    tracing::debug!("Instance ID: {:?}", instance);

    let deadline = tokio::time::sleep(setup.ttl());
    tokio::pin!(deadline);

    let validated_setup =
        ValidatedSetup::from_decoded(setup, party_sk.clone()).expect("Failed to construct ValidatedSetup");

    tracing::info!("Validated setup!");

    let seed = rand::random();

    let share = tokio::select! {
        _ = &mut deadline => {
            return Err(ErrCode::DKGFail.pack_with_str("timeout"));
        }

        share = keygen::run(validated_setup.clone(), seed, msg_relay) => {
            share.map_err(|err| {
                ErrCode::DKGFail.pack_with_cause("", err.into())
            })?
        }
    };

    // This encompasses any actions that need to be done after we have our share.
    match post_keygen(&validated_setup, &share) {
        Ok(_) => {
            tracing::debug!("post_keygen ok");
        }
        Err(_err) => {
            return Err(ErrCode::Internal.pack_with_cause("Error in post_keygen: {:?}", _err));
        }
    }

    storage
        .put_keyshare(hex::encode(share.key_id), share.as_slice().to_vec())
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;

    let total_time = start.elapsed().as_millis() as u32;

    let stats = stats.lock().unwrap();

    tracing::info!("keygen send_count: {}", stats.send_count);
    tracing::info!("keygen send_size:  {}", stats.send_size);
    tracing::info!("keygen recv_count: {}", stats.recv_count);
    tracing::info!("keygen recv_size:  {}", stats.recv_size);
    tracing::info!("keygen wait_time:  {:?}", stats.wait_time);

    for (id, wait) in &stats.wait_times {
        tracing::debug!(" - {:?} {:?}", id, wait);
    }

    tracing::info!("keygen total_time: {:?}", total_time);

    let resp = Json(KeygenResponse {
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        public_key: share.public_key.into(),
        total_time,
    });

    Ok(resp)
}

#[axum::debug_handler]
async fn handle_migration(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<MigrationResponse>, AppError> {
    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-keygen: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-keygen: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-keygen: party_vk {:?}", party_vk_hex);

    let party_sk = storage
        .get_party_sk(party_vk_hex)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
    let party_sk = Arc::new(party_sk);

    // Set up the connection to the message relay service
    let msg_relay = state.mux.connect(100);
    // Connection for eddsa
    let ed_msg_relay = state.mux.connect(100);

    let stats = Stats::alloc();
    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);
    let ed_msg_relay = BufferedMsgRelay::new(RelayStats::new(ed_msg_relay, stats.clone()));

    // If the POST request contains a setup, use it by default
    // Otherwise, check the message relay service for a relevant message that would contain the setup
    // keyed by this instance ID
    tracing::debug!("Received setup message from request. Decoding that...");

    let given_setup = payload.setup_msg;

    // tracing::debug!("Received auth token: {:?}", given_setup.auth_token());

    let setup = DecodedSetup::decode(instance, given_setup, &setup_vk).unwrap();

    let ec_public_key = find_tags(setup.data(), TOBI_ECDSA_PUBLIC_KEY)
        .next()
        .ok_or(ErrCode::SetupFail.pack_with_str("missing public key"))?
        .to_vec();

    let ed_public_key = find_tags(setup.data(), TOBI_EDDSA_PUBLIC_KEY)
        .next()
        .ok_or(ErrCode::SetupFail.pack_with_str("missing public key"))?
        .to_vec();

    let share = state
        .storage
        .get_legacy_keyshare(hex::encode(ec_public_key))
        .await?;
    let ed_share = state
        .storage
        .get_legacy_eddsa_keyshare(hex::encode(ed_public_key))
        .await?;
    let data = share.recovery_data(vec![1]);
    let ed_data = ed_share.get_refresh_data(Some(vec![1]));

    tracing::debug!("Setup constructed");

    let ttl = setup.ttl();
    tracing::debug!("Time to live: {:?}", ttl);

    tracing::debug!("Instance ID: {:?}", instance);

    let deadline = tokio::time::sleep(setup.ttl());
    tokio::pin!(deadline);

    let validated_setup = ValidatedSetup::from_decoded(setup.clone(), party_sk.clone())
        .expect("Failed to construct ValidatedSetup");
    let eddsa_setup =
        KeygenSetupMsg::from_decoded(setup, party_sk.clone()).expect("Failed to construct KeygenSetupMsg");

    tracing::info!("Validated setup!");

    let seed = rand::random();
    let ed_seed = rand::random();

    let res = futures::future::join(
        keygen::key_refresh::run(validated_setup.clone(), seed, msg_relay, data),
        schnorr_relay::dkg::run(eddsa_setup, ed_seed, ed_msg_relay, Some(ed_data)),
    );

    let (ec_share, ed_share) = tokio::select! {
        _ = &mut deadline => {
            return Err(ErrCode::DKGFail.pack_with_str("timeout"));
        }
    (ec_share, ed_share) = res => {
            (ec_share.map_err(|err| ErrCode::DKGFail.pack_with_str(&err.to_string()))?,
                ed_share.map_err(|err| ErrCode::DKGFail.pack_with_str(&err.to_string()))?)
            }

        };

    // // This encompasses any actions that need to be done after we have our share.
    // match post_keygen(&validated_setup, &share) {
    //     Ok(_) => {
    //         tracing::debug!("post_keygen ok");
    //     }
    //     Err(_err) => {
    //         return Err(ErrCode::Internal.pack_with_cause("Error in post_keygen: {:?}", _err));
    //     }
    // }
    let ed_bytes = bincode::serde::encode_to_vec(&ed_share, bincode::config::legacy()).unwrap();

    // Write both keyshares
    futures::future::try_join(
        storage
            .put_keyshare(hex::encode(ec_share.key_id), ec_share.as_slice().to_vec())
            .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into())),
        storage
            .put_keyshare(hex::encode(ed_share.key_id), ed_bytes)
            .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into())),
    )
    .await?;

    let resp = Json(MigrationResponse {
        ecdsa_public_key: ec_share.public_key.into(),
        eddsa_public_key: ed_share.public_key.to_bytes().into(),
    });

    Ok(resp)
}

async fn handle_ecdsa_migration(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<KeygenResponse>, AppError> {
    let start = Instant::now();

    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-keygen: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-keygen: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-keygen: party_vk {:?}", party_vk_hex);

    let party_sk = storage
        .get_party_sk(party_vk_hex)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
    let party_sk = Arc::new(party_sk);

    // Set up the connection to the message relay service
    let msg_relay = state.mux.connect(100);

    let stats = Stats::alloc();
    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    // If the POST request contains a setup, use it by default
    // Otherwise, check the message relay service for a relevant message that would contain the setup
    // keyed by this instance ID
    tracing::debug!("Received setup message from request. Decoding that...");

    let given_setup = payload.setup_msg;

    // tracing::debug!("Received auth token: {:?}", given_setup.auth_token());

    let setup = DecodedSetup::decode(instance, given_setup, &setup_vk).unwrap();

    let public_key = find_tags(setup.data(), TOBI_ECDSA_PUBLIC_KEY)
        .next()
        .ok_or(ErrCode::SetupFail.pack_with_str("missing public key"))?
        .to_vec();

    let share = state.storage.get_legacy_keyshare(hex::encode(public_key)).await?;
    let data = share.recovery_data(vec![1]);

    tracing::debug!("Setup constructed");

    let ttl = setup.ttl();
    tracing::debug!("Time to live: {:?}", ttl);

    tracing::debug!("Instance ID: {:?}", instance);

    let deadline = tokio::time::sleep(setup.ttl());
    tokio::pin!(deadline);

    let validated_setup =
        ValidatedSetup::from_decoded(setup, party_sk.clone()).expect("Failed to construct ValidatedSetup");

    tracing::info!("Validated setup!");

    let seed = rand::random();

    let share = tokio::select! {
        _ = &mut deadline => {
            return Err(ErrCode::DKGFail.pack_with_str("timeout"));
        }

        share = keygen::key_refresh::run(validated_setup.clone(), seed, msg_relay, data) => {
            share.map_err(|err| {
                ErrCode::DKGFail.pack_with_cause("", err.into())
            })?
        }
    };

    // This encompasses any actions that need to be done after we have our share.
    match post_keygen(&validated_setup, &share) {
        Ok(_) => {
            tracing::debug!("post_keygen ok");
        }
        Err(_err) => {
            return Err(ErrCode::Internal.pack_with_cause("Error in post_keygen: {:?}", _err));
        }
    }

    storage
        .put_keyshare(hex::encode(share.key_id), share.as_slice().to_vec())
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;

    let total_time = start.elapsed().as_millis() as u32;

    let stats = stats.lock().unwrap();

    tracing::info!("keygen send_count: {}", stats.send_count);
    tracing::info!("keygen send_size:  {}", stats.send_size);
    tracing::info!("keygen recv_count: {}", stats.recv_count);
    tracing::info!("keygen recv_size:  {}", stats.recv_size);
    tracing::info!("keygen wait_time:  {:?}", stats.wait_time);

    for (id, wait) in &stats.wait_times {
        tracing::debug!(" - {:?} {:?}", id, wait);
    }

    tracing::info!("keygen total_time: {:?}", total_time);

    let resp = Json(KeygenResponse {
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        public_key: share.public_key.into(),
        total_time,
    });

    Ok(resp)
}

async fn handle_eddsa_migration(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<KeygenResponse>, AppError> {
    let start = Instant::now();

    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-keygen: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-keygen: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-keygen: party_vk {:?}", party_vk_hex);

    let party_sk = storage
        .get_party_sk(party_vk_hex)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
    let party_sk = Arc::new(party_sk);

    // Set up the connection to the message relay service
    let msg_relay = state.mux.connect(100);

    let stats = Stats::alloc();
    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    // If the POST request contains a setup, use it by default
    // Otherwise, check the message relay service for a relevant message that would contain the setup
    // keyed by this instance ID
    tracing::debug!("Received setup message from request. Decoding that...");

    let given_setup = payload.setup_msg;

    // tracing::debug!("Received auth token: {:?}", given_setup.auth_token());

    let setup = DecodedSetup::decode(instance, given_setup, &setup_vk).unwrap();

    let public_key = find_tags(setup.data(), TOBI_EDDSA_PUBLIC_KEY)
        .next()
        .ok_or(ErrCode::SetupFail.pack_with_str("missing public key"))?
        .to_vec();

    let share = state
        .storage
        .get_legacy_eddsa_keyshare(hex::encode(public_key))
        .await?;
    let refresh_data = share.get_refresh_data(Some(vec![1]));

    tracing::debug!("Setup constructed");

    let ttl = setup.ttl();
    tracing::debug!("Time to live: {:?}", ttl);

    tracing::debug!("Instance ID: {:?}", instance);

    let deadline = tokio::time::sleep(setup.ttl());
    tokio::pin!(deadline);

    let validated_setup =
        KeygenSetupMsg::from_decoded(setup, party_sk.clone()).expect("Failed to construct ValidatedSetup");

    tracing::info!("Validated setup!");

    let seed = rand::random();

    let share = tokio::select! {
        _ = &mut deadline => {
            return Err(ErrCode::DKGFail.pack_with_str("timeout"));
        }

        share = schnorr_relay::dkg::run(validated_setup.clone(), seed, msg_relay, Some(refresh_data)) => {
            share.map_err(|err| {
                ErrCode::DKGFail.pack_with_cause("", err.into())
            })?
        }
    };

    let share_bytes = bincode::serde::encode_to_vec(&share, bincode::config::legacy())
        .map_err(|err| ErrCode::Internal.pack_with_cause("encode keyshare fail", err.into()))?;
    storage
        .put_keyshare(hex::encode(share.key_id), share_bytes)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;

    let total_time = start.elapsed().as_millis() as u32;

    let stats = stats.lock().unwrap();

    tracing::info!("keygen send_count: {}", stats.send_count);
    tracing::info!("keygen send_size:  {}", stats.send_size);
    tracing::info!("keygen recv_count: {}", stats.recv_count);
    tracing::info!("keygen recv_size:  {}", stats.recv_size);
    tracing::info!("keygen wait_time:  {:?}", stats.wait_time);

    for (id, wait) in &stats.wait_times {
        tracing::debug!(" - {:?} {:?}", id, wait);
    }

    tracing::info!("keygen total_time: {:?}", total_time);

    let resp = Json(KeygenResponse {
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        public_key: share.public_key.to_bytes().to_vec(),
        total_time,
    });

    Ok(resp)
}

async fn handle_eddsa_keygen(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<KeygenResponse>, AppError> {
    let start = Instant::now();

    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-keygen: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-keygen: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-keygen: party_vk {:?}", party_vk_hex);

    let party_sk = storage
        .get_party_sk(party_vk_hex)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
    let party_sk = Arc::new(party_sk);

    // Set up the connection to the message relay service
    let msg_relay = state.mux.connect(100);

    let stats = Stats::alloc();
    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    // If the POST request contains a setup, use it by default
    // Otherwise, check the message relay service for a relevant message that would contain the setup
    // keyed by this instance ID
    tracing::debug!("Received setup message from request. Decoding that...");

    let given_setup = payload.setup_msg;

    // tracing::debug!("Received auth token: {:?}", given_setup.auth_token());

    let setup = DecodedSetup::decode(instance, given_setup, &setup_vk).unwrap();

    tracing::debug!("Setup constructed");

    let ttl = setup.ttl();
    tracing::debug!("Time to live: {:?}", ttl);

    tracing::debug!("Instance ID: {:?}", instance);

    let deadline = tokio::time::sleep(setup.ttl());
    tokio::pin!(deadline);

    let validated_setup =
        KeygenSetupMsg::from_decoded(setup, party_sk.clone()).expect("Failed to construct ValidatedSetup");

    tracing::info!("Validated setup!");

    let seed = rand::random();

    let share: EddsaKeyshare = tokio::select! {
        _ = &mut deadline => {
            return Err(ErrCode::DKGFail.pack_with_str("timeout"));
        }

        share = schnorr_relay::dkg::run(validated_setup.clone(), seed, msg_relay, None) => {
            share.map_err(|err| {
                ErrCode::DKGFail.pack_with_cause("", err.into())
            })?
        }
    };

    let bytes = bincode::serde::encode_to_vec(&share, bincode::config::legacy()).unwrap();
    storage
        .put_keyshare(hex::encode(share.key_id), bytes)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;

    let total_time = start.elapsed().as_millis() as u32;

    let stats = stats.lock().unwrap();

    tracing::info!("keygen send_count: {}", stats.send_count);
    tracing::info!("keygen send_size:  {}", stats.send_size);
    tracing::info!("keygen recv_count: {}", stats.recv_count);
    tracing::info!("keygen recv_size:  {}", stats.recv_size);
    tracing::info!("keygen wait_time:  {:?}", stats.wait_time);

    for (id, wait) in &stats.wait_times {
        tracing::debug!(" - {:?} {:?}", id, wait);
    }

    tracing::info!("keygen total_time: {:?}", total_time);

    let resp = Json(KeygenResponse {
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        public_key: share.public_key.compress().to_bytes().into(),
        total_time,
    });

    Ok(resp)
}

// async fn handle_refresh(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<SetupMsg>,
// ) -> Result<Json<KeygenResponse>, AppError> {
//     let start = Instant::now();
//
//     // if !auth_disabled() {
//     //     validate_user(headers)
//     //         .await
//     //         .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     // }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-keygen: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-keygen: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-keygen: party_vk {:?}", party_vk_hex);
//
//     let party_sk = storage
//         .get_party_sk(party_vk_hex)
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//     let party_sk = Arc::new(party_sk);
//
//     // Set up the connection to the message relay service
//     let msg_relay = state.mux.connect(100);
//
//     let stats = Stats::alloc();
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     // If the POST request contains a setup, use it by default
//     // Otherwise, check the message relay service for a relevant message that would contain the setup
//     // keyed by this instance ID
//     tracing::debug!("Received setup message from request. Decoding that...");
//
//     let given_setup = payload.setup_msg;
//
//     // tracing::debug!("Received auth token: {:?}", given_setup.auth_token());
//
//     let setup = DecodedSetup::decode(instance, given_setup, &setup_vk).unwrap();
//
//     let key_id = find_tags(setup.data(), tags::KEY_ID)
//         .next()
//         .ok_or(ErrCode::SetupFail.pack_with_str("missing key_id"))?
//         .to_vec();
//
//     tracing::debug!("Setup constructed");
//
//     let ttl = setup.ttl();
//     tracing::debug!("Time to live: {:?}", ttl);
//
//     tracing::debug!("Instance ID: {:?}", instance);
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     let validated_setup =
//         ValidatedSetup::from_decoded(setup, party_sk.clone()).expect("Failed to construct ValidatedSetup");
//
//     tracing::info!("Validated setup!");
//
//     let seed = rand::random();
//     let old_share = storage
//         .get_keyshare(hex::encode(key_id))
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve keyshare", err.into()))?;
//
//     let share = tokio::select! {
//         _ = &mut deadline => {
//             return Err(ErrCode::DKGFail.pack_with_str("timeout"));
//         }
//
//         share = key_refresh::run(validated_setup.clone(), seed, msg_relay, KeyshareForRefresh::from_keyshare(&old_share, None)) => {
//             share.map_err(|err| {
//                 ErrCode::DKGFail.pack_with_cause("", err.into())
//             })?
//         }
//     };
//
//     // This encompasses any actions that need to be done after we have our share.
//     match post_keygen(&validated_setup, &share) {
//         Ok(_) => {
//             tracing::debug!("post_keygen ok");
//         }
//         Err(_err) => {
//             return Err(ErrCode::Internal.pack_with_cause("Error in post_keygen: {:?}", _err));
//         }
//     }
//
//     storage
//         .put_keyshare(hex::encode(share.key_id), share.as_slice().to_vec())
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("keygen send_count: {}", stats.send_count);
//     tracing::info!("keygen send_size:  {}", stats.send_size);
//     tracing::info!("keygen recv_count: {}", stats.recv_count);
//     tracing::info!("keygen recv_size:  {}", stats.recv_size);
//     tracing::info!("keygen wait_time:  {:?}", stats.wait_time);
//
//     for (id, wait) in &stats.wait_times {
//         tracing::debug!(" - {:?} {:?}", id, wait);
//     }
//
//     tracing::info!("keygen total_time: {:?}", total_time);
//
//     let resp = Json(KeygenResponse {
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         public_key: share.public_key.into(),
//         total_time,
//     });
//
//     Ok(resp)
// }

// #[debug_handler]
// async fn handle_eddsa_keygen(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<EddsaKeygenParams>,
// ) -> Result<Json<KeygenResponse>, AppError> {
//     let start = Instant::now();
//
//     tracing::info!("handle-eddsa-keygen: inst {:?}", hex::encode(&payload.instance));
//
//     if !auth_disabled() {
//         validate_user(headers)
//             .await
//             .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-eddsa-keygen: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-eddsa-keygen: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-eddsa-keygen: party_vk {:?}", party_vk_hex);
//
//     let party_vk = storage
//         .get_party_sk(party_vk_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//
//     let party_enc_key_hex = hex::encode(&payload.party_enc_key);
//
//     tracing::info!("handle-eddsa-keygen: party_enc_key_hex {:?}", party_enc_key_hex);
//
//     let party_enc_key = storage
//         .get_party_enc_key(party_enc_key_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_enc_key", err.into()))?;
//
//     let msg_relay = state.mux.connect(100);
//
//     let stats = Stats::alloc();
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let mut msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);
//     tracing::debug!("ask {:X}", msg_id);
//
//     let mut setup = msg_relay
//         .recv(&msg_id, 10)
//         .await
//         .ok_or(ErrCode::Internal.pack_with_str("unable to connect to msg relay"))?;
//
//     tracing::info!("setup received");
//
//     let party_key = PartyKeys::from_keys(party_vk.clone(), party_enc_key.clone());
//
//     tracing::info!("Decoding setup message");
//     let setup =
//         schnorr_keygen::ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_key, |_, _, _| true)
//             .ok_or(ErrCode::Internal.pack_with_str("Cannot decode setup message"))?;
//
//     tracing::info!("setup validated");
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     let seed = rand::random();
//
//     tracing::debug!("seed {:?}", seed);
//
//     let share = tokio::select! {
//         _ = &mut deadline => {
//             return Err(ErrCode::DKGFail.pack_with_str("timeout"));
//         }
//
//         share = schnorr_keygen::run(setup, seed, msg_relay) => {
//             share.map_err(|err| {
//                 return ErrCode::DKGFail.pack_with_cause("", err.into());
//             })?
//         }
//     };
//
//     let pk_vec = share.public_key.compress().to_bytes();
//     let pk_hex = hex::encode(pk_vec);
//
//     let share = bincode::encode_to_vec(&share, bincode::config::standard())
//         .map_err(|err| ErrCode::Internal.pack_with_cause("encode keyshare fail", err.into()))?;
//
//     storage
//         .put_keyshare(format!("{}.keyshare", pk_hex), share)
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("eddsa keygen send_count: {}", stats.send_count);
//     tracing::info!("eddsa keygen send_size:  {}", stats.send_size);
//     tracing::info!("eddsa keygen recv_count: {}", stats.recv_count);
//     tracing::info!("eddsa keygen recv_size:  {}", stats.recv_size);
//     tracing::info!("eddsa keygen wait_time:  {:?}", stats.wait_time);
//
//     for (id, wait) in &stats.wait_times {
//         tracing::debug!(" - {:?} {:?}", id, wait);
//     }
//
//     tracing::info!("eddsa keygen total_time: {:?}", total_time);
//
//     let resp = Json(KeygenResponse {
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         public_key: pk_vec.to_vec(),
//         total_time,
//     });
//
//     Ok(resp)
// }
//
// async fn handle_keymigration(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<KeyRefreshParams>,
// ) -> Result<Json<KeygenResponse>, AppError> {
//     let start = Instant::now();
//
//     let mut user_info = UserInfo::default();
//     let auth_disabled = auth_disabled();
//     if !auth_disabled {
//         user_info = validate_user(headers)
//             .await
//             .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-keymigration: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-keymigration: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let address_hex: String = hex::encode(&payload.address);
//     tracing::info!("handle-keymigration: address {:?}", address_hex);
//
//     let address: [u8; 33] = payload
//         .address
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid address"))?;
//
//     let public_key = AffinePoint::from_bytes(&address.into());
//     let public_key = if bool::from(public_key.is_some()) {
//         public_key.unwrap()
//     } else {
//         return Err(ErrCode::SetupFail.pack_with_str("unable to decode address"));
//     };
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-keymigration: party_vk {:?}", party_vk_hex);
//
//     let party_vk = storage
//         .get_party_sk(party_vk_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//
//     // Set up the connection to the message relay service
//     let msg_relay = state.mux.connect(100);
//
//     let stats = Stats::alloc();
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let mut msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     // There should be no setup in opts
//     tracing::debug!("No setup received. Checking message relay");
//
//     let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);
//
//     let mut setup = msg_relay
//         .recv(&msg_id, 10)
//         .await
//         .ok_or(ErrCode::Internal.pack_with_str("unable to connect to msg relay"))?;
//
//     tracing::debug!("setup received");
//
//     // Tiendv: both setup_vk & party_key should be send from client
//     // party key in this case is signing Key
//     // client should send verifying_key instead
//     // here we will get the key from cache or db
//     let setup = keygen::ValidatedSetup::decode(
//         &mut setup,
//         &instance,
//         &setup_vk,
//         party_vk.clone(),
//         validate_setup_keygen,
//     )
//     .ok_or(ErrCode::Internal.pack_with_str("unable to validate setup message"))?;
//
//     tracing::debug!("setup validated");
//
//     if !auth_disabled {
//         let public_key = public_key.to_encoded_point(false);
//         let public_key = public_key.as_bytes();
//
//         let hash = keccak256(&public_key[1..]);
//
//         let a = Address::from_slice(&hash[12..]);
//         let addr = format!("{}{}", "0x".to_string(), hex::encode(a.as_fixed_bytes()));
//
//         match user_info.get_wallet_addresses() {
//             Some(wallets) => {
//                 if !wallets.iter().any(|e| e.to_lowercase().eq(&addr)) {
//                     tracing::debug!(
//                         "user {:?} is not allowed to access {:?}",
//                         user_info.get_identity(),
//                         addr
//                     );
//                     return Err(ErrCode::Internal.pack_with_str(""));
//                 }
//             }
//             None => {
//                 return Err(ErrCode::Internal.pack_with_str("invalid wallet addresses"));
//             }
//         }
//     }
//
//     let old_share = storage
//         .get_keyshare_v0(format!("{}.keyshare", address_hex))
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve keyshare", err.into()))?;
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     let seed = rand::random();
//
//     let new_share = tokio::select! {
//         _ = &mut deadline => {
//             return Err(ErrCode::DKMFail.pack_with_str("timeout"));
//         }
//
//         share = key_refresh::run(setup, seed, msg_relay, old_share.into_with_lost_party_ids(vec!())) => {
//             share.map_err(|err| {
//                 return ErrCode::DKMFail.pack_with_cause("", err.into());
//             })?
//         }
//     };
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     // let stats = stats.lock().unwrap();
//
//     let pk_vec = new_share.public_key.to_affine().to_bytes().to_vec();
//     let pk_hex = hex::encode(&pk_vec);
//
//     let share = bincode::encode_to_vec(&new_share, bincode::config::standard())
//         .map_err(|err| ErrCode::Internal.pack_with_cause("encode keyshare fail", err.into()))?;
//
//     storage
//         .put_keyshare(format!("{}.keyshare", pk_hex), share)
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("keymigr send_count: {}", stats.send_count);
//     tracing::info!("keymigr send_size:  {}", stats.send_size);
//     tracing::info!("keymigr recv_count: {}", stats.recv_count);
//     tracing::info!("keymigr recv_size:  {}", stats.recv_size);
//     tracing::info!("keymigr wait_time:  {:?}", stats.wait_time);
//
//     for (id, wait) in &stats.wait_times {
//         tracing::debug!(" - {:?} {:?}", id, wait);
//     }
//
//     tracing::info!("keymigr total_time: {:?}", total_time);
//
//     let resp = Json(KeygenResponse {
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         public_key: pk_vec,
//         total_time,
//     });
//
//     Ok(resp)
// }
//
// async fn handle_keyrefresh(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<KeyRefreshParams>,
// ) -> Result<Json<KeygenResponse>, AppError> {
//     let start = Instant::now();
//
//     let mut user_info = UserInfo::default();
//     let auth_disabled = auth_disabled();
//     if !auth_disabled {
//         user_info = validate_user(headers)
//             .await
//             .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-keyrefresh: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-keyrefresh: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let address_hex: String = hex::encode(&payload.address);
//     tracing::info!("handle-keyrefresh: address {:?}", address_hex);
//
//     let address: [u8; 33] = payload
//         .address
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid address"))?;
//
//     let public_key = AffinePoint::from_bytes(&address.into());
//     let public_key = if bool::from(public_key.is_some()) {
//         public_key.unwrap()
//     } else {
//         return Err(ErrCode::SetupFail.pack_with_str("unable to decode address"));
//     };
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-keyrefresh: party_vk {:?}", party_vk_hex);
//
//     let party_vk = storage
//         .get_party_sk(party_vk_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//
//     // Set up the connection to the message relay service
//     let msg_relay = state.mux.connect(100);
//
//     let stats = Stats::alloc();
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let mut msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     // There should be no setup in opts
//     tracing::debug!("No setup received. Checking message relay");
//
//     let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);
//
//     let mut setup = msg_relay
//         .recv(&msg_id, 10)
//         .await
//         .ok_or(ErrCode::Internal.pack_with_str("unable to connect to msg relay"))?;
//
//     tracing::debug!("setup received");
//
//     let setup = keygen::ValidatedSetup::decode(
//         &mut setup,
//         &instance,
//         &setup_vk,
//         party_vk.clone(),
//         validate_setup_keygen,
//     )
//     .ok_or(ErrCode::Internal.pack_with_str("unable to validate setup message"))?;
//
//     tracing::debug!("setup validated");
//
//     let key_share = storage
//         .get_keyshare(format!("{}.keyshare", address_hex))
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve keyshare", err.into()))?;
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     let seed = rand::random();
//
//     let new_share = tokio::select! {
//         _ = &mut deadline => {
//             return Err(ErrCode::DKRFail.pack_with_str("timeout"));
//         }
//
//         share = key_refresh::run(setup, seed, msg_relay, key_share.into_with_lost_party_ids(payload.lost_party_ids.unwrap_or_default(), false)) => {
//             share.map_err(|err| {
//                 return ErrCode::DKRFail.pack_with_cause("", err.into());
//             })?
//         }
//     };
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     // let stats = stats.lock().unwrap();
//
//     let pk_vec = new_share.public_key.to_affine().to_bytes().to_vec();
//     let pk_hex = hex::encode(&pk_vec);
//
//     let share = bincode::encode_to_vec(&new_share, bincode::config::standard())
//         .map_err(|err| ErrCode::Internal.pack_with_cause("encode keyshare fail", err.into()))?;
//
//     storage
//         .put_keyshare(format!("{}.keyshare", pk_hex), share)
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("keyrefresh send_count: {}", stats.send_count);
//     tracing::info!("keyrefresh send_size:  {}", stats.send_size);
//     tracing::info!("keyrefresh recv_count: {}", stats.recv_count);
//     tracing::info!("keyrefresh recv_size:  {}", stats.recv_size);
//     tracing::info!("keyrefresh wait_time:  {:?}", stats.wait_time);
//
//     for (id, wait) in &stats.wait_times {
//         tracing::debug!(" - {:?} {:?}", id, wait);
//     }
//
//     tracing::info!("keyrefresh total_time: {:?}", total_time);
//
//     let resp = Json(KeygenResponse {
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         public_key: pk_vec,
//         total_time,
//     });
//
//     Ok(resp)
// }
//
// async fn handle_eddsa_keyrefresh(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<EddsaKeyRefreshParams>,
// ) -> Result<Json<KeygenResponse>, AppError> {
//     let start = Instant::now();
//
//     let mut user_info = UserInfo::default();
//     let auth_disabled = auth_disabled();
//     if !auth_disabled {
//         user_info = validate_user(headers)
//             .await
//             .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-eddsa-keyrefresh: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-eddsa-keyrefresh: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let address = payload.address;
//     tracing::info!("handle-eddsa-keyrefresh: address {:?}", address);
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-eddsa-keyrefresh: party_vk {:?}", party_vk_hex);
//
//     let party_vk = storage
//         .get_party_sk(party_vk_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//
//     let party_enc_key_hex = hex::encode(&payload.party_enc_key);
//
//     tracing::info!(
//         "handle-eddsa-keyrefresh: party_enc_key_hex {:?}",
//         party_enc_key_hex
//     );
//
//     let party_enc_key = storage
//         .get_party_enc_key(party_enc_key_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_enc_key", err.into()))?;
//
//     let msg_relay = state.mux.connect(100);
//
//     let stats = Stats::alloc();
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let mut msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     let party_key = PartyKeys::from_keys(party_vk.clone(), party_enc_key.clone());
//
//     // There should be no setup in opts
//     tracing::debug!("No setup received. Checking message relay");
//
//     let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);
//
//     let mut setup = msg_relay
//         .recv(&msg_id, 10)
//         .await
//         .ok_or(ErrCode::Internal.pack_with_str("unable to connect to msg relay"))?;
//
//     tracing::debug!("setup received");
//
//     let setup =
//         schnorr_keygen::ValidatedSetup::decode(&mut setup, &instance, &setup_vk, party_key, |_, _, _| true)
//             .ok_or(ErrCode::Internal.pack_with_str("Cannot decode setup message"))?;
//
//     tracing::debug!("setup validated");
//
//     let key_share = storage
//         .get_eddsa_keyshare(format!("{}.keyshare", address))
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve keyshare", err.into()))?;
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     let seed = rand::random();
//
//     let new_share = tokio::select! {
//         _ = &mut deadline => {
//             return Err(ErrCode::DKRFail.pack_with_str("timeout"));
//         }
//
//         share = schnorr_keygen::run_refresh(setup, seed, key_share.into_with_lost_party_ids(payload.lost_party_ids.unwrap_or_default(), false), msg_relay) => {
//             share.map_err(|err| {
//                 return ErrCode::DKRFail.pack_with_cause("", err.into());
//             })?
//         }
//     };
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     let pk_vec = new_share.public_key.compress().to_bytes();
//     let pk_hex = hex::encode(pk_vec);
//
//     let share = bincode::encode_to_vec(&new_share, bincode::config::standard())
//         .map_err(|err| ErrCode::Internal.pack_with_cause("encode keyshare fail", err.into()))?;
//
//     storage
//         .put_keyshare(format!("{}.keyshare", pk_hex), share)
//         .await
//         .map_err(|err| ErrCode::Internal.pack_with_cause("Error upload file", err.into()))?;
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("eddsa-keyrefresh send_count: {}", stats.send_count);
//     tracing::info!("eddsa-keyrefresh send_size:  {}", stats.send_size);
//     tracing::info!("eddsa-keyrefresh recv_count: {}", stats.recv_count);
//     tracing::info!("eddsa-keyrefresh recv_size:  {}", stats.recv_size);
//     tracing::info!("eddsa-keyrefresh wait_time:  {:?}", stats.wait_time);
//
//     for (id, wait) in &stats.wait_times {
//         tracing::debug!(" - {:?} {:?}", id, wait);
//     }
//
//     tracing::info!("eddsa-keyrefresh total_time: {:?}", total_time);
//
//     let resp = Json(KeygenResponse {
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         public_key: pk_vec.to_vec(),
//         total_time,
//     });
//
//     Ok(resp)
// }
//
async fn handle_sign(
    _headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<SignResponse>, AppError> {
    let start = Instant::now();

    // let user_info = UserInfo::default();
    // // TODO: add later
    // let auth_disabled = auth_disabled();
    // if !auth_disabled {
    //     user_info = validate_user(headers)
    //         .await
    //         .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    // }

    // TODO: add later
    // let user_id = user_info.get_identity();
    // let in_blacklist = state.storage.is_in_blacklist(user_id.clone())?;
    // if in_blacklist {
    //     return Err(ErrCode::Forbidden.pack_with_str("You are in the blacklist, you can't sign"));
    // }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-sign: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-sign: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-sign: party_vk {:?}", party_vk_hex);

    let party_sk = Arc::new(
        storage
            .get_party_sk(party_vk_hex)
            .await
            .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?,
    );

    let msg_relay = state.mux.connect(100);
    let stats = Stats::alloc();

    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    tracing::debug!("msg_relay connected");

    tracing::debug!("Received sign setup as part of the POST request");
    tracing::debug!("Instance ID: {:?}", instance);

    let decoded = SignDecodedSetup::decode(instance, payload.setup_msg, &setup_vk).unwrap();

    let key_id = decoded.key_id();

    let keyshare = storage.get_keyshare(hex::encode(key_id)).await?;

    // Receive the ttl number and parse a Duration.
    let ttl: Duration = decoded.ttl;
    tracing::debug!("Time to live: {:?}", ttl);

    let validated_setup = SignValidatedSetup::from_decoded(decoded, party_sk.clone(), keyshare.into())
        .expect("Failed to construct ValidatedSetup");

    tracing::debug!("Setup constructed successfully");

    let deadline = tokio::time::sleep(ttl);
    tokio::pin!(deadline);

    tracing::debug!("validate setup msg ok");

    let seed = rand::random();

    let sign = tokio::select! {
        _ = &mut deadline => {
            let res =  Ok(());
             match res {
                Ok(_) => {
                    tracing::debug!("handle_failed_signature ok");
                }
                Err(_err) => {
                    return Err(ErrCode::DSGFail.pack_with_cause("handle_failed_signature", _err));
                }
            }
            return Err(ErrCode::DSGFail.pack_with_str("timeout"));
        }

        sign = sign::run(validated_setup, seed, msg_relay) => {
            match sign {
                Ok(sign) => {
                    sign
                }
                Err(err) => {
                    if let SignError::AbortProtocolAndBanParty(_) = err {
                        // TODO: Add later!
                        // _ = state.storage.append_to_blacklist(user_id.clone());
                        return Err(ErrCode::DSGFail.pack_with_str("add party to ban list"));
                    }else {
                        return Err(ErrCode::DSGFail.pack_with_cause("",err.into()));
                    }
                }
            }
        }
    };

    let total_time = start.elapsed().as_millis() as u32;

    let stats = stats.lock().unwrap();

    tracing::info!("stats {:?} {:?}", *stats, start.elapsed());

    Ok(Json(SignResponse {
        sign: sign.0.to_vec(),
        recid: sign.1.into(),
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        total_time,
        times: None,
    }))
}

async fn handle_eddsa_sign(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<SetupMsg>,
) -> Result<Json<SignResponse>, AppError> {
    let start = Instant::now();

    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    // TODO: add later
    // let user_id = user_info.get_identity();
    // let in_blacklist = state.storage.is_in_blacklist(user_id.clone())?;
    // if in_blacklist {
    //     return Err(ErrCode::Forbidden.pack_with_str("You are in the blacklist, you can't sign"));
    // }

    let instance_id_hex: String = hex::encode(&payload.instance);
    tracing::info!("handle-sign: inst {:?}", instance_id_hex);

    let instance: [u8; 32] = payload
        .instance
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
    let instance = InstanceId::from(instance);

    let setup_vk_hex: String = hex::encode(&payload.setup_vk);
    tracing::info!("handle-sign: setup_vk {:?}", setup_vk_hex);

    let setup_vk: [u8; 32] = payload
        .setup_vk
        .try_into()
        .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
    let setup_vk = VerifyingKey::from_bytes(&setup_vk)
        .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;

    let storage = &state.storage;

    let party_vk_hex = hex::encode(&payload.party_vk);

    tracing::info!("handle-sign: party_vk {:?}", party_vk_hex);

    let party_sk = Arc::new(
        storage
            .get_party_sk(party_vk_hex)
            .await
            .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?,
    );

    let msg_relay = state.mux.connect(100);
    let stats = Stats::alloc();

    let msg_relay = RelayStats::new(msg_relay, stats.clone());
    let msg_relay = BufferedMsgRelay::new(msg_relay);

    tracing::debug!("msg_relay connected");

    tracing::debug!("Received sign setup as part of the POST request");
    tracing::debug!("Instance ID: {:?}", instance);

    let decoded =
        schnorr_relay::setup::sign::DecodedSetup::decode(instance, payload.setup_msg, &setup_vk).unwrap();

    let key_id = decoded.key_id();

    let keyshare = storage.get_eddsa_keyshare(hex::encode(key_id)).await?;

    // Receive the ttl number and parse a Duration.
    let ttl: Duration = decoded.ttl;
    tracing::debug!("Time to live: {:?}", ttl);

    let validated_setup = SignSetupMsg::from_decoded(decoded, party_sk.clone(), keyshare.into())
        .expect("Failed to construct ValidatedSetup");

    tracing::debug!("Setup constructed successfully");

    let deadline = tokio::time::sleep(ttl);
    tokio::pin!(deadline);

    tracing::debug!("validate setup msg ok");

    let seed = rand::random();

    let sign = tokio::select! {
        _ = &mut deadline => {
            let res =  Ok(());
             match res {
                Ok(_) => {
                    tracing::debug!("handle_failed_signature ok");
                }
                Err(_err) => {
                    return Err(ErrCode::DSGFail.pack_with_cause("handle_failed_signature", _err));
                }
            }
            return Err(ErrCode::DSGFail.pack_with_str("timeout"));
        }

        sign = schnorr_relay::dsg::eddsa::run(validated_setup, seed, msg_relay) => {
            match sign {
                Ok(sign) => {
                    sign
                }
                Err(err) => {
                    if let ProtocolError::AbortProtocol(_) = err {
                        // TODO: Add later!
                        // _ = state.storage.append_to_blacklist(user_id.clone());
                        return Err(ErrCode::DSGFail.pack_with_str("add party to ban list"));
                    }else {
                        return Err(ErrCode::DSGFail.pack_with_cause("",err.into()));
                    }
                }
            }
        }
    };

    let total_time = start.elapsed().as_millis() as u32;

    let stats = stats.lock().unwrap();

    tracing::info!("stats {:?} {:?}", *stats, start.elapsed());

    Ok(Json(SignResponse {
        sign: sign.to_bytes().to_vec(),
        recid: 33,
        total_send: stats.send_size as u32,
        total_recv: stats.recv_size as u32,
        total_wait: stats.wait_time.as_millis() as u32,
        total_time,
        times: None,
    }))
}
//
// async fn handle_sign_custom(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<SignParams>,
// ) -> Result<Json<SignResponse>, AppError> {
//     let start = Instant::now();
//
//     // let mut user_info = UserInfo::default();
//     // let auth_disabled = true;
//     // if !auth_disabled {
//     //     user_info = validate_user(headers)
//     //         .await
//     //         .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     // }
//
//     // let user_id = user_info.get_identity();
//     // let in_blacklist = state.storage.is_in_blacklist(user_id.clone())?;
//     // if in_blacklist {
//     //     return Err(ErrCode::Forbidden.pack_with_str("You are in the blacklist, you can't sign"));
//     // }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-sign: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-sign: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-sign: party_vk {:?}", party_vk_hex);
//
//     let party_vk = storage
//         .get_party_sk(party_vk_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//
//     let msg_relay = state.mux.connect(100);
//     let stats = Stats::alloc();
//
//     let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);
//
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let mut msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     tracing::debug!("msg_relay connected");
//
//     let setup: sign::ValidatedSetup = match payload.opts {
//         Some(opts) => {
//             tracing::debug!("Received sign setup as part of the POST request");
//             tracing::debug!("Instance ID: {:?}", instance);
//
//             let given_setup = opts.setup;
//
//             let chain_path: DerivationPath = given_setup.chain_path();
//
//             let public_key = given_setup.public_key();
//             let auth_token = given_setup.auth_token();
//             let parties = given_setup.parties_verifying_keys();
//             let message = given_setup.message().clone();
//             let raw_message = given_setup.raw_message().clone();
//             let hash_algo = given_setup.hash_algo();
//
//             let setup = setup::sign::Setup::new(
//                 public_key,
//                 auth_token,
//                 chain_path,
//                 parties,
//                 hash_algo,
//                 message,
//                 raw_message,
//             );
//
//             tracing::debug!("Setup constructed successfully");
//
//             // Receive the ttl number and parse a Duration.
//             let ttl: Duration = Duration::from_secs(opts.ttl);
//             tracing::debug!("Time to live: {:?}", ttl);
//
//             // TODO: This needs to check that the current user requesting a signature is the owner of the keyshare!
//             let pk = hex::encode(given_setup.public_key().to_bytes());
//             let mut path = PathBuf::new();
//             path.push("./data");
//             let path = path.join(format!("{}.keyshare", &pk));
//
//             let bytes = std::fs::read(path).expect("Failed to decode bytes for my keyshare");
//
//             let (share, _) = bincode::decode_from_slice(&bytes, bincode::config::standard())
//                 .expect("Failed to decode keyshare");
//
//             let validated_setup = setup::sign::ValidatedSetup::new(
//                 instance,
//                 setup,
//                 party_vk.clone(),
//                 share,
//                 ttl,
//                 validate_setup_sign,
//             )
//             .expect("Failed to construct ValidatedSetup");
//
//             tracing::debug!("Produced a validated setup, i.e. the setup is VALID");
//
//             validated_setup
//         }
//         None => {
//             tracing::debug!("Checking message relay for setup message");
//
//             let mut setup = msg_relay
//                 .recv(&msg_id, 10)
//                 .await
//                 .ok_or(ErrCode::Internal.pack_with_str("unable connect to msg relay"))?;
//
//             tracing::debug!("setup received");
//
//             let setup: sign::ValidatedSetup = sign::ValidatedSetup::decode_async(
//                 &mut setup,
//                 &instance,
//                 &setup_vk,
//                 party_vk.clone(),
//                 |setup, _| async move {
//                     let pk = hex::encode(setup.public_key().to_bytes());
//
//                     tracing::debug!("retrieving keyshare {:?}", pk);
//
//                     let public_key = setup.public_key().to_encoded_point(false);
//                     let public_key = public_key.as_bytes();
//
//                     let hash = keccak256(&public_key[1..]);
//                     let address = Address::from_slice(&hash[12..]);
//                     let addr = format!("{}{}", "0x".to_string(), hex::encode(address.as_fixed_bytes()));
//
//                     // if !auth_disabled {
//                     //     match user_info.get_wallet_addresses() {
//                     //         Some(wallets) => {
//                     //             if !wallets.iter().any(|e| e.to_lowercase().eq(&addr)) {
//                     //                 tracing::debug!(
//                     //                     "user {:?} is not allowed to access {:?}",
//                     //                     user_info.get_identity(),
//                     //                     addr
//                     //                 );
//                     //                 return None;
//                     //             }
//                     //         }
//                     //         None => {
//                     //             return None;
//                     //         }
//                     //     }
//                     // }
//
//                     let share = storage.get_keyshare(format!("{}.keyshare", pk)).await.ok()?;
//
//                     Some(share)
//                 },
//                 validate_setup_sign,
//             )
//             .await
//             .ok_or(ErrCode::SetupFail.pack_with_str("decode setup msg failed"))?;
//
//             tracing::debug!("setup decoded");
//
//             setup
//         }
//     };
//     // Save the setup for later use
//     let setup_copy = setup.clone();
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     tracing::debug!("validate setup msg ok");
//
//     let seed = rand::random();
//
//     let sign = tokio::select! {
//         _ = &mut deadline => {
//             let res = handle_failed_signature(&setup_copy);
//             match res {
//                 Ok(_) => {
//                     tracing::debug!("handle_failed_signature ok");
//                 }
//                 Err(_err) => {
//                     return Err(ErrCode::DSGFail.pack_with_cause("handle_failed_signature", _err));
//                 }
//             }
//             return Err(ErrCode::DSGFail.pack_with_str("timeout"));
//         }
//
//         sign = sign::run(setup, seed, msg_relay) => {
//             match sign {
//                 Ok(sign) => {
//                     sign
//                 }
//                 Err(err) => {
//                     if let SignError::UpdateBanList(keyshare) = err {
//                         _ = save_keyshare(&state, &(*keyshare)).await;
//                         // _ = state.storage.append_to_blacklist(user_id.clone());
//                         return Err(ErrCode::DSGFail.pack_with_str("add party to ban list"));
//                     }else {
//                         return Err(ErrCode::DSGFail.pack_with_cause("",err.into()));
//                     }
//                 }
//             }
//         }
//     };
//
//     // This encompasses any actions that need to be done after we have done a signature.
//     match post_sign(&setup_copy, &sign) {
//         Ok(_) => {
//             tracing::debug!("post_sign ok");
//         }
//         Err(_err) => {
//             return Err(ErrCode::Internal.pack_with_cause("Error in post_sign: {:?}", _err));
//         }
//     }
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     let sign = sign.to_sign_recid_bytes().to_vec();
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("stats {:?} {:?}", *stats, start.elapsed());
//
//     Ok(Json(SignResponse {
//         sign,
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         total_time,
//         times: None,
//     }))
// }
//
// async fn handle_eddsa_sign(
//     headers: HeaderMap,
//     State(state): State<AppState>,
//     Json(payload): Json<SignParams>,
// ) -> Result<Json<SignResponse>, AppError> {
//     let start = Instant::now();
//
//     let mut user_info = UserInfo::default();
//     let auth_disabled = auth_disabled();
//     if !auth_disabled {
//         user_info = validate_user(headers)
//             .await
//             .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
//     }
//
//     let instance_id_hex: String = hex::encode(&payload.instance);
//     tracing::info!("handle-sign: inst {:?}", instance_id_hex);
//
//     let instance: [u8; 32] = payload
//         .instance
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("instance invalid"))?;
//     let instance = InstanceId::from(instance);
//
//     let setup_vk_hex: String = hex::encode(&payload.setup_vk);
//     tracing::info!("handle-sign: setup_vk {:?}", setup_vk_hex);
//
//     let setup_vk: [u8; 32] = payload
//         .setup_vk
//         .try_into()
//         .map_err(|_| ErrCode::SetupFail.pack_with_str("invalid setup_vk"))?;
//     let setup_vk = VerifyingKey::from_bytes(&setup_vk)
//         .map_err(|err| ErrCode::SetupFail.pack_with_cause("unable to decode setup_vk", err.into()))?;
//
//     let storage = &state.storage;
//
//     let party_vk_hex = hex::encode(&payload.party_vk);
//
//     tracing::info!("handle-sign: party_vk {:?}", party_vk_hex);
//
//     let party_vk = storage
//         .get_party_sk(party_vk_hex)
//         .map_err(|err| ErrCode::Internal.pack_with_cause("unable to retrieve party_sk", err.into()))?;
//
//     let msg_relay = state.mux.connect(100);
//
//     let msg_id = MsgId::new(&instance, setup_vk.as_bytes(), None, SETUP_MESSAGE_TAG);
//
//     let stats = Stats::alloc();
//
//     let msg_relay = RelayStats::new(msg_relay, stats.clone());
//     let mut msg_relay = BufferedMsgRelay::new(msg_relay);
//
//     let mut setup = msg_relay
//         .recv(&msg_id, 10)
//         .await
//         .ok_or(ErrCode::Internal.pack_with_str("unable connect to msg relay"))?;
//
//     tracing::debug!("recv setup msf ok");
//
//     let setup = schnorr_sign::ValidatedSetup::decode_async(
//         &mut setup,
//         &instance,
//         &setup_vk,
//         party_vk.clone(),
//         |setup, _| async move {
//             let pk = hex::encode(setup.public_key().compress().as_bytes());
//             let share = storage
//                 .get_eddsa_keyshare(format!("{}.keyshare", pk))
//                 .await
//                 .ok()?;
//             Some(share)
//         },
//         |_| true,
//     )
//     .await
//     .ok_or(ErrCode::SetupFail.pack_with_str("decode setup msg failed"))?;
//
//     let deadline = tokio::time::sleep(setup.ttl());
//     tokio::pin!(deadline);
//
//     tracing::debug!("validate setup msg ok");
//
//     let seed = rand::random();
//
//     let sign = tokio::select! {
//         _ = &mut deadline => {
//             return Err(ErrCode::DSGFail.pack_with_str("timeout"));
//         }
//
//         sign = schnorr_sign::run(setup, seed, msg_relay) => {
//             sign.map_err(|err| ErrCode::DSGFail.pack_with_cause("",err.into()))?
//         }
//     };
//
//     let total_time = start.elapsed().as_millis() as u32;
//
//     let sign = sign.to_bytes().to_vec();
//
//     let stats = stats.lock().unwrap();
//
//     tracing::info!("stats {:?} {:?}", *stats, start.elapsed());
//
//     Ok(Json(SignResponse {
//         sign,
//         total_send: stats.send_size as u32,
//         total_recv: stats.recv_size as u32,
//         total_wait: stats.wait_time.as_millis() as u32,
//         total_time,
//         times: None,
//     }))
// }

#[derive(Serialize)]
struct GenPartyResponse {
    party_vk: String,
}

#[axum::debug_handler]
async fn handle_party_keys(
    // headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<GenPartyResponse>, AppError> {
    // if !auth_disabled() {
    //     validate_user(headers)
    //         .await
    //         .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    // }

    let secret = {
        let mut rng = rand::thread_rng();
        rng.gen()
    };
    let setup_sk = SigningKey::from_bytes(&secret);
    let public_key = hex::encode(setup_sk.verifying_key().to_bytes());

    let storage = &state.storage;
    let _ = storage
        .put_party_sk(public_key.clone(), secret.to_vec())
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("unable to store party sk", err.into()))
        .unwrap();

    let response = GenPartyResponse { party_vk: public_key };

    Ok(Json(response))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PartyIdParams {
    keyshare_version: u8,
    public_key: String,
}

#[derive(Serialize)]
struct PartyIdResponse {
    party_id: u8,
}

async fn handle_party_id(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<PartyIdParams>,
) -> Result<Json<PartyIdResponse>, AppError> {
    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let storage = &state.storage;
    let keyshare_key = format!("{}.keyshare", payload.public_key);
    let party_id = match payload.keyshare_version {
        0 => {
            unreachable!()
            // let keyshare = storage
            //     .get_keyshare_v0(keyshare_key)
            //     .await
            //     .map_err(|err| ErrCode::Internal.pack_with_cause("", err.into()))?;
            // keyshare.party_id
        }
        _ => {
            let keyshare = storage
                .get_keyshare(keyshare_key)
                .await
                .map_err(|err| ErrCode::Internal.pack_with_cause("", err.into()))?;
            keyshare.party_id
        }
    };

    let response = PartyIdResponse { party_id };

    Ok(Json(response))
}

async fn handle_eddsa_party_id(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<PartyIdParams>,
) -> Result<Json<PartyIdResponse>, AppError> {
    if !auth_disabled() {
        validate_user(headers)
            .await
            .map_err(|err| ErrCode::AuthFail.pack_with_cause("", err.into()))?;
    }

    let storage = &state.storage;
    let keyshare_key = format!("{}.keyshare", payload.public_key);
    let keyshare = storage
        .get_eddsa_keyshare(keyshare_key)
        .await
        .map_err(|err| ErrCode::Internal.pack_with_cause("", err.into()))?;
    let party_id = keyshare.party_id();

    let response = PartyIdResponse { party_id };

    Ok(Json(response))
}

#[derive(Serialize)]
struct GenPartyEncKeyResponse {
    party_enc_key: String,
}

#[derive(Deserialize)]
struct WhitelistQuery {
    pk: String,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/v1/party-keys", post(handle_party_keys))
        // .route("/v1/party-enc-keys", post(handle_party_enc_key))
        .route("/v1/party-id", post(handle_party_id))
        .route("/v1/eddsa-party-id", post(handle_eddsa_party_id))
        .route("/v1/keygen", post(handle_keygen))
        .route("/v1/eddsa-keygen", post(handle_eddsa_keygen))
        .route("/v1/signgen", post(handle_sign))
        // .route("/v1/signgen-custom", post(handle_sign_custom))
        .route("/v1/eddsa-signgen", post(handle_eddsa_sign))
        .route("/v1/ecdsa-key-migration", post(handle_ecdsa_migration))
        .route("/v1/eddsa-key-migration", post(handle_eddsa_migration))
        .route("/v1/key-migration", post(handle_migration))
        // .route("/v1/key-refresh", post(handle_keyrefresh))
        // .route("/v1/eddsa-key-refresh", post(handle_eddsa_keyrefresh))
        .layer(CorsLayer::permissive())
        .layer(
            ServiceBuilder::new()
                // Handle errors from middleware
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .concurrency_limit(1024)
                .timeout(Duration::from_secs(500)), // 60
        )
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().level(Level::INFO)))
        .with_state(state)
}

fn auth_disabled() -> bool {
    let ret = env::var("AUTH_DISABLED");
    return match ret {
        Ok(val) => val == "true",
        Err(_) => false,
    };
}

pub async fn run(opts: flags::Serve) -> anyhow::Result<()> {
    let coord = opts.coordinator.unwrap();

    let msg_relay: MsgRelayClient = loop {
        if let Ok(relay) = MsgRelayClient::connect(Endpoint::new(coord.clone())).await {
            break relay;
        }
        tracing::info!("connect to {} failed, retry", &coord);
        tokio::time::sleep(Duration::new(3, 0)).await;
    };

    // let aws_client = AwsClient::new().await?;
    // TODO: add later
    // let gcs_client = GcpClient::new().await?;
    //
    // let cache = Cache::new();
    // let storage = GcpStorage::new(gcs_client, cache);
    //

    let storage: Box<dyn Storage + Send + Sync> = if let Some(path) = opts.storage {
        println!("Using FileStorage with path: {}", path.display());
        Box::new(FileStorage::new(path))
    } else {
        println!(
            "Using GcpStorage from '{}'",
            env::var("BUCKET_NAME").unwrap_or("default".to_string())
        );
        let gcs_client = GcpClient::new().await?;
        let cache = Cache::new();
        Box::new(GcpStorage::new(gcs_client, cache))
    };

    // // TODO: add later
    // let _ = match opts.party_key {
    //     Some(path) => match load_signing_key(path) {
    //         Ok(key) => {
    //             let public_key = hex::encode(key.verifying_key().to_bytes());
    //
    //             storage.put_party_sk(public_key.clone(), key.to_bytes().to_vec())
    //         }
    //         _ => Ok({}),
    //     },
    //     None => Ok({}),
    // };

    let state = Arc::new(Inner::new(MsgRelayMux::new(msg_relay), storage));
    let app = app(AppState(state));

    let listen = {
        if !opts.listen.is_empty() {
            opts.listen
        } else {
            vec![format!(
                "{}:{}",
                opts.host.unwrap_or(String::from("0.0.0.0")),
                opts.port.unwrap_or(8080)
            )]
        }
    };

    let mut servers = JoinSet::new();

    for addrs in &listen {
        for addr in addrs.to_socket_addrs()? {
            tracing::info!("listening on {}", addr);

            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

            let app = app.clone().into_make_service();
            servers.spawn(axum::serve(listener, app).into_future());
        }
    }

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("got SIGINT, exiting");
                break;
            }

            _ = sigterm.recv() => {
                tracing::info!("got SIGTERM, exiting");
                break;
            }

            listener = servers.join_next() => {
                if listener.is_none() {
                    break;
                }
            }
        };
    }

    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::timeout::error::Elapsed>() {
        return (StatusCode::REQUEST_TIMEOUT, Cow::from("request timed out"));
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("Unhandled internal error: {error}")),
    )
}

async fn save_keyshare(state: &Arc<Inner>, share: &Keyshare) -> anyhow::Result<()> {
    let pk_vec = share.key_id;
    let pk_hex = hex::encode(pk_vec);
    state
        .storage
        .put_keyshare(format!("{}.keyshare", pk_hex), share.as_slice().to_vec())
        .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn keygen_params() {}
}
