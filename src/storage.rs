#![allow(dead_code)]

use std::env;

use axum::async_trait;

use k256::elliptic_curve::group::GroupEncoding;
use legacy_keyshare::{schnorr::NewKeyshare, LegacyKeyshare};
use sha2::Digest;

use crate::{cache::Cache, config, crypto::EncryptDecryptor};
use crypto_box::SecretKey;
// use dkls23::compat::keyshare::pre_v0::Keyshare as KeyshareV0;
use dkls23::keygen::Keyshare;
use ed25519_dalek::SigningKey;
use google_cloud_storage::{
    client::{google_cloud_auth::credentials::CredentialsFile, Client, ClientConfig},
    http::objects::{
        download::Range,
        get::GetObjectRequest,
        upload::{Media, UploadObjectRequest, UploadType},
    },
};

use schnorr_relay::multi_party_schnorr::curve25519_dalek::EdwardsPoint;

pub type EddsaKeyshare = schnorr_relay::multi_party_schnorr::keygen::Keyshare<EdwardsPoint>;

#[async_trait]
pub trait Storage {
    async fn put_keyshare(&self, key: String, data: Vec<u8>) -> anyhow::Result<()>;
    async fn get_keyshare(&self, key: String) -> anyhow::Result<Keyshare>;
    async fn put_party_sk(&self, key: String, data: Vec<u8>) -> anyhow::Result<()>;
    async fn get_party_sk(&self, key: String) -> anyhow::Result<SigningKey>;
    async fn get_eddsa_keyshare(&self, key: String) -> anyhow::Result<EddsaKeyshare>;
    async fn get_legacy_keyshare(&self, key: String) -> anyhow::Result<LegacyKeyshare>;
    async fn get_legacy_eddsa_keyshare(&self, key: String) -> anyhow::Result<EddsaKeyshare>;
}

pub type BoxedStorage = Box<dyn Storage + Send + Sync>;

pub struct GcpStorage {
    storage: GcpClient,
    cache: Cache,
}

impl GcpStorage {
    pub fn new(storage: GcpClient, cache: Cache) -> Self {
        Self { storage, cache }
    }
}

#[async_trait]
impl Storage for GcpStorage {
    async fn put_keyshare(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        let c = EncryptDecryptor::from(None, &[key.clone()])?;
        let data = c.encrypt(data)?;

        self.storage.put_keyshare(key.clone(), data.clone()).await?;

        let _ = self.cache.put_keyshare(key, data);

        Ok(())
    }

    async fn get_keyshare(&self, key: String) -> anyhow::Result<Keyshare> {
        let data = match self.cache.get_keyshare(key.clone()) {
            Ok(data) => Ok(data),
            Err(_) => {
                tracing::debug!("Load keyshare from redis failed.");
                match self.storage.get_keyshare(key.clone()).await {
                    Ok(data) => {
                        let _ = self.cache.put_keyshare(key.clone(), data.clone());
                        Ok(data)
                    }
                    Err(_) => Err(anyhow::anyhow!("Load keyshare from s3 failed.")),
                }
            }
        }?;

        let c = EncryptDecryptor::from(Some(&data), &[key.clone()])?;
        if c.should_upgrade_to_latest() {
            self.put_keyshare(key, data.clone()).await?;
        }
        let data = c.decrypt(data)?;

        // let (share, _) = bincode::decode_from_slice(&data, bincode::config::standard())?;
        Keyshare::from_vec(data).map_err(|_| anyhow::Error::msg("invalid keyshare"))
    }

    async fn get_eddsa_keyshare(&self, key: String) -> anyhow::Result<EddsaKeyshare> {
        let data = match self.cache.get_keyshare(key.clone()) {
            Ok(data) => Ok(data),
            Err(_) => {
                tracing::debug!("Load keyshare from redis failed.");
                match self.storage.get_keyshare(key.clone()).await {
                    Ok(data) => {
                        let _ = self.cache.put_keyshare(key.clone(), data.clone());
                        Ok(data)
                    }
                    Err(_) => Err(anyhow::anyhow!("Load keyshare from s3 failed.")),
                }
            }
        }?;

        let c = EncryptDecryptor::from(Some(&data), &[key.clone()])?;
        if c.should_upgrade_to_latest() {
            self.put_keyshare(key, data.clone()).await?;
        }
        let data = c.decrypt(data)?;

        let (share, _) = bincode::serde::decode_from_slice(&data, bincode::config::legacy())?;
        Ok(share)
    }

    async fn get_legacy_keyshare(&self, key: String) -> anyhow::Result<LegacyKeyshare> {
        let data = match self.cache.get_keyshare(key.clone()) {
            Ok(data) => Ok(data),
            Err(_) => {
                tracing::debug!("Load keyshare from redis failed.");
                match self.storage.get_keyshare(key.clone()).await {
                    Ok(data) => {
                        let _ = self.cache.put_keyshare(key.clone(), data.clone());
                        Ok(data)
                    }
                    Err(_) => Err(anyhow::anyhow!("Load keyshare from s3 failed.")),
                }
            }
        }?;

        let c = EncryptDecryptor::from(Some(&data), &[key.clone()])?;
        if c.should_upgrade_to_latest() {
            self.put_keyshare(key, data.clone()).await?;
        }
        let data = c.decrypt(data)?;
        let (share, _) = bincode::decode_from_slice(&data, bincode::config::standard())?;
        Ok(share)
    }

    // We load and immediately convert to latest format
    async fn get_legacy_eddsa_keyshare(&self, key: String) -> anyhow::Result<EddsaKeyshare> {
        let data = match self.cache.get_keyshare(key.clone()) {
            Ok(data) => Ok(data),
            Err(_) => {
                tracing::debug!("Load keyshare from redis failed.");
                match self.storage.get_keyshare(key.clone()).await {
                    Ok(data) => {
                        let _ = self.cache.put_keyshare(key.clone(), data.clone());
                        Ok(data)
                    }
                    Err(_) => Err(anyhow::anyhow!("Load keyshare from s3 failed.")),
                }
            }
        }?;

        let c = EncryptDecryptor::from(Some(&data), &[key.clone()])?;
        if c.should_upgrade_to_latest() {
            self.put_keyshare(key, data.clone()).await?;
        }
        let data = c.decrypt(data)?;
        let share: legacy_keyshare::schnorr::Keyshare =
            bincode::decode_from_slice(&data, bincode::config::standard())?.0;
        let key_id = sha2::Sha256::digest(&share.public_key.0.to_bytes()).into();
        let data = bincode::serde::encode_to_vec(
            NewKeyshare::from_legacy(share, key_id),
            bincode::config::legacy(),
        )?;

        let share = bincode::serde::decode_from_slice(&data, bincode::config::legacy())?.0;
        Ok(share)
    }

    // pub async fn get_keyshare_v0(&self, key: String) -> anyhow::Result<KeyshareV0> {
    //     let data = match self.cache.get_keyshare(key.clone()) {
    //         Ok(data) => Ok(data),
    //         Err(_) => {
    //             tracing::debug!("Load keyshare from redis failed.");
    //             self.storage.get_keyshare(key.clone()).await
    //         }
    //     }?;
    //
    //     let c = EncryptDecryptor::from(Some(&data), &[key.clone()])?;
    //     if c.should_upgrade_to_latest() {
    //         self.put_keyshare(key, data.clone()).await?;
    //     }
    //     let data = c.decrypt(data)?;
    //
    //     let (share, _) = bincode::decode_from_slice(&data, bincode::config::standard())?;
    //     return Ok(share);
    // }

    async fn put_party_sk(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        return self.cache.put_party_sk(key, data);
    }

    async fn get_party_sk(&self, key: String) -> anyhow::Result<SigningKey> {
        let bytes = self.cache.get_party_sk(key)?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
}

impl GcpStorage {
    fn put_party_enc_key(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        return self.cache.put_party_sk(key, data);
    }

    fn get_party_enc_key(&self, key: String) -> anyhow::Result<SecretKey> {
        let bytes = self.cache.get_party_sk(key)?;
        return Ok(SecretKey::from_bytes(bytes));
    }

    fn append_to_blacklist(&self, user_id: String) -> anyhow::Result<()> {
        self.cache.append_to_blacklist(user_id)
    }

    pub fn is_in_blacklist(&self, user_id: String) -> anyhow::Result<bool> {
        self.cache.is_in_blacklist(user_id)
    }
}

/// Aws struct#
#[derive(Debug, Clone)]
pub struct AwsClient {
    pub s3: aws_sdk_s3::Client,
    pub default_bucket: String,
}

impl AwsClient {
    pub async fn new() -> Result<AwsClient, anyhow::Error> {
        // need to put .aws files in the env
        let config = aws_config::load_from_env().await;
        let s3_client = aws_sdk_s3::Client::new(&config);
        let default_bucket = env::var("S3_DEFAULT_BUCKET")?;

        Ok(AwsClient {
            s3: s3_client,
            default_bucket: default_bucket.to_string(),
        })
    }
}

impl AwsClient {
    async fn put_keyshare(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        let bucket = &self.default_bucket;
        self.s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(Into::into(data))
            .send()
            .await?;

        Ok(())
    }

    async fn get_keyshare(&self, key: String) -> anyhow::Result<Vec<u8>> {
        let bucket = &self.default_bucket;

        let result = self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .response_content_type("application/json")
            .send()
            .await?;

        let bytes = result.body.collect().await?.into_bytes();

        tracing::debug!("Got the keyshare from aws S3.");

        Ok(bytes.to_vec())
    }
}

#[derive(Clone)]
pub struct GcpClient {
    pub gcs: Client,
    pub default_bucket: String,
}

impl GcpClient {
    pub async fn new() -> Result<GcpClient, anyhow::Error> {
        let credentials: CredentialsFile = CredentialsFile::new().await?;
        let config = ClientConfig::default()
            .with_credentials(credentials)
            .await
            .unwrap();

        let client = Client::new(config);
        let default_bucket = env::var("GCS_DEFAULT_BUCKET")?;

        Ok(GcpClient {
            gcs: client,
            default_bucket: default_bucket.to_string(),
        })
    }
}

impl GcpClient {
    async fn put_keyshare(&self, key: String, data: Vec<u8>) -> anyhow::Result<()> {
        let bucket = self.default_bucket.clone();

        let upload_type = UploadType::Simple(Media::new(key));
        self.gcs
            .upload_object(
                &UploadObjectRequest {
                    bucket,
                    ..Default::default()
                },
                data,
                &upload_type,
            )
            .await?;

        Ok(())
    }

    async fn get_keyshare(&self, key: String) -> anyhow::Result<Vec<u8>> {
        let bucket = self.default_bucket.clone();
        let result = self
            .gcs
            .download_object(
                &GetObjectRequest {
                    bucket,
                    object: key,
                    ..Default::default()
                },
                &Range::default(),
            )
            .await?;

        tracing::debug!("Got the keyshare from GCS.");

        Ok(result)
    }
}
