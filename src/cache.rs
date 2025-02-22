#![allow(dead_code)]
// FIXME: this is seriois problem in future. Update redis?.
#![allow(dependency_on_unit_never_type_fallback)]

use ed25519_dalek::SigningKey;
use redis::{Client, Commands};
use std::env;

use crate::utils::load_signing_key;

const DEFAULT_KEYSHARE_TTL: usize = 24 * 60 * 60;

const KEY_BLACKLIST: &str = "blacklist";

pub struct Cache {
    client: Client,
    keyshare_key: Key,
    party_sk_key: Key,
}

impl Cache {
    pub fn new() -> Self {
        let redis_host = env::var("REDIS_HOST").expect("REDIS_HOST env var not set");
        let client = Client::open(redis_host).unwrap();
        let keyshare_key = Key::new("keyshare");
        let party_sk_key = Key::new("party_sk");
        Self {
            client,
            keyshare_key,
            party_sk_key,
        }
    }

    pub fn put_keyshare(&self, key: String, value: Vec<u8>) -> anyhow::Result<()> {
        let mut conn: redis::Connection = self.client.get_connection()?;
        let _: () = conn.set_ex(self.keyshare_key.make(key), value, DEFAULT_KEYSHARE_TTL)?;

        Ok(())
    }

    pub fn get_keyshare(&self, key: String) -> anyhow::Result<Vec<u8>> {
        let mut conn = self.client.get_connection()?;
        let key = self.keyshare_key.make(key);
        let value: Vec<u8> = conn.get(key.clone())?;

        // NOTICE!!!  if the key not exists, the return value is vec(0)
        if value.is_empty() {
            return Err(anyhow::Error::msg("redis key not found"));
        }

        conn.expire(key, DEFAULT_KEYSHARE_TTL)?;

        Ok(value)
    }

    pub fn put_party_sk(&self, key: String, value: Vec<u8>) -> anyhow::Result<()> {
        let mut conn = self.client.get_connection()?;
        let _: () = conn.set(self.party_sk_key.make(key), value)?;

        Ok(())
    }

    pub fn get_party_sk(&self, key: String) -> anyhow::Result<[u8; 32]> {
        tracing::info!("GETTING PARTY SK");
        let mut conn = self.client.get_connection()?;

        let value: Vec<u8> = conn.get(self.party_sk_key.make(key))?;
        let value: [u8; 32] = value
            .try_into()
            .map_err(|_| anyhow::Error::msg("invalid length of signing key file"))?;
        tracing::info!("GOT PARTY SK : {:?}", value);
        let sk = SigningKey::from_bytes(&value);
        tracing::info!("GOT PARTY VK : {:?}", hex::encode(sk.verifying_key().to_bytes()));

        Ok(value)
    }

    pub fn append_to_blacklist(&self, user_id: String) -> anyhow::Result<()> {
        let mut conn = self.client.get_connection()?;

        conn.sadd(KEY_BLACKLIST, user_id)?;

        Ok(())
    }

    pub fn is_in_blacklist(&self, user_id: String) -> anyhow::Result<bool> {
        let mut conn = self.client.get_connection()?;

        let x = conn.sismember(KEY_BLACKLIST, user_id)?;

        Ok(x)
    }
}

struct Key {
    prefix: &'static str,
}

impl Key {
    fn new(prefix: &'static str) -> Self {
        return Self { prefix };
    }
    fn make(&self, k: String) -> String {
        return format!("{}:{}", self.prefix, k);
    }
}
