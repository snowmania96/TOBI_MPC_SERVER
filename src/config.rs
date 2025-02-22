#![allow(dead_code)]

use anyhow::{Error, Ok};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref INSTANCE: ConfigData = ConfigData::load().unwrap();
}

pub struct ConfigData {
    pub threshold: u8,
    pub party_count: u8,
    pub crypto_version: u8,
    pub crypto_v1_key: String,
    pub slack_token: String,
    pub gcp_credentials_json: String,
}

impl ConfigData {
    pub fn load() -> Result<ConfigData, Error> {
        let threshold = std::env::var("THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);

        let party_count = std::env::var("PARTY_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let crypto_version = std::env::var("CRYPTO_VERSION")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let crypto_v1_key = std::env::var("CRYPTO_V1_KEY").ok().unwrap_or("tobi".to_string());
        let slack_token = std::env::var("SLACK_TOKEN").ok().unwrap_or("tobi".to_string());
        let gcp_credentials_json: String =
            std::env::var("GOOGLE_APPLICATION_CREDENTIALS_JSON").ok().unwrap_or("".to_string());
        return Ok(ConfigData {
            threshold,
            party_count,
            crypto_version,
            crypto_v1_key,
            slack_token,
            gcp_credentials_json,
        });
    }
}
