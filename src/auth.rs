#![allow(dead_code)]

use anyhow::anyhow;
use std::env;

use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::{decode, Algorithm};

use serde::Deserialize;
use serde::Serialize;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct UserInfo {
    id: String,
    telegram_id: i64,
    username: Option<String>,
    wallet_addresses: Option<Vec<String>>,
}

impl UserInfo {
    /// Private function that should be used for testing purpose
    /// UserInfo should never be initialized by this party
    fn new(
        id: String,
        telegram_id: i64,
        username: Option<String>,
        wallet_addresses: Option<Vec<String>>,
    ) -> Self {
        Self {
            id,
            telegram_id,
            username,
            wallet_addresses,
        }
    }
    pub fn get_wallet_addresses(&self) -> Option<Vec<String>> {
        return self.wallet_addresses.clone();
    }

    pub fn get_identity(&self) -> String {
        return self.id.clone();
    }

    pub fn get_abstraction(&self) -> String {
        return format!(
            "{}:{}:{}",
            self.id,
            self.telegram_id,
            self.username.clone().unwrap_or_default()
        );
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    jti: String,
    sub: String,
    iss: String,
    user: UserInfo,
    iat: usize,
    exp: usize, // exp is a UNIX timestamp
}

use axum::http::HeaderMap;

use crate::trace;

pub async fn validate_user(headers: HeaderMap) -> anyhow::Result<UserInfo> {
    let authorization_header = match headers.get("Authorization") {
        Some(header) => header,
        None => return Err(anyhow!("Missing Authorization Header")),
    };

    let auth_token = authorization_header.to_str()?;
    let auth_token = auth_token.replace("Bearer ", "");

    let secret_key = env::var("JWT_PUBLIC_KEY")?;

    let decoding_key = DecodingKey::from_rsa_pem(secret_key.as_bytes())?;
    let validation = Validation::new(Algorithm::RS256);
    let claims = decode::<Claims>(&auth_token, &decoding_key, &validation)?.claims;

    tracing::debug!("User wallet: {:?}", claims.user.wallet_addresses);
    trace::record_ctx(claims.user.get_abstraction());

    Ok(claims.user)
}

// pub async fn validate_user(
//     _headers: HeaderMap,
// ) -> anyhow::Result<UserInfo> {
//     Ok(UserInfo::new(
//         "1".to_string(),
//         1,
//         Some(vec!["0x".to_string()]),
//     ))
// }
