extern crate core;

use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod auth;
mod cache;
mod config;
mod crypto;
mod error;
mod flags;
mod serve;
mod slack;
mod storage;
mod trace;
mod utils;
mod validators;

use flags::{Dkls23Party, Dkls23PartyCmd};

/// Hash function used for signing.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum SignHashFn {
    /// Keccak256 hash function.
    Keccak256,

    /// SHA-256 hash function.
    Sha256,

    /// Double SHA-256 hash. SHA-256 is applied twice like in Bitcoin.
    Sha256D,

    /// Sign the message directly without hashing.
    /// The message must be 32 bytes long.
    NoHash,
}

///
#[derive(Debug)]
pub struct SignHashParseError(String);

impl FromStr for SignHashFn {
    type Err = SignHashParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "SHA256" => Ok(SignHashFn::Sha256),
            "SHA256D" => Ok(SignHashFn::Sha256D),
            "KECCAK256" => Ok(SignHashFn::Keccak256),
            "NONE" => Ok(SignHashFn::NoHash),

            _ => Err(SignHashParseError(String::from(s))),
        }
    }
}

impl std::fmt::Display for SignHashParseError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "SignHashParseError: {}", self.0)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let flags = Dkls23Party::from_env_or_exit();

    match flags.subcommand {
        Dkls23PartyCmd::Serve(opts) => serve::run(opts).await,
    }
}
