#![allow(dead_code)]

use std::ops::Deref;

use crypto_secretbox::{
    aead::{Aead, KeyInit},
    XSalsa20Poly1305,
};

use rand::{distributions::Alphanumeric, Rng};
use sha2::digest::generic_array::GenericArray;

use crate::config;

const HEADER_SIZE: usize = 7;
pub(crate) const HEADER_PREFIX: &str = "tobi-v";

#[derive()]
pub enum EncryptDecryptor {
    // for none crypto
    V0(EncryptDecryptorV0),
    // use https://nacl.cr.yp.to/secretbox.html
    V1(EncryptDecryptorV1),
}

impl EncryptDecryptor {
    pub fn from(header: Option<&Vec<u8>>, params: &[String]) -> anyhow::Result<EncryptDecryptor> {
        let version: u8 = match header {
            Some(header) => {
                if header.len() < HEADER_SIZE {
                    0
                } else {
                    if HEADER_PREFIX.as_bytes().eq(&header[..HEADER_SIZE - 1]) {
                        header[HEADER_SIZE - 1] - '0' as u8
                    } else {
                        0
                    }
                }
            }
            None => config::INSTANCE.crypto_version,
        };

        return match version {
            0 => Ok(EncryptDecryptor::V0(EncryptDecryptorV0 {})),
            1 => {
                if params.len() < 1 {
                    Err(anyhow::anyhow!("Cryptoer params missing: v1(nonce)"))
                } else {
                    let nonce = params[0].clone();
                    Ok(EncryptDecryptor::V1(EncryptDecryptorV1 {
                        key: config::INSTANCE.crypto_v1_key.clone(),
                        nonce,
                    }))
                }
            }
            v => Err(anyhow::anyhow!("Cryptoer unsupported version: {}", v)),
        };
    }
}

impl Deref for EncryptDecryptor {
    type Target = dyn TEncryptDecryptor;

    fn deref(&self) -> &Self::Target {
        match self {
            EncryptDecryptor::V0(inner) => inner,
            EncryptDecryptor::V1(inner) => inner,
        }
    }
}

impl TEncryptDecryptor for EncryptDecryptor {
    fn version(&self) -> u8 {
        (&**self).version()
    }

    fn encrypt(&self, plain_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        (&**self).encrypt(plain_data)
    }

    fn decrypt(&self, cipher_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        (&**self).decrypt(cipher_data)
    }
}

pub trait TEncryptDecryptor {
    fn version(&self) -> u8;

    fn header(&self) -> Vec<u8> {
        let mut h = HEADER_PREFIX.as_bytes().to_vec();
        h.push('0' as u8 + self.version());
        h
    }

    fn should_upgrade_to_latest(&self) -> bool {
        self.version() < config::INSTANCE.crypto_version
    }

    fn encrypt(&self, plain_data: Vec<u8>) -> anyhow::Result<Vec<u8>>;

    fn decrypt(&self, cipher_data: Vec<u8>) -> anyhow::Result<Vec<u8>>;
}

pub struct EncryptDecryptorV0 {}

impl TEncryptDecryptor for EncryptDecryptorV0 {
    fn version(&self) -> u8 {
        0
    }

    fn encrypt(&self, plain_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(plain_data)
    }

    fn decrypt(&self, cipher_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        Ok(cipher_data)
    }
}

pub struct EncryptDecryptorV1 {
    key: String,
    nonce: String,
}

impl TEncryptDecryptor for EncryptDecryptorV1 {
    fn version(&self) -> u8 {
        1
    }

    fn encrypt(&self, plain_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let key = pad_string_to_length(&self.key, 32);
        let key = GenericArray::from_slice(key.as_bytes());
        let nonce = pad_string_to_length(&self.nonce, 24);
        let nonce = GenericArray::from_slice(nonce.as_bytes());
        let cipher = XSalsa20Poly1305::new(key);
        let ciphertext = cipher.encrypt(&nonce, plain_data.as_ref());
        match ciphertext {
            Ok(ciphertext) => {
                let mut ret: Vec<u8> = self.header().to_vec();
                ret.extend_from_slice(&ciphertext);
                Ok(ret)
            }
            Err(e) => Err(anyhow::format_err!("{}", e)),
        }
    }

    fn decrypt(&self, cipher_data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let cipher_data = cipher_data[HEADER_SIZE..].to_vec();
        let key = pad_string_to_length(&self.key, 32);
        let key = GenericArray::from_slice(key.as_bytes());
        let nonce = pad_string_to_length(&self.nonce, 24);
        let nonce = GenericArray::from_slice(nonce.as_bytes());
        let cipher = XSalsa20Poly1305::new(key);
        let plaintext = cipher.decrypt(&nonce, cipher_data.as_ref());
        match plaintext {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(anyhow::format_err!("{}", e)),
        }
    }
}

fn pad_string_to_length(input: &str, length: usize) -> String {
    if input.len() >= length {
        return format!("{}", &input[..length]);
    }
    let padding_length = length - input.len();
    let padding = "#".repeat(padding_length);
    format!("{}{}", input, padding)
}

fn random_string(min_length: usize, max_length: usize) -> String {
    let mut rng = rand::thread_rng();
    let length: usize = rng.gen_range(min_length..max_length);
    return rng
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
}

#[cfg(test)]
mod tests {
    use crate::crypto::{
        random_string, EncryptDecryptor, EncryptDecryptorV0, EncryptDecryptorV1, TEncryptDecryptor,
        HEADER_PREFIX,
    };

    #[test]
    fn test_crypto_v0() {
        use super::random_string;

        for _ in 0..100 {
            let plain_data = random_string(1, 100);

            let cryptoer = EncryptDecryptorV0 {};

            let cipher_data = cryptoer.encrypt(plain_data.as_bytes().to_vec()).unwrap();
            let output = cryptoer.decrypt(cipher_data).unwrap();
            assert_eq!(String::from_utf8(output).unwrap(), plain_data);
        }
    }

    #[test]
    fn test_crypto_v1() {
        use super::random_string;

        for _ in 0..100 {
            let plain_data = random_string(1, 100);

            let cryptoer = EncryptDecryptorV1 {
                key: random_string(1, 100),
                nonce: random_string(1, 100),
            };

            let cipher_data = cryptoer.encrypt(plain_data.as_bytes().to_vec()).unwrap();
            let output = cryptoer.decrypt(cipher_data).unwrap();
            assert_eq!(String::from_utf8(output).unwrap(), plain_data);
        }
    }

    #[ignore]
    #[test]
    fn test_get_cryptoer() {
        let cryptoer = EncryptDecryptor::from(None, &vec!["".to_string()]).unwrap();
        assert_eq!(1, cryptoer.version());

        let params = &vec!["".to_string()];

        let header = random_string(1, 100).as_bytes().to_vec();
        let cryptoer = EncryptDecryptor::from(Some(&header), params).unwrap();
        assert_eq!(0, cryptoer.version());

        let header = HEADER_PREFIX.as_bytes().to_vec();
        let cryptoer = EncryptDecryptor::from(Some(&header), params).unwrap();
        assert_eq!(0, cryptoer.version());

        let mut header = HEADER_PREFIX.as_bytes().to_vec();
        header.push(0);
        let cryptoer = EncryptDecryptor::from(Some(&header), params).unwrap();
        assert_eq!(0, cryptoer.version());

        let mut header = HEADER_PREFIX.as_bytes().to_vec();
        header.push(1);
        let cryptoer = EncryptDecryptor::from(Some(&header), params).unwrap();
        assert_eq!(1, cryptoer.version());

        let mut header = HEADER_PREFIX.as_bytes().to_vec();
        header.push(2);
        let cryptoer = EncryptDecryptor::from(Some(&header), params);
        assert!(cryptoer.is_err());
    }
}
