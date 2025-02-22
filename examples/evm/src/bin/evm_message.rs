use dkls23::keygen::{gen_keyshares, Keyshare};
use dkls23::sign::{generate_sign, SignError};
use ethers::{
    signers::{to_eip155_v, Signer},
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Address, Signature, H256, U256,
    },
    utils::{hash_message, keccak256},
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::FieldBytes;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
#[tokio::main]
async fn main() {
    // Instantiate a Silent Wallet.
    // Silent wallet is a two party ECDSA signer.
    let signer = SilentWallet::<2, 3>::new(1).await;

    let message = "Hello World!";

    // Hash the message with the ethereum message prefix
    let message_hash = hash_message(message);
    println!("Message hash: {}", hex::encode(message_hash.as_ref()));

    // Sign the message
    let signature = signer.sign_message(message).await.unwrap();

    println!("Signature: {}", hex::encode(signature.to_vec()));

    // Recover the address from the signature
    let address = signature.recover(message).unwrap();

    assert!(address == signer.address);
}

/// 2-party signer used for signing/transactions on ethereum.
/// Used for demostration purposes only.
#[derive(Clone)]
pub struct SilentWallet<const T: usize, const N: usize> {
    /// The ethereum address of the signer
    pub address: Address,
    keyshares: Vec<Keyshare>,
    /// The chain id of the signer
    pub chain_id: u64,
}

impl<const T: usize, const N: usize> std::fmt::Debug for SilentWallet<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SilentWallet")
            .field("address", &self.address)
            .field(
                "public_key",
                &hex::encode(self.keyshares[0].public_key.to_encoded_point(true)),
            )
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl<const T: usize, const N: usize> SilentWallet<T, N> {
    /// Creates a new wallet with the given chain id
    pub async fn new(chain_id: u64) -> Self {
        let keyshares = gen_keyshares(T as u8, N as u8, None).await;

        let public_key = keyshares[0].public_key.to_encoded_point(false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);
        let address = Address::from_slice(&hash[12..]);

        Self {
            address,
            keyshares,
            chain_id,
        }
    }
}

#[async_trait::async_trait]
impl<const T: usize, const N: usize> Signer for SilentWallet<T, N> {
    type Error = SignError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<ethers::types::Signature, Self::Error> {
        let message = message.as_ref();
        let message_hash = hash_message(message);
        self.sign_hash(message_hash).await
    }

    async fn sign_transaction(
        &self,
        tx: &TypedTransaction,
    ) -> Result<ethers::types::Signature, Self::Error> {
        let mut tx_with_chain = tx.clone();
        if tx_with_chain.chain_id().is_none() {
            // in the case we don't have a chain_id, let's use the signer chain id instead
            tx_with_chain.set_chain_id(self.chain_id);
        }
        Ok(self.sign_transaction(&tx_with_chain).await)
    }

    async fn sign_typed_data<D: Eip712 + Send + Sync>(
        &self,
        payload: &D,
    ) -> Result<ethers::types::Signature, Self::Error> {
        // NOTE: Using unwrap here, in real setting, we should handle the error
        let encoded = payload.encode_eip712().unwrap();

        self.sign_hash(H256::from(encoded)).await
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn with_chain_id<I: Into<u64>>(self, chain_id: I) -> Self {
        Self {
            chain_id: chain_id.into(),
            ..self
        }
    }
}
impl<const T: usize, const N: usize> SilentWallet<T, N> {
    /// Synchronously signs the provided transaction, normalizing the signature `v` value with
    /// EIP-155 using the transaction's `chain_id`, or the signer's `chain_id` if the transaction
    /// does not specify one.
    pub async fn sign_transaction(&self, tx: &TypedTransaction) -> Signature {
        // rlp (for sighash) must have the same chain id as v in the signature
        let chain_id = tx.chain_id().map(|id| id.as_u64()).unwrap_or(self.chain_id);
        let mut tx = tx.clone();
        tx.set_chain_id(chain_id);

        let sighash = tx.sighash();
        let mut sig = self.sign_hash(sighash).await.unwrap();

        // sign_hash sets `v` to recid + 27, so we need to subtract 27 before normalizing
        sig.v = to_eip155_v(sig.v as u8 - 27, chain_id);
        sig
    }
    async fn sign_hash(&self, hash: H256) -> Result<ethers::types::Signature, SignError> {
        let mut rng = StdRng::from_entropy();
        // Choosing a random threshold number of keyshares
        let subset: Vec<Keyshare> = self
            .keyshares
            .choose_multiple(&mut rng, T)
            .cloned()
            .collect();

        let sign_with_recid =
            generate_sign(&subset, &"m".parse().unwrap(), hash.to_fixed_bytes().into()).await;

        let v = sign_with_recid.recid.to_byte() as u64 + 27;

        let r_bytes: FieldBytes<k256::Secp256k1> = sign_with_recid.sign.r().into();
        let s_bytes: FieldBytes<k256::Secp256k1> = sign_with_recid.sign.s().into();
        let r = U256::from_big_endian(r_bytes.as_slice());
        let s = U256::from_big_endian(s_bytes.as_slice());

        Ok(ethers::types::Signature { v, r, s })
    }
}
