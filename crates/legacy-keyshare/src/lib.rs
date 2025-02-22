use std::{
    fmt::{self, Formatter},
    marker::PhantomData,
    ops::{Add, Deref, DerefMut, Mul},
};

use bincode::{
    de::{
        read::{BorrowReader, Reader},
        BorrowDecode, BorrowDecoder, Decoder,
    },
    enc::{write::Writer, Encoder},
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

use dkls23::keygen::key_refresh::KeyshareForRefresh;
use k256::{
    elliptic_curve::{
        generic_array::{ArrayLength, GenericArray},
        group::GroupEncoding,
        zeroize::{Zeroize, ZeroizeOnDrop},
        CurveArithmetic, FieldBytes, NonZeroScalar, PrimeField,
    },
    ProjectivePoint, Scalar,
};

use sl_mpc_mate::{ByteArray, SessionId};
use sl_oblivious::soft_spoken::{ReceiverOTSeed, SenderOTSeed};

pub const TOBI_ECDSA_PUBLIC_KEY: u16 = 70;
pub const TOBI_EDDSA_PUBLIC_KEY: u16 = 71;

pub mod schnorr;

/// Keyshare of a party.
#[derive(Clone, bincode::Encode, Zeroize, ZeroizeOnDrop)]
pub struct LegacyKeyshare {
    /// A marker
    pub magic: u32,

    /// Total number of parties
    pub total_parties: u8,

    /// Threshold value
    pub threshold: u8,

    /// Rank of each party
    pub rank_list: Vec<u8>,

    /// Party Id of the sender
    pub party_id: u8,

    /// Public key of the generated key.
    pub public_key: Opaque<ProjectivePoint, GR>,

    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],

    ///
    pub seed_ot_receivers: Vec<ReceiverOTSeed>, // N-1

    ///
    pub seed_ot_senders: Vec<SenderOTSeed>, // N-1

    /// Seed values sent to the other parties
    pub sent_seed_list: Vec<[u8; 32]>, // [0..N-1]

    /// Seed values received from the other parties
    pub rec_seed_list: Vec<[u8; 32]>, // [0..N-1]

    /// Final session ID
    pub final_session_id: Opaque<SessionId>,

    pub(crate) s_i: Opaque<Scalar, PF>,
    pub(crate) big_s_list: Vec<Opaque<ProjectivePoint, GR>>, // N
    pub(crate) x_i_list: Vec<Opaque<k256::NonZeroScalar, NZ>>, // N

    /// List of banned party-ids.
    /// If a party is banned, we will not accept any messages from that party.
    pub ban_list: Vec<u8>,
}

impl std::fmt::Debug for LegacyKeyshare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyshare")
            .field("magic", &self.magic)
            .field("party_id", &self.party_id)
            .field("public_key", &self.public_key)
            .field("ban_list", &self.ban_list)
            .finish()
    }
}

impl LegacyKeyshare {
    const MAGIC: u32 = 1u32;

    pub fn recovery_data(&self, lost_party_ids: Vec<u8>) -> KeyshareForRefresh {
        KeyshareForRefresh::new(
            self.rank_list.clone(),
            self.threshold,
            self.public_key.0,
            self.root_chain_code,
            Some(self.s_i.0),
            Some(self.x_i_list.clone().into_iter().map(|x_i| x_i.0).collect()),
            lost_party_ids,
            self.party_id,
        )
    }

    pub fn start_recovery_for_lost(
        lost_party_ids: Vec<u8>,
        threshold: u8,
        public_key: ProjectivePoint,
        rank_list: Vec<u8>,
        party_id: u8,
    ) -> KeyshareForRefresh {
        KeyshareForRefresh::from_lost_keyshare(rank_list, threshold, public_key, lost_party_ids, party_id)
    }
}

impl Decode for LegacyKeyshare {
    fn decode<D: bincode::de::Decoder>(decoder: &mut D) -> Result<Self, bincode::error::DecodeError> {
        let magic = u32::decode(decoder)?;
        if magic != LegacyKeyshare::MAGIC {
            return Err(DecodeError::Other("Invalid magic number for keyshare"));
        }

        let total_parties = u8::decode(decoder)?;
        let threshold = u8::decode(decoder)?;
        let rank_list = Vec::<u8>::decode(decoder)?;
        let party_id = u8::decode(decoder)?;
        let public_key = Opaque::<ProjectivePoint, GR>::decode(decoder)?;
        let root_chain_code = <[u8; 32]>::decode(decoder)?;
        let seed_ot_receivers = Vec::<ReceiverOTSeed>::decode(decoder)?;
        let seed_ot_senders = Vec::<SenderOTSeed>::decode(decoder)?;
        let sent_seed_list = Vec::<[u8; 32]>::decode(decoder)?;
        let rec_seed_list = Vec::<[u8; 32]>::decode(decoder)?;
        let final_session_id = Opaque::<SessionId>::decode(decoder)?;
        let s_i = Opaque::<Scalar, PF>::decode(decoder)?;
        let big_s_list = Vec::<Opaque<ProjectivePoint, GR>>::decode(decoder)?;
        let x_i_list = Vec::<Opaque<k256::NonZeroScalar, NZ>>::decode(decoder)?;

        // NOTE: If ban list is not present, then set it to an empty list
        // This is to maintain backward compatibility
        let ban_list = if let Ok(ban_list) = Vec::<u8>::decode(decoder) {
            ban_list
        } else {
            vec![]
        };

        Ok(LegacyKeyshare {
            magic,
            total_parties,
            threshold,
            rank_list,
            party_id,
            public_key,
            root_chain_code,
            seed_ot_receivers,
            seed_ot_senders,
            sent_seed_list,
            rec_seed_list,
            final_session_id,
            s_i,
            big_s_list,
            x_i_list,
            ban_list,
        })
    }
}

/// Wrapper to provide bincode serialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opaque<T, K = ()>(pub T, pub PhantomData<K>);

impl<Z, K> Zeroize for Opaque<Z, K>
where
    Z: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<K, R, T: Mul<R>> Mul<R> for Opaque<T, K> {
    type Output = T::Output;

    fn mul(self, rhs: R) -> T::Output {
        self.0.mul(rhs)
    }
}

impl<K, R, T: Add<R>> Add<R> for Opaque<T, K> {
    type Output = T::Output;

    fn add(self, rhs: R) -> T::Output {
        self.0.add(rhs)
    }
}

impl<T, K> Opaque<T, K> {
    pub fn from_inner<F: From<T>>(self) -> F {
        F::from(self.0)
    }
}

impl<T, K> From<T> for Opaque<T, K> {
    fn from(v: T) -> Self {
        Self(v, PhantomData)
    }
}

impl<T, K> Deref for Opaque<T, K> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, K> DerefMut for Opaque<T, K> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<U: ArrayLength<u8>> Encode for Opaque<GenericArray<u8, U>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }
}

impl<U: ArrayLength<u8>> Decode for Opaque<GenericArray<u8, U>> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = GenericArray::default();

        decoder.claim_bytes_read(U::USIZE)?;
        decoder.reader().read(array.as_mut())?;

        Ok(Opaque(array, PhantomData))
    }
}

impl<const N: usize> Encode for Opaque<[u8; N]> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }
}

impl<const N: usize> Decode for Opaque<[u8; N]> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = [0; N];

        decoder.claim_bytes_read(N)?;
        decoder.reader().read(&mut array)?;

        Ok(Opaque(array, PhantomData))
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<[u8; N]> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<const N: usize> Encode for Opaque<&[u8; N]> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0)
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<&'de [u8; N]> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let array = decoder.borrow_reader().take_bytes(N)?;

        Ok(Opaque(
            unsafe { &*(array.as_ptr() as *const [u8; N]) },
            PhantomData,
        ))
    }
}

impl<const N: usize> Encode for Opaque<ByteArray<N>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(&self.0)
    }
}

impl<const N: usize> Encode for Opaque<&ByteArray<N>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0)
    }
}

impl<const N: usize> Decode for Opaque<ByteArray<N>> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = [0; N];

        decoder.claim_bytes_read(N)?;
        decoder.reader().read(&mut array)?;

        Ok(Opaque(ByteArray(array), PhantomData))
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<ByteArray<N>> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<'de, const N: usize> BorrowDecode<'de> for Opaque<&'de ByteArray<N>> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let array = decoder.borrow_reader().take_bytes(N)?;

        Ok(Opaque(
            unsafe { &*(array.as_ptr() as *const ByteArray<N>) },
            PhantomData,
        ))
    }
}

impl<U: ArrayLength<u8>> Encode for Opaque<&GenericArray<u8, U>> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0)
    }
}

impl<'de, U: ArrayLength<u8>> BorrowDecode<'de> for Opaque<&'de GenericArray<u8, U>> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let array = decoder.borrow_reader().take_bytes(U::USIZE)?;

        Ok(Opaque(array.into(), PhantomData))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GR;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PFR;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NZ;

impl<T: GroupEncoding> Encode for Opaque<T, GR> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_bytes().as_ref())
    }
}

impl<T: PrimeField> Encode for Opaque<T, PF> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_repr().as_ref())
    }
}

impl<T: PrimeField> Encode for Opaque<&T, PFR> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.to_repr().as_ref())
    }
}

impl<C: CurveArithmetic> Encode for Opaque<NonZeroScalar<C>, NZ> {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.writer().write(self.0.as_ref().to_repr().as_ref())
    }
}

impl<T: GroupEncoding> Decode for Opaque<T, GR> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = T::Repr::default();

        decoder.reader().read(array.as_mut())?;

        let value = T::from_bytes(&array);

        if bool::from(value.is_some()) {
            Ok(Opaque(value.unwrap(), PhantomData))
        } else {
            Err(DecodeError::Other("bad group element"))
        }
    }
}

impl<T: PrimeField> Decode for Opaque<T, PF> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = T::Repr::default();

        decoder.reader().read(array.as_mut())?;

        let value = T::from_repr(array);

        if bool::from(value.is_some()) {
            Ok(Opaque(value.unwrap(), PhantomData))
        } else {
            Err(DecodeError::Other("bad group element"))
        }
    }
}

impl<C: CurveArithmetic> Decode for Opaque<NonZeroScalar<C>, NZ> {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let mut array = FieldBytes::<C>::default();

        decoder.reader().read(array.as_mut())?;

        let value = C::Scalar::from_repr(array).and_then(NonZeroScalar::new);

        if bool::from(value.is_some()) {
            Ok(Opaque(value.unwrap(), PhantomData))
        } else {
            Err(DecodeError::Other("bad group element"))
        }
    }
}

impl<'de, T: GroupEncoding> BorrowDecode<'de> for Opaque<T, GR> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<'de, T: PrimeField> BorrowDecode<'de> for Opaque<T, PF> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}

impl<'de, C: CurveArithmetic> BorrowDecode<'de> for Opaque<NonZeroScalar<C>, NZ> {
    fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
        Self::decode(decoder)
    }
}
