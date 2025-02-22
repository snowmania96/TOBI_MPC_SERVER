use elliptic_curve::{group::GroupEncoding, Group};
use schnorr_relay::multi_party_schnorr::curve25519_dalek::{EdwardsPoint, Scalar};

use super::*;

// Custom serde serializer
mod serde_point {
    use std::marker::PhantomData;

    use elliptic_curve::group::GroupEncoding;
    use serde::de::Visitor;

    pub fn serialize<S, G: GroupEncoding>(point: &G, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(G::Repr::default().as_ref().len())?;
        for byte in point.to_bytes().as_ref().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D, G: GroupEncoding>(deserializer: D) -> Result<G, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PointVisitor<G: GroupEncoding>(PhantomData<G>);

        impl<'de, G: GroupEncoding> Visitor<'de> for PointVisitor<G> {
            type Value = G;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a valid point in Edwards y + sign format")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<G, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut encoding = G::Repr::default();
                for (idx, byte) in encoding.as_mut().iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(idx, &"wrong length of point"))?;
                }

                Option::from(G::from_bytes(&encoding))
                    .ok_or(serde::de::Error::custom("point decompression failed"))
            }
        }

        deserializer.deserialize_tuple(G::Repr::default().as_ref().len(), PointVisitor(PhantomData))
    }
}

/// Keyshare of a party.
#[allow(unused)]
#[derive(Clone, bincode::Encode, bincode::Decode, Zeroize, ZeroizeOnDrop)]
pub struct Keyshare {
    /// Threshold value
    pub threshold: u8,
    /// Total number of parties
    pub total_parties: u8,
    /// Party Id of the sender
    pub party_id: u8,
    // pub(crate) x_i: Opaque<Scalar, PF>,
    // /// Participants rank
    // pub rank: u8,
    pub d_i: Opaque<Scalar, PF>,
    /// Public key of the generated key.
    pub public_key: Opaque<EdwardsPoint, GR>,
    pub(crate) big_a_poly: Vec<Opaque<EdwardsPoint, GR>>,
}

/// This struct is exact copy of multi-party-schnorr
/// Keyshare with field `party_id` and `d_i` public.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NewKeyshare<G>
where
    G: Group + GroupEncoding,
{
    /// Threshold value
    pub threshold: u8,
    /// Total number of parties
    pub total_parties: u8,
    /// Party Id of the sender
    pub party_id: u8,
    /// d_i, internal
    pub d_i: G::Scalar,
    /// Public key of the generated key.
    #[serde(with = "serde_point")]
    pub public_key: G,
    /// Key ID
    pub key_id: [u8; 32],
}

impl NewKeyshare<EdwardsPoint> {
    pub fn from_legacy(old: Keyshare, key_id: [u8; 32]) -> Self {
        Self {
            threshold: old.threshold,
            total_parties: old.total_parties,
            party_id: old.party_id,
            d_i: old.d_i.0,
            public_key: old.public_key.0,
            key_id,
        }
    }
}

pub fn load_schnorr_keyshare(data: &[u8]) -> Option<Keyshare> {
    let (share, _size) =
        bincode::decode_from_slice::<Keyshare, _>(&data, bincode::config::standard()).ok()?;

    Some(share)
}

#[cfg(test)]
mod tests {
    use super::*;

    // extracted from file legacy_keyshare_data/legacy_share1.json
    const OLD_SHARE: &str = "020300717749d9f829dcf0a17f561c612dcbdf04c508ee8eaabf64f11e63fc26e31f082403be50f401d712573ffa1333a8a18068b5c42b33ad58dc6d4e4fb2324dd68a022403be50f401d712573ffa1333a8a18068b5c42b33ad58dc6d4e4fb2324dd68aa6f3c4ba8232881abc1746d99f41e9074fc5ea0156443956853702a4ccf44314";

    #[test]
    fn decode() {
        let data: Vec<u8> = hex::decode(OLD_SHARE).unwrap();

        let (_share, size) =
            bincode::decode_from_slice::<Keyshare, _>(&data, bincode::config::standard()).unwrap();

        assert_eq!(size, data.len());

        assert!(load_schnorr_keyshare(&data).is_some());
    }
}
