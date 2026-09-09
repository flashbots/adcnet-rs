//! Wire-level message types and the generic [`Signed<T>`] envelope.

use negacyclic_rings::ntt64::sub_mod;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{
    fields::{add_mod_slice, P},
    sign, verify, xor_inplace, KeyError, PrivateKey, PublicKey, ServerId, Signature,
};

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("non-canonical field element")]
    NonCanonicalFieldElement,
    #[error("signature not valid")]
    BadSignature,
    #[error("mismatching rounds")]
    MismatchingRounds,
    #[error("mismatching share servers")]
    MismatchingServers,
    #[error("mismatching message vector lengths in decryption messages")]
    MismatchingVectorLengths,
    #[error("message for incorrect round {got}, expected {expected}")]
    WrongRound { got: i64, expected: i64 },
    #[error("message for invalid server {0:?}")]
    InvalidServer(ServerId),
    #[error("no shared key with user {0}")]
    NoSharedKey(String),
    #[error("client not yet initialized")]
    ClientNotInitialized,
    #[error("another message already pending")]
    AlreadyPending,
    #[error("previous round broadcast not available")]
    NoPreviousBroadcast,
    #[error("unknown previous round")]
    UnknownPreviousRound,
    #[error("message cannot be nil")]
    NilMessage,
    #[error("message exceeds allocated slot: needed {needed}, available {available}")]
    MessageExceedsAllocatedSlot { needed: usize, available: usize },
    #[error("no partial-decryption messages supplied")]
    EmptyPartials,
    #[error("two partials carry the same server_id {0:?}")]
    DuplicatePartial(ServerId),
    #[error("duplicate submission from signer {0}")]
    DuplicateSubmission(String),
    #[error("partial-decryption inputs disagree on the original aggregate")]
    MismatchingAggregate,
    #[error("signed message claims server_id {claimed:?} but signer is unknown / wrong pubkey")]
    SignerIdentityMismatch { claimed: ServerId },
    #[error("no registered pubkey for server_id {0:?}")]
    UnknownPeerServer(ServerId),
    #[error("bincode error: {0}")]
    Bincode(String),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Iblt(#[from] crate::auction::iblt::IbltError),
}

impl ProtocolError {
    fn bincode(e: bincode::Error) -> Self {
        ProtocolError::Bincode(e.to_string())
    }
}

/// Serialize field vectors as little-endian bytes (`8 · N` bytes).
pub mod u64_vec_bytes {
    use crate::crypto::fields::P;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u64], s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = vec![0u8; v.len() * 8];
        for (i, &x) in v.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&x.to_le_bytes());
        }
        serde_bytes::Bytes::new(&bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
        let buf = serde_bytes::ByteBuf::deserialize(d)?;
        if buf.len() % 8 != 0 {
            return Err(serde::de::Error::custom("u64 vec bytes must be a multiple of 8"));
        }
        let mut out = Vec::with_capacity(buf.len() / 8);
        for chunk in buf.chunks_exact(8) {
            let arr: [u8; 8] = chunk.try_into().unwrap();
            let x = u64::from_le_bytes(arr);
            if x >= P {
                return Err(serde::de::Error::custom("non-canonical field element"));
            }
            out.push(x);
        }
        Ok(out)
    }
}

/// Generic signed envelope. The signature covers
/// `bincode::serialize(object) || pubkey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed<T> {
    pub public_key: PublicKey,
    pub signature: Signature,
    pub object: T,
}

impl<T: Serialize + for<'de> Deserialize<'de>> Signed<T> {
    /// Hash the bincode-serialized object and pubkey with BLAKE3 (32-byte
    /// digest), then sign that digest with Ed25519.
    pub fn new(priv_key: &PrivateKey, obj: T) -> Result<Self, ProtocolError> {
        let pubkey = priv_key.public_key()?;
        let digest = blake3_digest(&obj, &pubkey)?;
        let signature = sign(priv_key, digest.as_bytes())?;
        Ok(Self { public_key: pubkey, signature, object: obj })
    }

    /// Verify the signature and return references to the authenticated payload.
    pub fn recover(&self) -> Result<(&T, &PublicKey), ProtocolError> {
        let digest = blake3_digest(&self.object, &self.public_key)?;
        if !verify(&self.public_key, digest.as_bytes(), &self.signature) {
            return Err(ProtocolError::BadSignature);
        }
        Ok((&self.object, &self.public_key))
    }
}

fn blake3_digest<T: Serialize>(obj: &T, pubkey: &PublicKey) -> Result<blake3::Hash, ProtocolError> {
    let mut h = blake3::Hasher::new();
    bincode::serialize_into(&mut HasherWriter(&mut h), obj).map_err(ProtocolError::bincode)?;
    h.update(pubkey.as_bytes());
    Ok(h.finalize())
}

struct HasherWriter<'a>(&'a mut blake3::Hasher);
impl<'a> std::io::Write for HasherWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Per-round, per-client submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientRoundMessage {
    pub round_number: i64,
    pub all_server_ids: Vec<ServerId>,
    #[serde(with = "u64_vec_bytes")]
    pub auction_vector: Vec<u64>,
    #[serde(with = "serde_bytes")]
    pub message_vector: Vec<u8>,
}

/// Aggregator output (or single-client equivalent if aggregation is disabled).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedClientMessages {
    pub round_number: i64,
    pub all_server_ids: Vec<ServerId>,
    #[serde(with = "u64_vec_bytes")]
    pub auction_vector: Vec<u64>,
    #[serde(with = "serde_bytes")]
    pub message_vector: Vec<u8>,
    pub user_pks: Vec<PublicKey>,
}

impl AggregatedClientMessages {
    pub fn empty() -> Self {
        Self {
            round_number: 0,
            all_server_ids: Vec::new(),
            auction_vector: Vec::new(),
            message_vector: Vec::new(),
            user_pks: Vec::new(),
        }
    }

    /// Field-add the auction vectors, XOR the message vectors, and concatenate user PK lists.
    pub fn union_inplace(&mut self, o: &AggregatedClientMessages) -> Result<(), ProtocolError> {
        let empty = self.all_server_ids.is_empty()
            && self.auction_vector.is_empty()
            && self.message_vector.is_empty()
            && self.user_pks.is_empty();
        if !empty {
            if self.round_number != o.round_number {
                return Err(ProtocolError::MismatchingRounds);
            }
            if self.all_server_ids != o.all_server_ids {
                return Err(ProtocolError::MismatchingServers);
            }
            if self.auction_vector.len() != o.auction_vector.len()
                || self.message_vector.len() != o.message_vector.len()
            {
                return Err(ProtocolError::MismatchingVectorLengths);
            }
        }
        let mut seen = std::collections::HashSet::new();
        for pk in self.user_pks.iter().chain(&o.user_pks) {
            if !seen.insert(pk) {
                return Err(ProtocolError::DuplicateSubmission(pk.to_hex()));
            }
        }
        if self.auction_vector.iter().chain(&o.auction_vector)
            .any(|&x| x >= crate::crypto::fields::P)
        {
            return Err(ProtocolError::NonCanonicalFieldElement);
        }
        if empty {
            *self = o.clone();
            return Ok(());
        }

        add_mod_slice(&mut self.auction_vector, &o.auction_vector);
        xor_inplace(&mut self.message_vector, &o.message_vector);
        self.user_pks.extend_from_slice(&o.user_pks);
        Ok(())
    }
}

/// A server's partial-decryption share: contains its unblinding vectors plus
/// the aggregate they were derived from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerPartialDecryptionMessage {
    pub server_id: ServerId,
    pub original_aggregate: AggregatedClientMessages,
    pub user_pks: Vec<PublicKey>,
    #[serde(with = "u64_vec_bytes")]
    pub auction_vector: Vec<u64>,
    #[serde(with = "serde_bytes")]
    pub message_vector: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundBroadcast {
    pub round_number: i64,
    pub auction_vector: crate::auction::iblt::IbltVector,
    pub message_vector: Vec<u8>,
}

/// In-place field subtraction `a -= b` over the auction vector, mirroring
/// [`AggregatedClientMessages::union_inplace`]'s add semantics.
pub fn sub_assign_field(a: &mut [u64], b: &[u64]) {
    for (x, &y) in a.iter_mut().zip(b.iter()) {
        *x = sub_mod(*x, y, P);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::fields::P;

    fn batch(round: i64, client: u8) -> AggregatedClientMessages {
        AggregatedClientMessages {
            round_number: round,
            all_server_ids: vec![ServerId(1)],
            auction_vector: vec![1, 2],
            message_vector: vec![3, 4],
            user_pks: vec![PublicKey::from_bytes(&[client; 32])],
        }
    }

    #[test]
    fn union_preserves_round_zero_and_combines_vectors() {
        let mut a = AggregatedClientMessages::empty();
        let mut b = batch(0, 1);
        b.auction_vector[0] = P - 1;
        a.union_inplace(&b).unwrap();
        assert_eq!(bincode::serialize(&a).unwrap(), bincode::serialize(&b).unwrap());
        a.union_inplace(&batch(0, 2)).unwrap();
        assert_eq!(a.round_number, 0);
        assert_eq!(a.auction_vector, vec![0, 4]);
        assert_eq!(a.message_vector, vec![0, 0]);
        assert_eq!(a.user_pks.len(), 2);
        let before = bincode::serialize(&a).unwrap();
        assert!(matches!(a.union_inplace(&batch(1, 3)), Err(ProtocolError::MismatchingRounds)));
        assert_eq!(bincode::serialize(&a).unwrap(), before);
    }

    #[test]
    fn union_rejects_duplicate_members_without_mutation() {
        for mut a in [AggregatedClientMessages::empty(), batch(1, 1)] {
            let mut b = batch(1, 2);
            b.user_pks.push(b.user_pks[0].clone());
            let before = bincode::serialize(&a).unwrap();
            assert!(matches!(a.union_inplace(&b), Err(ProtocolError::DuplicateSubmission(_))));
            assert_eq!(bincode::serialize(&a).unwrap(), before);
        }
        let mut a = batch(1, 1);
        let before = bincode::serialize(&a).unwrap();
        assert!(matches!(a.union_inplace(&batch(1, 1)), Err(ProtocolError::DuplicateSubmission(_))));
        assert_eq!(bincode::serialize(&a).unwrap(), before);
    }

    #[test]
    fn union_rejects_invalid_shapes_and_elements_without_mutation() {
        for case in 0..5 {
            let mut a = batch(1, 1);
            let mut b = batch(1, 2);
            match case {
                0 => b.all_server_ids.push(ServerId(2)),
                1 => b.auction_vector.clear(),
                2 => a.message_vector.clear(),
                3 => b.auction_vector[0] = P,
                _ => a.auction_vector[0] = u64::MAX,
            }
            let before = bincode::serialize(&a).unwrap();
            let error = a.union_inplace(&b).unwrap_err();
            match case {
                0 => assert!(matches!(error, ProtocolError::MismatchingServers)),
                1 | 2 => assert!(matches!(error, ProtocolError::MismatchingVectorLengths)),
                _ => assert!(matches!(error, ProtocolError::NonCanonicalFieldElement)),
            }
            assert_eq!(bincode::serialize(&a).unwrap(), before);
        }
    }
}
