//! Wire-level message types and the generic [`Signed<T>`] envelope.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{
    fields::{add_mod_slice, sub_assign_mod},
    sign, verify, xor_inplace, KeyError, PrivateKey, PublicKey, ServerId, Signature,
};

#[derive(Debug, Error)]
pub enum ProtocolError {
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
    #[error("unauthorized client {0}")]
    Unauthorized(String),
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

/// Avoid `Vec<u64>` length-prefixed serde overhead by transporting the
/// vector as raw bytes (`8 · N` LE). Pub so session-level wire types can
/// reuse it.
pub mod u64_vec_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // `&Vec<u64>` (not `&[u64]`) is required by serde's `with` field binding.
    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(v: &Vec<u64>, s: S) -> Result<S::Ok, S::Error> {
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
            out.push(u64::from_le_bytes(arr));
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
        if self.round_number == 0 {
            self.round_number = o.round_number;
        } else if self.round_number != o.round_number {
            return Err(ProtocolError::MismatchingRounds);
        }

        if self.all_server_ids.is_empty() {
            self.all_server_ids = o.all_server_ids.clone();
        } else if self.all_server_ids != o.all_server_ids {
            return Err(ProtocolError::MismatchingServers);
        }

        if self.auction_vector.is_empty() {
            self.auction_vector = vec![0u64; o.auction_vector.len()];
        }
        if self.message_vector.is_empty() {
            self.message_vector = vec![0u8; o.message_vector.len()];
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
        sub_assign_mod(x, y);
    }
}
