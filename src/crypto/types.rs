//! Key types, server IDs, signatures.
//!
//! Ed25519 signing via `ed25519-dalek`; P-256 key exchange via `p256`.

use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH,
};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{PublicKey as P256Pub, SecretKey as P256Sec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Ed25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(#[serde(with = "hex_bytes")] pub Vec<u8>);

impl PublicKey {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        Ok(Self(hex::decode(s)?))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// Ed25519 private key, stored in dalek's 64-byte expanded form `seed || pub`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrivateKey(#[serde(with = "hex_bytes")] pub Vec<u8>);

impl PrivateKey {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self(b.to_vec())
    }

    pub fn public_key(&self) -> Result<PublicKey, KeyError> {
        if self.0.len() < 64 {
            return Err(KeyError::InvalidPrivateKeySize);
        }
        Ok(PublicKey(self.0[32..64].to_vec()))
    }

    fn signing_key(&self) -> Result<SigningKey, KeyError> {
        if self.0.len() < SECRET_KEY_LENGTH {
            return Err(KeyError::InvalidPrivateKeySize);
        }
        let seed: [u8; SECRET_KEY_LENGTH] = self.0[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| KeyError::InvalidPrivateKeySize)?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

/// Generate a fresh Ed25519 keypair, returned in `(pubkey, privkey)` order.
pub fn generate_keypair() -> (PublicKey, PrivateKey) {
    let mut csprng = rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pub_bytes = sk.verifying_key().to_bytes().to_vec();
    let mut priv_bytes = Vec::with_capacity(64);
    priv_bytes.extend_from_slice(&sk.to_bytes());
    priv_bytes.extend_from_slice(&pub_bytes);
    (PublicKey(pub_bytes), PrivateKey(priv_bytes))
}

/// Ed25519 signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Signature(#[serde(with = "hex_bytes")] pub Vec<u8>);

impl Signature {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn sign(priv_key: &PrivateKey, data: &[u8]) -> Result<Signature, KeyError> {
    let sk = priv_key.signing_key()?;
    let sig = sk.sign(data);
    Ok(Signature(sig.to_bytes().to_vec()))
}

pub fn verify(pub_key: &PublicKey, data: &[u8], sig: &Signature) -> bool {
    let vk = match <[u8; 32]>::try_from(pub_key.as_bytes()) {
        Ok(b) => match VerifyingKey::from_bytes(&b) {
            Ok(vk) => vk,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    let s = match <[u8; 64]>::try_from(sig.as_bytes()) {
        Ok(b) => DalekSignature::from_bytes(&b),
        Err(_) => return false,
    };
    vk.verify(data, &s).is_ok()
}

/// Server identifier — non-zero u32 derived from a public key.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct ServerId(pub u32);

pub fn public_key_to_server_id(pk: &PublicKey) -> ServerId {
    let hash = Sha256::digest(pk.as_bytes());
    let id = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    ServerId(if id == 0 { 1 } else { id })
}

/// Maps server IDs to integer x-coordinates (1-indexed rank within the sorted
/// round ID set) for polynomial evaluation. `0` marks an ID not in `round_sids`.
pub fn server_ids_to_x_evals(round_sids: &[ServerId], available_sids: &[ServerId]) -> Vec<u64> {
    let mut ordered = round_sids.to_vec();
    ordered.sort();
    let mut res = vec![0u64; available_sids.len()];
    for (j, id1) in ordered.iter().enumerate() {
        for (k, id2) in available_sids.iter().enumerate() {
            if id1 == id2 {
                res[k] = (j + 1) as u64;
                break;
            }
        }
    }
    res
}

/// Symmetric DH shared secret used to derive blinding vectors.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SharedKey(#[serde(with = "hex_bytes")] pub Vec<u8>);

impl SharedKey {
    pub fn from_bytes(b: &[u8]) -> Self {
        Self(b.to_vec())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// --- P-256 ECDH wrappers ---------------------------------------------------

#[derive(Clone, Debug)]
pub struct ExchangePrivateKey(pub P256Sec);

#[derive(Clone, Debug)]
pub struct ExchangePublicKey(pub P256Pub);

impl ExchangePrivateKey {
    pub fn generate() -> Self {
        Self(P256Sec::random(&mut rand::rngs::OsRng))
    }
    pub fn public(&self) -> ExchangePublicKey {
        ExchangePublicKey(self.0.public_key())
    }
    pub fn ecdh(&self, other: &ExchangePublicKey) -> SharedKey {
        let shared = diffie_hellman(self.0.to_nonzero_scalar(), other.0.as_affine());
        SharedKey(shared.raw_secret_bytes().to_vec())
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, KeyError> {
        Ok(Self(P256Sec::from_slice(b).map_err(|_| KeyError::InvalidExchangeKey)?))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl ExchangePublicKey {
    /// Uncompressed SEC1 encoding (65 bytes for P-256).
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }
    pub fn from_sec1_bytes(b: &[u8]) -> Result<Self, KeyError> {
        let ep = p256::EncodedPoint::from_bytes(b).map_err(|_| KeyError::InvalidExchangeKey)?;
        let pk: Option<P256Pub> = P256Pub::from_encoded_point(&ep).into();
        Ok(Self(pk.ok_or(KeyError::InvalidExchangeKey)?))
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid private key size")]
    InvalidPrivateKeySize,
    #[error("invalid exchange key")]
    InvalidExchangeKey,
}

// --- serde helpers ---------------------------------------------------------

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            serde_bytes::Bytes::new(v).serialize(s)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            hex::decode(&s).map_err(serde::de::Error::custom)
        } else {
            let buf = serde_bytes::ByteBuf::deserialize(d)?;
            Ok(buf.into_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, b"hello").unwrap();
        assert!(verify(&pk, b"hello", &sig));
        assert!(!verify(&pk, b"world", &sig));
    }

    #[test]
    fn ecdh_agrees() {
        let a = ExchangePrivateKey::generate();
        let b = ExchangePrivateKey::generate();
        let ab = a.ecdh(&b.public());
        let ba = b.ecdh(&a.public());
        assert_eq!(ab.as_bytes(), ba.as_bytes());
    }
}
