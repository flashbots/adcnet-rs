//! ECIES (P-256 + AES-256-GCM) for sealed-envelope encryption between protocol
//! participants.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use super::types::{ExchangePrivateKey, ExchangePublicKey, KeyError};

#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub ephemeral_pubkey: Vec<u8>, // SEC1 uncompressed (65 bytes for P-256)
    pub nonce: Vec<u8>,            // 12 bytes
    pub ciphertext: Vec<u8>,       // includes 16-byte GCM tag
}

impl EncryptedMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ephemeral_pubkey.len() + self.nonce.len() + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_pubkey);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }
}

const PUBKEY_LEN: usize = 65;
const NONCE_LEN: usize = 12;

pub fn parse_encrypted_message(data: &[u8]) -> Result<EncryptedMessage, EncError> {
    let min_len = PUBKEY_LEN + NONCE_LEN + 16;
    if data.len() < min_len {
        return Err(EncError::TooShort);
    }
    Ok(EncryptedMessage {
        ephemeral_pubkey: data[..PUBKEY_LEN].to_vec(),
        nonce: data[PUBKEY_LEN..PUBKEY_LEN + NONCE_LEN].to_vec(),
        ciphertext: data[PUBKEY_LEN + NONCE_LEN..].to_vec(),
    })
}

fn derive_aes_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"adcnet-ecies-v1");
    h.update(shared_secret);
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

pub fn encrypt(recipient: &ExchangePublicKey, plaintext: &[u8]) -> Result<EncryptedMessage, EncError> {
    let ephemeral = ExchangePrivateKey::generate();
    let shared = ephemeral.ecdh(recipient);
    let key = derive_aes_key(shared.as_bytes());

    let cipher = Aes256Gcm::new((&key).into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ephemeral_pub = ephemeral.public().to_sec1_bytes();
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &ephemeral_pub })
        .map_err(|_| EncError::Aead)?;

    Ok(EncryptedMessage {
        ephemeral_pubkey: ephemeral_pub,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

pub fn decrypt(recipient_priv: &ExchangePrivateKey, msg: &EncryptedMessage) -> Result<Vec<u8>, EncError> {
    let eph_pub = ExchangePublicKey::from_sec1_bytes(&msg.ephemeral_pubkey)
        .map_err(EncError::Key)?;
    let shared = recipient_priv.ecdh(&eph_pub);
    let key = derive_aes_key(shared.as_bytes());

    let cipher = Aes256Gcm::new((&key).into());
    if msg.nonce.len() != NONCE_LEN {
        return Err(EncError::BadNonce);
    }
    let nonce = Nonce::from_slice(&msg.nonce);
    cipher
        .decrypt(nonce, Payload { msg: &msg.ciphertext, aad: &msg.ephemeral_pubkey })
        .map_err(|_| EncError::Aead)
}

#[derive(Debug, Error)]
pub enum EncError {
    #[error("encrypted message too short")]
    TooShort,
    #[error("aead error")]
    Aead,
    #[error("invalid nonce size")]
    BadNonce,
    #[error(transparent)]
    Key(#[from] KeyError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecies_roundtrip() {
        let sk = ExchangePrivateKey::generate();
        let pk = sk.public();
        let ct = encrypt(&pk, b"hello adcnet").unwrap();
        let pt = decrypt(&sk, &ct).unwrap();
        assert_eq!(pt, b"hello adcnet");
    }
}
