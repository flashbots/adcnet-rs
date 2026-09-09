//! Cryptographic primitives: keys, signatures, ECDH, the prime field, and
//! PRF-based blinding vectors.

pub mod blinding;
pub mod encryption;
pub mod fields;
pub mod types;

pub use blinding::{derive_blinding_vector, derive_xor_blinding_vector, domain_prefixed, xor_inplace};
pub use encryption::{decrypt, encrypt, parse_encrypted_message, EncryptedMessage};
pub use fields::{P, PACK_BYTES, WIRE_BYTES};
pub use types::{
    generate_keypair, public_key_to_server_id, sign, verify,
    ExchangePrivateKey, ExchangePublicKey, KeyError, PrivateKey, PublicKey, ServerId, SharedKey,
    Signature,
};
