//! Encode payloads into an IBLT and decode payloads from the recovered
//! field-element vector. Each payload becomes one IBLT entry; multiple
//! payloads aggregate into a single IBLT via field-additive composition and
//! peel out atomically at the receiver.
//!
//! Payload framing inside one IBLT entry:
//!
//! ```text
//!   key   = PACK_BYTES random bytes (uniqueness; bucket-placement input)
//!   V[0..ξ-1] = length-prefixed payload, zero-padded
//!
//!   V[0][0..4] = (length as u32, big-endian)
//!   V[0][4..PACK_BYTES] || V[1] || … || V[ξ-1]  =  payload (length B) || zeros
//! ```
//!
//! `ξ = ⌈(max_payload_bytes + 4) / PACK_BYTES⌉` covers any payload up to
//! `max_payload_bytes`. Usable bytes per insert = `ξ · PACK_BYTES − 4`.

use rand::Rng;
use thiserror::Error;

use crate::auction::iblt::{IbltError, IbltVector, KEY_BYTES, RecoveredEntry};
use crate::crypto::fields::PACK_BYTES;

const LENGTH_PREFIX_BYTES: usize = 4;

#[derive(Clone, Debug)]
pub struct IbltMsgParams {
    /// Expected number of payloads per round. Determines IBLT bucket count.
    pub estimated_messages: u32,
    /// Maximum payload bytes per insert. Determines ξ.
    pub max_payload_bytes: usize,
}

impl IbltMsgParams {
    /// Field-element slots per cell.
    pub fn xi(&self) -> usize {
        (self.max_payload_bytes + LENGTH_PREFIX_BYTES).div_ceil(PACK_BYTES)
    }

    /// Usable payload bytes per insert.
    pub fn usable_payload_bytes(&self) -> usize {
        self.xi() * PACK_BYTES - LENGTH_PREFIX_BYTES
    }

    /// Construct an empty IBLT matching these params.
    pub fn empty_iblt(&self) -> IbltVector {
        IbltVector::new_with_xi(self.estimated_messages, self.xi())
    }

    /// Length of the encoded field-element vector for one round.
    pub fn encoded_len(&self) -> usize {
        crate::auction::iblt::iblt_field_element_count(self.estimated_messages, self.xi())
    }
}

#[derive(Debug, Error)]
pub enum IbltMsgError {
    #[error("payload of {got}B exceeds usable capacity {usable}B")]
    PayloadTooLarge { got: usize, usable: usize },
    #[error("recovered payload framing invalid: claimed length {claimed} > capacity {capacity}")]
    BadFraming { claimed: usize, capacity: usize },
    #[error("IBLT operation failed: {0}")]
    Iblt(#[from] IbltError),
}

/// Encode one payload into a fresh per-client IBLT and return its
/// field-element representation, ready for the field-additive primitive.
pub fn encode_payload<R: Rng>(
    params: &IbltMsgParams,
    payload: &[u8],
    rng: &mut R,
) -> Result<Vec<u64>, IbltMsgError> {
    if payload.len() > params.usable_payload_bytes() {
        return Err(IbltMsgError::PayloadTooLarge {
            got: payload.len(),
            usable: params.usable_payload_bytes(),
        });
    }

    let mut key = [0u8; KEY_BYTES];
    rng.fill_bytes(&mut key);

    let xi = params.xi();
    let cell_bytes = xi * PACK_BYTES;
    let mut framed = vec![0u8; cell_bytes];
    framed[0..LENGTH_PREFIX_BYTES].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    framed[LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + payload.len()].copy_from_slice(payload);

    let mut iblt = params.empty_iblt();
    let value_slices: Vec<&[u8]> = (0..xi)
        .map(|i| &framed[i * PACK_BYTES..(i + 1) * PACK_BYTES])
        .collect();
    iblt.insert(&key, &value_slices)?;
    Ok(iblt.encode_as_field_elements())
}

/// Encode an empty (zero) contribution.
pub fn encode_empty(params: &IbltMsgParams) -> Vec<u64> {
    params.empty_iblt().encode_as_field_elements()
}

/// Decode the recovered field-element vector back into the set of payloads
/// contributed this round.
pub fn decode_round(
    params: &IbltMsgParams,
    recovered: &[u64],
) -> Result<Vec<Vec<u8>>, IbltMsgError> {
    let mut iblt = params.empty_iblt();
    iblt.decode_from_elements(recovered)?;
    let entries = iblt.recover()?;
    entries.into_iter().map(|e| unframe(params, e)).collect()
}

fn unframe(params: &IbltMsgParams, e: RecoveredEntry) -> Result<Vec<u8>, IbltMsgError> {
    let mut flat = Vec::with_capacity(e.values.len() * PACK_BYTES);
    for v in &e.values {
        flat.extend_from_slice(v);
    }
    if flat.len() < LENGTH_PREFIX_BYTES {
        return Err(IbltMsgError::BadFraming {
            claimed: 0,
            capacity: flat.len(),
        });
    }
    let length = u32::from_be_bytes([flat[0], flat[1], flat[2], flat[3]]) as usize;
    if length > params.usable_payload_bytes() {
        return Err(IbltMsgError::BadFraming {
            claimed: length,
            capacity: params.usable_payload_bytes(),
        });
    }
    Ok(flat[LENGTH_PREFIX_BYTES..LENGTH_PREFIX_BYTES + length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn params(max_payload: usize, n_msgs: u32) -> IbltMsgParams {
        IbltMsgParams {
            estimated_messages: n_msgs,
            max_payload_bytes: max_payload,
        }
    }

    #[test]
    fn xi_sized_for_1kb() {
        let p = params(1024, 16);
        // ceil((1024+4)/7) = 147
        assert_eq!(p.xi(), 147);
        assert!(p.usable_payload_bytes() >= 1024);
    }

    #[test]
    fn one_payload_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let p = params(64, 4);
        let payload = b"hello adcnet one-round".to_vec();
        let encoded = encode_payload(&p, &payload, &mut rng).unwrap();
        assert_eq!(encoded.len(), p.encoded_len());
        let decoded = decode_round(&p, &encoded).unwrap();
        assert_eq!(decoded, vec![payload]);
    }

    #[test]
    fn many_payloads_via_field_aggregation() {
        use crate::primitives::field_round;

        let n: u32 = 8;
        let p = params(64, n);
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let mut all_encoded: Vec<Vec<u64>> = Vec::new();
        let mut expected: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let payload = format!("msg-{:02}-payload-contents", i).into_bytes();
            expected.push(payload.clone());
            let enc = encode_payload(&p, &payload, &mut rng).unwrap();
            all_encoded.push(enc);
        }
        let agg = field_round::aggregate_clients(
            &all_encoded.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
        );
        let mut decoded = decode_round(&p, &agg).unwrap();
        decoded.sort();
        expected.sort();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn payload_too_large_errors() {
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let p = params(16, 4);
        let too_big = vec![0u8; 100];
        let err = encode_payload(&p, &too_big, &mut rng).unwrap_err();
        assert!(matches!(err, IbltMsgError::PayloadTooLarge { .. }));
    }

    #[test]
    fn empty_contribution_is_neutral() {
        use crate::primitives::field_round;
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let p = params(32, 4);
        let payload = b"only-one-real-msg".to_vec();
        let real = encode_payload(&p, &payload, &mut rng).unwrap();
        let zero = encode_empty(&p);
        let agg = field_round::aggregate_clients(&[&real, &zero, &zero]);
        let decoded = decode_round(&p, &agg).unwrap();
        assert_eq!(decoded, vec![payload]);
    }
}
