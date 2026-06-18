//! Multi-value Invertible Bloom Lookup Table over `F_p` (61-bit prime, see
//! [`crate::crypto::fields`]).
//!
//! Uniform `γ × δ` layout (γ=4 rows, δ=⌈1.5·n⌉ buckets per row, where `n` is
//! the expected element count). Each cell stores
//! `(counter, key, V_0 … V_{ξ-1})`:
//!
//! - **counter**: hit count. `counter == 1` marks a *pure* cell — decoding is
//!   driven by repeatedly peeling pure cells.
//! - **key**: one field element identifying the entry. Bucket placement is
//!   `SHA-256(row_be || key_bytes)[0..8] mod δ`. On peel, the key is
//!   recovered from the pure cell and used to recompute bucket positions so
//!   the entry can be subtracted from its other γ−1 rows.
//! - **V**: `ξ` extra field elements carried alongside. Bucket placement is
//!   driven by the key alone; V slots ride atomically with the key, so
//!   peeling recovers `(key, V_0..V_{ξ-1})` in one go.
//!
//! With ξ=0 the layout reduces to a classical IBLT (counter + key only),
//! useful when the key alone carries the data. With ξ>0 each cell carries
//! `(ξ+1) × PACK_BYTES` bytes of payload per insert.
//!
//! All cell components are `u64` field elements in `F_p` and accumulate via
//! modular addition, so an IBLT aggregates across clients using the
//! field-additive blinded-broadcast primitive.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto::fields::{add_assign_mod, from_le_bytes_packed, sub_assign_mod, to_le_bytes_packed, PACK_BYTES};

/// Number of rows in the IBLT. Fixed at 4 — the per-row peeling-probability
/// bound is `(load_factor)^(γ-2)`, so γ ≥ 2 is required and γ = 4 gives the
/// standard ~2.5× headroom margin at `IBLT_LOAD_FACTOR`.
pub const IBLT_GAMMA: usize = 4;

/// Buckets per row = `⌈IBLT_LOAD_FACTOR · n⌉` where `n` is the expected
/// element count. Load factor is **per row** (not total), so
/// `total_cells = γ · LOAD_FACTOR · n`.
///
/// For γ=4 the asymptotic peelability threshold (Eppstein–Goodrich–
/// Mitzenmacher) is `δ ≥ 1.295 · n`. We pick `1.5` for ~15% headroom over
/// that limit — generous enough to absorb expected variance in `N` without
/// inflating IBLT size more than needed.
pub const IBLT_LOAD_FACTOR: f64 = 1.5;

/// Bytes per IBLT key (one field element packed).
pub const KEY_BYTES: usize = PACK_BYTES;

/// Buckets-per-row for an estimated element count.
pub fn iblt_delta(estimated_elements: u32) -> usize {
    ((estimated_elements as f64) * IBLT_LOAD_FACTOR).ceil().max(1.0) as usize
}

/// Total field elements per encoded IBLT: `γ · δ · (2 + ξ)`.
/// (One counter, one key, ξ V slots per cell.)
pub fn iblt_field_element_count(estimated_elements: u32, xi: usize) -> usize {
    IBLT_GAMMA * iblt_delta(estimated_elements) * (2 + xi)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbltVector {
    pub estimated_elements: u32,
    pub gamma: usize,
    pub delta: usize,
    pub xi: usize,
    /// `γ × δ` counters, row-major (`counters[row * δ + col]`).
    pub counters: Vec<u64>,
    /// `γ × δ` key field elements, row-major.
    pub keys: Vec<u64>,
    /// `γ × δ × ξ` payload field elements: `values[(row * δ + col) * ξ + v]`.
    pub values: Vec<u64>,
}

impl IbltVector {
    /// New IBLT sized for `estimated_elements`, ξ=0 (classical IBLT layout).
    pub fn new(estimated_elements: u32) -> Self {
        Self::new_with_xi(estimated_elements, 0)
    }

    /// New IBLT with `xi` payload field elements per cell.
    pub fn new_with_xi(estimated_elements: u32, xi: usize) -> Self {
        let delta = iblt_delta(estimated_elements);
        let n_cells = IBLT_GAMMA * delta;
        Self {
            estimated_elements,
            gamma: IBLT_GAMMA,
            delta,
            xi,
            counters: vec![0u64; n_cells],
            keys: vec![0u64; n_cells],
            values: vec![0u64; n_cells * xi],
        }
    }

    #[inline]
    fn cell_idx(&self, row: usize, col: usize) -> usize {
        row * self.delta + col
    }

    #[inline]
    fn value_idx(&self, row: usize, col: usize, v: usize) -> usize {
        (row * self.delta + col) * self.xi + v
    }

    /// Insert a `(key, values)` tuple. `values.len()` must equal `self.xi`;
    /// each value slice must be ≤ `PACK_BYTES`.
    pub fn insert(
        &mut self,
        key: &[u8; KEY_BYTES],
        values: &[&[u8]],
    ) -> Result<(), IbltError> {
        if values.len() != self.xi {
            return Err(IbltError::PayloadArity {
                expected: self.xi,
                got: values.len(),
            });
        }
        for v in values {
            if v.len() > PACK_BYTES {
                return Err(IbltError::PayloadTooLarge {
                    got: v.len(),
                    cap: PACK_BYTES,
                });
            }
        }
        let key_el = from_le_bytes_packed(key);
        let value_els: Vec<u64> = values.iter().map(|b| from_le_bytes_packed(b)).collect();
        for row in 0..self.gamma {
            let col = chunk_index(key, row, self.delta);
            let ci = self.cell_idx(row, col);
            self.counters[ci] += 1;
            add_assign_mod(&mut self.keys[ci], key_el);
            for (v, &el) in value_els.iter().enumerate() {
                let vi = self.value_idx(row, col, v);
                add_assign_mod(&mut self.values[vi], el);
            }
        }
        Ok(())
    }

    /// Single-chunk insert (ξ=0 layout).
    pub fn insert_chunk(&mut self, msg: &[u8; KEY_BYTES]) {
        debug_assert_eq!(self.xi, 0, "insert_chunk requires xi=0; use insert for multi-V");
        self.insert(msg, &[]).expect("xi=0 arity");
    }

    /// Flatten cells into a single field-element vector for blinding.
    ///
    /// Layout: counters, keys, values, row-major. Length = `γ · δ · (2 + ξ)`.
    pub fn encode_as_field_elements(&self) -> Vec<u64> {
        let n_cells = self.gamma * self.delta;
        let mut out = Vec::with_capacity(n_cells * (2 + self.xi));
        out.extend_from_slice(&self.counters);
        out.extend_from_slice(&self.keys);
        out.extend_from_slice(&self.values);
        out
    }

    /// Inverse of [`Self::encode_as_field_elements`]. Verifies length; errors
    /// if the slice length disagrees with the IBLT's shape.
    pub fn decode_from_elements(&mut self, elements: &[u64]) -> Result<&mut Self, IbltError> {
        let n_cells = self.gamma * self.delta;
        let expected = n_cells * (2 + self.xi);
        if elements.len() != expected {
            return Err(IbltError::FieldElementCountMismatch {
                expected,
                got: elements.len(),
            });
        }
        self.counters.copy_from_slice(&elements[..n_cells]);
        self.keys.copy_from_slice(&elements[n_cells..2 * n_cells]);
        self.values.copy_from_slice(&elements[2 * n_cells..]);
        Ok(self)
    }

    /// Queue-based peeling. Returns recovered `(key, values)` tuples in
    /// arrival order. Errors if any cell remains non-zero after peeling
    /// drains.
    pub fn recover(&self) -> Result<Vec<RecoveredEntry>, IbltError> {
        let mut working = self.clone();
        let mut recovered: Vec<RecoveredEntry> = Vec::new();
        let mut queue: Vec<(usize, usize)> = Vec::new();

        for row in 0..working.gamma {
            for col in 0..working.delta {
                if working.counters[working.cell_idx(row, col)] == 1 {
                    queue.push((row, col));
                }
            }
        }

        let mut head = 0usize;
        while head < queue.len() {
            let (row, col) = queue[head];
            head += 1;
            let ci = working.cell_idx(row, col);
            if working.counters[ci] != 1 {
                continue;
            }
            let key_el = working.keys[ci];
            let key_bytes = to_le_bytes_packed(key_el);
            let mut value_els: Vec<u64> = Vec::with_capacity(working.xi);
            for v in 0..working.xi {
                value_els.push(working.values[working.value_idx(row, col, v)]);
            }
            let value_bytes: Vec<Vec<u8>> = value_els
                .iter()
                .map(|&e| to_le_bytes_packed(e).to_vec())
                .collect();
            recovered.push(RecoveredEntry {
                key: key_bytes,
                values: value_bytes,
            });

            for inner_row in 0..working.gamma {
                let inner_col = chunk_index(&key_bytes, inner_row, working.delta);
                let ici = working.cell_idx(inner_row, inner_col);
                if working.counters[ici] == 0 {
                    return Err(IbltError::UnexpectedZeroCounter);
                }
                sub_assign_mod(&mut working.keys[ici], key_el);
                for (v, &el) in value_els.iter().enumerate() {
                    let ivi = working.value_idx(inner_row, inner_col, v);
                    sub_assign_mod(&mut working.values[ivi], el);
                }
                working.counters[ici] -= 1;
                if working.counters[ici] == 1 {
                    queue.push((inner_row, inner_col));
                }
            }
        }

        for &c in &working.counters {
            if c != 0 {
                return Err(IbltError::PeelStalled);
            }
        }
        Ok(recovered)
    }
}

/// One recovered IBLT entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredEntry {
    pub key: [u8; KEY_BYTES],
    pub values: Vec<Vec<u8>>,
}

/// Bucket index for `chunk` at row `row`:
/// `SHA-256(row_be || chunk)[0..8] mod δ`. The row prefix is the 4-byte
/// big-endian encoding of `row`, allocation-free per call.
pub fn chunk_index(chunk: &[u8; KEY_BYTES], row: usize, delta: usize) -> usize {
    let mut h = Sha256::new();
    h.update((row as u32).to_be_bytes());
    h.update(chunk);
    let out = h.finalize();
    let seed = u64::from_be_bytes([
        out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
    ]);
    (seed % delta as u64) as usize
}

#[derive(Debug, Error)]
pub enum IbltError {
    #[error("unexpected zero counter while recovering IBLT")]
    UnexpectedZeroCounter,
    #[error("peeling stalled: cells remain non-zero with no pure cell")]
    PeelStalled,
    #[error("expected {expected} field elements, got {got}")]
    FieldElementCountMismatch { expected: usize, got: usize },
    #[error("payload arity mismatch: expected {expected}, got {got}")]
    PayloadArity { expected: usize, got: usize },
    #[error("payload slice of {got}B exceeds field-element cap of {cap}B")]
    PayloadTooLarge { got: usize, cap: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_recover_one_xi0() {
        let mut v = IbltVector::new(10);
        let chunk: [u8; KEY_BYTES] = [0x42, 0, 0, 0, 0, 0x99, 0];
        v.insert_chunk(&chunk);
        let r = v.recover().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].key, chunk);
        assert!(r[0].values.is_empty());
    }

    #[test]
    fn insert_recover_many_xi0() {
        let n: u32 = 20;
        let mut v = IbltVector::new(n);
        let mut chunks: Vec<[u8; KEY_BYTES]> = Vec::new();
        for i in 0..n as u8 {
            let mut c = [0u8; KEY_BYTES];
            c[0] = i + 1;
            c[1] = i + 2;
            v.insert_chunk(&c);
            chunks.push(c);
        }
        let mut recovered: Vec<[u8; KEY_BYTES]> =
            v.recover().unwrap().into_iter().map(|e| e.key).collect();
        recovered.sort();
        chunks.sort();
        assert_eq!(recovered, chunks);
    }

    #[test]
    fn insert_recover_with_values() {
        let xi = 3;
        let mut v = IbltVector::new_with_xi(8, xi);
        let key: [u8; KEY_BYTES] = [0xa, 0, 0, 0, 0, 0, 0];
        let v0 = [1u8; PACK_BYTES];
        let v1 = [2u8; PACK_BYTES];
        let v2 = [3u8; PACK_BYTES];
        v.insert(&key, &[&v0, &v1, &v2]).unwrap();
        let r = v.recover().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].key, key);
        assert_eq!(r[0].values.len(), 3);
        assert_eq!(r[0].values[0], v0);
        assert_eq!(r[0].values[1], v1);
        assert_eq!(r[0].values[2], v2);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut v = IbltVector::new(10);
        let a: [u8; KEY_BYTES] = [7, 0, 0, 0, 0, 0, 0];
        v.insert_chunk(&a);
        let els = v.encode_as_field_elements();
        let mut v2 = IbltVector::new(10);
        v2.decode_from_elements(&els).unwrap();
        let r = v2.recover().unwrap();
        assert!(r.iter().any(|e| e.key == a));
    }

    #[test]
    fn decode_wrong_length_errors() {
        let mut v = IbltVector::new(10);
        let err = v.decode_from_elements(&[0u64; 3]).unwrap_err();
        assert!(matches!(err, IbltError::FieldElementCountMismatch { .. }));
    }

    #[test]
    fn insert_arity_mismatch() {
        let mut v = IbltVector::new_with_xi(8, 2);
        let key = [0u8; KEY_BYTES];
        let v0 = [1u8; PACK_BYTES];
        let err = v.insert(&key, &[&v0]).unwrap_err();
        assert!(matches!(err, IbltError::PayloadArity { expected: 2, got: 1 }));
    }
}
