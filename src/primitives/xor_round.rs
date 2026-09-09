//! XOR-additive blinded broadcast over `Vec<u8>`.
//!
//! Carries the message round of the 2-round protocol. Plaintexts are raw bytes;
//! "summation" is XOR.

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::crypto::blinding::{derive_xor_blinding_vector, domain_prefixed, xor_inplace};
use crate::crypto::SharedKey;

use super::XOR_ROUND_DOMAIN;

/// XOR the per-secret PRF pads into `contents` in-place and return it.
pub fn client_blind(secrets: &[SharedKey], round: u32, mut contents: Vec<u8>) -> Vec<u8> {
    let prefixed = xor_prefixed(secrets);
    let pad = derive_xor_blinding_vector(&prefixed, round, contents.len());
    xor_inplace(&mut contents, &pad);
    contents
}

pub fn server_share(secrets: &[SharedKey], round: u32, len: usize) -> Vec<u8> {
    let prefixed = xor_prefixed(secrets);
    derive_xor_blinding_vector(&prefixed, round, len)
}

/// XOR every blinded client contribution into a caller-provided `dst`.
///
/// `dst.len()` must match each source length; `dst` is *not* pre-zeroed
/// (callers can extend a running aggregate).
///
/// With the `parallel` feature, `sources.len() >= 2 · n_threads` triggers a
/// `par_chunks` split: each chunk produces one partial XOR accumulator
/// (bounded `n_threads + 1` allocations), reducing predictably.
///
/// # Panics
/// Panics before modifying `dst` if any source length differs from `dst.len()`.
pub fn aggregate_clients_into(dst: &mut [u8], sources: &[&[u8]]) {
    assert!(sources.iter().all(|s| s.len() == dst.len()),
        "xor_round::aggregate_clients length mismatch");
    if sources.is_empty() {
        return;
    }
    #[cfg(feature = "parallel")]
    {
        let n_threads = rayon::current_num_threads().max(1);
        if sources.len() >= 2 * n_threads {
            let chunk_size = sources.len().div_ceil(n_threads);
            let partials: Vec<Vec<u8>> = sources
                .par_chunks(chunk_size)
                .map(|chunk| {
                    let mut acc = vec![0u8; dst.len()];
                    for c in chunk {
                        xor_inplace(&mut acc, c);
                    }
                    acc
                })
                .collect();
            for p in partials {
                xor_inplace(dst, &p);
            }
            return;
        }
    }
    for c in sources {
        xor_inplace(dst, c);
    }
}

/// Convenience wrapper that allocates `dst` once.
pub fn aggregate_clients(sources: &[&[u8]]) -> Vec<u8> {
    if sources.is_empty() {
        return Vec::new();
    }
    let mut dst = vec![0u8; sources[0].len()];
    aggregate_clients_into(&mut dst, sources);
    dst
}

/// XOR all server shares into the aggregate to recover the plaintext XOR-sum
/// of all client contributions.
///
/// # Panics
/// Panics if any share length differs from `agg.len()`.
pub fn combine_partials(agg: &[u8], partials: &[&[u8]]) -> Vec<u8> {
    assert!(partials.iter().all(|p| p.len() == agg.len()),
        "xor_round::combine_partials length mismatch");
    let mut out = agg.to_vec();
    for p in partials {
        xor_inplace(&mut out, p);
    }
    out
}

fn xor_prefixed(secrets: &[SharedKey]) -> Vec<SharedKey> {
    secrets
        .iter()
        .map(|s| domain_prefixed(s, XOR_ROUND_DOMAIN))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(s: &str) -> SharedKey {
        SharedKey::from_bytes(s.as_bytes())
    }

    #[test]
    fn single_client_single_server_roundtrip() {
        let s = shared("c1s1");
        let contents = b"hello adcnet world".to_vec();
        let blinded = client_blind(std::slice::from_ref(&s), 11, contents.clone());
        let share = server_share(&[s], 11, contents.len());
        let recovered = combine_partials(&blinded, &[&share]);
        assert_eq!(recovered, contents);
    }

    #[test]
    fn two_clients_two_servers_roundtrip() {
        let c1s1 = shared("c1s1");
        let c1s2 = shared("c1s2");
        let c2s1 = shared("c2s1");
        let c2s2 = shared("c2s2");

        let c1 = b"aaaaaaaaaaaa".to_vec();
        let c2 = b"bbbbbbbbbbbb".to_vec();

        let b1 = client_blind(&[c1s1.clone(), c1s2.clone()], 1, c1.clone());
        let b2 = client_blind(&[c2s1.clone(), c2s2.clone()], 1, c2.clone());
        let agg = aggregate_clients(&[&b1, &b2]);

        let s1 = server_share(&[c1s1, c2s1], 1, c1.len());
        let s2 = server_share(&[c1s2, c2s2], 1, c1.len());
        let recovered = combine_partials(&agg, &[&s1, &s2]);

        let expected: Vec<u8> = c1.iter().zip(c2.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn domain_separation_field_vs_xor() {
        // The same shared secret produces independent pads for the field- and
        // XOR-additive primitives.
        let s = shared("identical-secret");
        let xor_pad = server_share(std::slice::from_ref(&s), 0, 8);
        let field_pad = crate::primitives::field_round::server_share(&[s], 0, 1);
        let field_bytes = field_pad[0].to_le_bytes();
        assert_ne!(&xor_pad[..7], &field_bytes[..7]);
    }
    #[test]
    fn aggregate_rejects_mismatched_lengths_before_mutating() {
        for count in [2, 16] {
            for bad_len in [0, 3, 5] {
                let mut sources = vec![vec![1; 4]; count];
                sources[count - 1] = vec![1; bad_len];
                let slices: Vec<_> = sources.iter().map(Vec::as_slice).collect();
                let mut dst = vec![7; 4];
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    aggregate_clients_into(&mut dst, &slices);
                }));
                assert!(result.is_err());
                assert_eq!(dst, vec![7; 4]);
            }
        }
    }

    #[test]
    fn combine_rejects_mismatched_lengths() {
        for bad_len in [0, 3, 5] {
            let bad = vec![1; bad_len];
            assert!(std::panic::catch_unwind(|| {
                combine_partials(&[7; 4], &[&[1; 4], &bad]);
            }).is_err());
        }
    }

}
