//! Field-additive blinded broadcast over `Vec<u64>` (elements in `F_p`).
//!
//! Carries the auction round of the 2-round protocol and the IBLT-message
//! round of the 1-round protocol. Plaintexts are field elements in
//! [`crate::crypto::fields`].

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::crypto::blinding::{derive_blinding_vector, domain_prefixed};
use crate::crypto::fields::{add_mod_slice, sub_mod_slice};
use crate::crypto::SharedKey;

use super::FIELD_ROUND_DOMAIN;

/// Add the PRF pads from every peer-shared secret to `contents` in-place.
pub fn client_blind(secrets: &[SharedKey], round: u32, contents: Vec<u64>) -> Vec<u64> {
    blind_or_share(secrets, round, contents)
}

/// Compute this server's share for a round of length `len`.
pub fn server_share(secrets: &[SharedKey], round: u32, len: usize) -> Vec<u64> {
    let prefixed = field_prefixed(secrets);
    derive_blinding_vector(&prefixed, round, len)
}

/// Sum every blinded client contribution into a caller-provided `dst` (mod p).
///
/// `dst.len()` must match each source length; `dst` is *not* pre-zeroed, so
/// this can extend a running aggregate.
///
/// With the `parallel` feature, `sources.len() >= 2 · n_threads` triggers a
/// `par_chunks` split: each chunk produces one partial accumulator (bounded
/// `n_threads + 1` allocations per call), then partial accumulators reduce
/// sequentially into `dst`. Predictable allocation profile vs rayon's
/// fold-induced per-task accumulators.
pub fn aggregate_clients_into(dst: &mut [u64], sources: &[&[u64]]) {
    if sources.is_empty() {
        return;
    }
    #[cfg(feature = "parallel")]
    {
        let n_threads = rayon::current_num_threads().max(1);
        if sources.len() >= 2 * n_threads {
            let chunk_size = (sources.len() + n_threads - 1) / n_threads;
            let partials: Vec<Vec<u64>> = sources
                .par_chunks(chunk_size)
                .map(|chunk| {
                    let mut acc = vec![0u64; dst.len()];
                    for c in chunk {
                        debug_assert_eq!(c.len(), dst.len());
                        add_mod_slice(&mut acc, c);
                    }
                    acc
                })
                .collect();
            for p in partials {
                add_mod_slice(dst, &p);
            }
            return;
        }
    }
    for c in sources {
        debug_assert_eq!(c.len(), dst.len(), "field_round::aggregate_clients length mismatch");
        add_mod_slice(dst, c);
    }
}

/// Convenience wrapper that allocates `dst` once and returns it.
pub fn aggregate_clients(sources: &[&[u64]]) -> Vec<u64> {
    if sources.is_empty() {
        return Vec::new();
    }
    let mut dst = vec![0u64; sources[0].len()];
    aggregate_clients_into(&mut dst, sources);
    dst
}

/// Subtract every server share from `dst` (mod p). Caller supplies `dst`
/// already populated with the aggregate.
pub fn combine_partials_into(dst: &mut [u64], partials: &[&[u64]]) {
    for p in partials {
        debug_assert_eq!(
            p.len(),
            dst.len(),
            "field_round::combine_partials length mismatch"
        );
        sub_mod_slice(dst, p);
    }
}

/// Convenience wrapper: clone `agg` into a fresh `dst` then subtract partials.
pub fn combine_partials(agg: &[u64], partials: &[&[u64]]) -> Vec<u64> {
    let mut dst: Vec<u64> = agg.to_vec();
    combine_partials_into(&mut dst, partials);
    dst
}

fn blind_or_share(secrets: &[SharedKey], round: u32, mut contents: Vec<u64>) -> Vec<u64> {
    let prefixed = field_prefixed(secrets);
    let pad = derive_blinding_vector(&prefixed, round, contents.len());
    add_mod_slice(&mut contents, &pad);
    contents
}

fn field_prefixed(secrets: &[SharedKey]) -> Vec<SharedKey> {
    secrets
        .iter()
        .map(|s| domain_prefixed(s, FIELD_ROUND_DOMAIN))
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
        let contents = vec![42u64, 1729u64];
        let blinded = client_blind(std::slice::from_ref(&s), 7, contents.clone());
        let share = server_share(&[s], 7, contents.len());
        let recovered = combine_partials(&blinded, &[&share]);
        assert_eq!(recovered, contents);
    }

    #[test]
    fn two_clients_two_servers_roundtrip() {
        use crate::crypto::fields::add_mod;

        let c1s1 = shared("c1s1");
        let c1s2 = shared("c1s2");
        let c2s1 = shared("c2s1");
        let c2s2 = shared("c2s2");

        let len = 5;
        let c1 = vec![10u64; len];
        let c2 = vec![20u64; len];

        let b1 = client_blind(&[c1s1.clone(), c1s2.clone()], 3, c1.clone());
        let b2 = client_blind(&[c2s1.clone(), c2s2.clone()], 3, c2.clone());
        let agg = aggregate_clients(&[&b1, &b2]);

        let s1 = server_share(&[c1s1, c2s1], 3, len);
        let s2 = server_share(&[c1s2, c2s2], 3, len);
        let recovered = combine_partials(&agg, &[&s1, &s2]);

        let expected: Vec<u64> = c1.iter().zip(c2.iter()).map(|(&a, &b)| add_mod(a, b)).collect();
        assert_eq!(recovered, expected);
    }
}
