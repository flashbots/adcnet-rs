//! PRF-based blinding vectors.
//!
//! Two flavors of pad derivation, both keyed by `SHA3-256(round || secret)`'s
//! low 128 bits used as an AES-128-CTR key:
//! - [`derive_blinding_vector`]: produces a vector of field elements
//!   (`u64`, each `< p`) by rejection-sampling AES-CTR words and summing
//!   per-secret contributions in `F_p`.
//! - [`derive_xor_blinding_vector`]: produces a byte vector by XORing the
//!   per-secret keystreams.

use std::cell::RefCell;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::Block;
use sha3::{Digest, Sha3_256};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::fields::{add_mod_slice, P};
use super::types::SharedKey;

thread_local! {
    /// Reuse AES block storage across pad derivations on this thread.
    static KEYSTREAM_SCRATCH: RefCell<Vec<Block>> = const { RefCell::new(Vec::new()) };
}

/// Prepend a 1-byte domain tag to a shared secret. Used to derive
/// independent pads for different sub-protocols (e.g. `0u8` for field-additive
/// auction pads, `1u8` for XOR-additive message pads) from the same ECDH
/// secret.
pub fn domain_prefixed(secret: &SharedKey, domain: u8) -> SharedKey {
    let raw = secret.as_bytes();
    let mut buf = Vec::with_capacity(1 + raw.len());
    buf.push(domain);
    buf.extend_from_slice(raw);
    SharedKey::from_bytes(&buf)
}

/// `l[i] ^= r[i]` for `i in 0..min(l.len(), r.len())`.
///
/// Uses runtime-detected AVX2 on x86_64, with unaligned loads and a scalar tail.
/// Falls back to scalar XOR otherwise.
#[inline]
pub fn xor_inplace(l: &mut [u8], r: &[u8]) {
    let n = l.len().min(r.len());
    #[cfg(target_arch = "x86_64")]
    {
        if n >= 32 && std::is_x86_feature_detected!("avx2") {
            // SAFETY: feature-detected at runtime; bounds checked by `n`.
            unsafe { xor_inplace_avx2(&mut l[..n], &r[..n]) };
            return;
        }
    }
    xor_inplace_scalar(&mut l[..n], &r[..n]);
}

#[inline]
fn xor_inplace_scalar(l: &mut [u8], r: &[u8]) {
    debug_assert_eq!(l.len(), r.len());
    for (li, ri) in l.iter_mut().zip(r.iter()) {
        *li ^= *ri;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_inplace_avx2(l: &mut [u8], r: &[u8]) {
    use std::arch::x86_64::*;
    debug_assert_eq!(l.len(), r.len());
    let n = l.len();
    let lp = l.as_mut_ptr();
    let rp = r.as_ptr();
    let mut i = 0usize;
    while i + 128 <= n {
        let l0 = _mm256_loadu_si256(lp.add(i) as *const __m256i);
        let l1 = _mm256_loadu_si256(lp.add(i + 32) as *const __m256i);
        let l2 = _mm256_loadu_si256(lp.add(i + 64) as *const __m256i);
        let l3 = _mm256_loadu_si256(lp.add(i + 96) as *const __m256i);
        let r0 = _mm256_loadu_si256(rp.add(i) as *const __m256i);
        let r1 = _mm256_loadu_si256(rp.add(i + 32) as *const __m256i);
        let r2 = _mm256_loadu_si256(rp.add(i + 64) as *const __m256i);
        let r3 = _mm256_loadu_si256(rp.add(i + 96) as *const __m256i);
        _mm256_storeu_si256(lp.add(i) as *mut __m256i, _mm256_xor_si256(l0, r0));
        _mm256_storeu_si256(lp.add(i + 32) as *mut __m256i, _mm256_xor_si256(l1, r1));
        _mm256_storeu_si256(lp.add(i + 64) as *mut __m256i, _mm256_xor_si256(l2, r2));
        _mm256_storeu_si256(lp.add(i + 96) as *mut __m256i, _mm256_xor_si256(l3, r3));
        i += 128;
    }
    while i + 32 <= n {
        let lv = _mm256_loadu_si256(lp.add(i) as *const __m256i);
        let rv = _mm256_loadu_si256(rp.add(i) as *const __m256i);
        _mm256_storeu_si256(lp.add(i) as *mut __m256i, _mm256_xor_si256(lv, rv));
        i += 32;
    }
    while i < n {
        *lp.add(i) ^= *rp.add(i);
        i += 1;
    }
}

/// Field-element pad. Sums per-secret contributions in `F_p`.
pub fn derive_blinding_vector(shared_secrets: &[SharedKey], round: u32, n_els: usize) -> Vec<u64> {
    if shared_secrets.is_empty() {
        return vec![0u64; n_els];
    }
    #[cfg(feature = "parallel")]
    {
        if shared_secrets.len() >= 2 {
            return shared_secrets
                .par_iter()
                .map(|s| single_field_pad(s, round, n_els))
                .reduce(
                    || vec![0u64; n_els],
                    |mut acc, pad| {
                        add_mod_slice(&mut acc, &pad);
                        acc
                    },
                );
        }
    }
    let mut acc = vec![0u64; n_els];
    for s in shared_secrets {
        let pad = single_field_pad(s, round, n_els);
        add_mod_slice(&mut acc, &pad);
    }
    acc
}

// Accept an exact multiple of P so each residue has equally many preimages.
const FIELD_SAMPLE_THRESHOLD: u64 = (((1u128 << 64) / P as u128) * P as u128) as u64;

fn field_candidate(word: u64) -> Option<u64> {
    (word < FIELD_SAMPLE_THRESHOLD).then_some(word % P)
}

/// One secret's field pad, rejection-sampled from little-endian AES-CTR words.
fn single_field_pad(shared_secret: &SharedKey, round: u32, n_els: usize) -> Vec<u64> {
    let mut round_key_buf = Vec::with_capacity(4 + shared_secret.as_bytes().len());
    round_key_buf.extend_from_slice(&round.to_be_bytes());
    round_key_buf.extend_from_slice(shared_secret.as_bytes());

    let h = Sha3_256::digest(&round_key_buf);
    let key = GenericArray::from_slice(&h[..16]);
    let cipher = Aes128::new(key);

    let mut out = Vec::with_capacity(n_els);
    KEYSTREAM_SCRATCH.with(|cell| {
        let mut blocks = cell.borrow_mut();
        let mut counter = 0u64;
        while out.len() < n_els {
            let n_blocks = (n_els - out.len()).div_ceil(2);
            if blocks.len() < n_blocks {
                blocks.resize(n_blocks, Block::default());
            }
            for block in &mut blocks[..n_blocks] {
                let mut bytes = [0u8; 16];
                bytes[8..].copy_from_slice(&counter.to_be_bytes());
                *block = *GenericArray::from_slice(&bytes);
                counter += 1;
            }
            cipher.encrypt_blocks(&mut blocks[..n_blocks]);
            for word in blocks[..n_blocks].iter().flat_map(|b| b.chunks_exact(8)) {
                if let Some(value) = field_candidate(u64::from_le_bytes(word.try_into().unwrap())) {
                    out.push(value);
                    if out.len() == n_els {
                        break;
                    }
                }
            }
        }
    });
    out
}

/// AES-CTR keystream XORed into `res`, summed over all shared secrets.
pub fn derive_xor_blinding_vector(
    shared_secrets: &[SharedKey],
    round: u32,
    n_bytes: usize,
) -> Vec<u8> {
    if n_bytes == 0 || shared_secrets.is_empty() {
        return vec![0u8; n_bytes];
    }
    #[cfg(feature = "parallel")]
    {
        if shared_secrets.len() >= 2 {
            return shared_secrets
                .par_iter()
                .map(|s| single_xor_pad(s, round, n_bytes))
                .reduce(
                    || vec![0u8; n_bytes],
                    |mut acc, pad| {
                        xor_inplace(&mut acc, &pad);
                        acc
                    },
                );
        }
    }
    let mut acc = vec![0u8; n_bytes];
    for s in shared_secrets {
        let pad = single_xor_pad(s, round, n_bytes);
        xor_inplace(&mut acc, &pad);
    }
    acc
}

fn single_xor_pad(shared_secret: &SharedKey, round: u32, n_bytes: usize) -> Vec<u8> {
    let mut res = vec![0u8; n_bytes];
    let mut round_key_buf = Vec::with_capacity(4 + shared_secret.as_bytes().len());
    round_key_buf.extend_from_slice(&round.to_be_bytes());
    round_key_buf.extend_from_slice(shared_secret.as_bytes());

    let h = Sha3_256::digest(&round_key_buf);
    let key = GenericArray::from_slice(&h[..16]);
    let cipher = Aes128::new(key);

    let n_blocks = n_bytes.div_ceil(16);
    KEYSTREAM_SCRATCH.with(|cell| {
        let mut blocks = cell.borrow_mut();
        if blocks.len() < n_blocks {
            blocks.resize(n_blocks, Block::default());
        }
        for (idx, b) in blocks[..n_blocks].iter_mut().enumerate() {
            let mut buf = [0u8; 16];
            buf[8..16].copy_from_slice(&(idx as u64).to_be_bytes());
            *b = *GenericArray::from_slice(&buf);
        }
        cipher.encrypt_blocks(&mut blocks[..n_blocks]);
        let ks: &[u8] =
            unsafe { std::slice::from_raw_parts(blocks.as_ptr() as *const u8, n_blocks * 16) };
        res.copy_from_slice(&ks[..n_bytes]);
    });
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_blinding_self_inverse() {
        let s = SharedKey::from_bytes(&[1, 2, 3, 4]);
        let v1 = derive_xor_blinding_vector(std::slice::from_ref(&s), 7, 100);
        let mut v2 = v1.clone();
        xor_inplace(&mut v2, &derive_xor_blinding_vector(&[s], 7, 100));
        assert!(v2.iter().all(|&b| b == 0));
    }

    #[test]
    fn field_blinding_self_inverse() {
        let s = SharedKey::from_bytes(&[5, 6, 7, 8]);
        let a = derive_blinding_vector(std::slice::from_ref(&s), 3, 10);
        let b = derive_blinding_vector(&[s], 3, 10);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x, y);
        }
    }

    #[test]
    fn field_sampler_rejection_boundaries() {
        assert_eq!(field_candidate(0), Some(0));
        assert_eq!(field_candidate(P - 1), Some(P - 1));
        assert_eq!(field_candidate(P), Some(0));
        assert_eq!(field_candidate(FIELD_SAMPLE_THRESHOLD - 1), Some(P - 1));
        assert_eq!(field_candidate(FIELD_SAMPLE_THRESHOLD), None);
        assert_eq!(field_candidate(u64::MAX), None);
    }

    #[test]
    fn field_pad_matches_ctr_reference_and_preserves_prefixes() {
        use aes::cipher::{KeyIvInit, StreamCipher};

        let secret = SharedKey::from_bytes(&[37; 32]);
        let round = 123u32;
        let mut input = round.to_be_bytes().to_vec();
        input.extend_from_slice(secret.as_bytes());
        let digest = Sha3_256::digest(&input);
        let mut cipher = ctr::Ctr128BE::<Aes128>::new(
            GenericArray::from_slice(&digest[..16]),
            GenericArray::from_slice(&[0; 16]),
        );
        let mut stream = vec![0; 8192];
        cipher.apply_keystream(&mut stream);
        let words: Vec<_> = stream.chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap())).collect();
        assert!(words.iter().any(|&x| x >= FIELD_SAMPLE_THRESHOLD));
        let expected: Vec<_> = words.into_iter()
            .filter(|&x| x < FIELD_SAMPLE_THRESHOLD).map(|x| x % P).take(512).collect();
        assert_eq!(expected.len(), 512);
        assert!(expected.iter().any(|&x| x >= 1 << 56));
        for len in [0, 1, 2, 3, 7, 16, 127, 512] {
            assert_eq!(single_field_pad(&secret, round, len), expected[..len]);
        }
        assert_ne!(single_field_pad(&secret, round + 1, 16), expected[..16]);
    }

}
