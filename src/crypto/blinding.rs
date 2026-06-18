//! PRF-based blinding vectors.
//!
//! Two flavors of pad derivation, both keyed by `SHA3-256(round || secret)`'s
//! low 128 bits used as an AES-128-CTR key:
//! - [`derive_blinding_vector`]: produces a vector of field elements
//!   (`u64`, each `< p`) by chunking the AES-CTR keystream into
//!   [`PACK_BYTES`]-byte windows and summing per-secret contributions in `F_p`.
//! - [`derive_xor_blinding_vector`]: produces a byte vector by XORing the
//!   per-secret keystreams.
//!
//! [`PACK_BYTES`]: super::fields::PACK_BYTES

use std::cell::RefCell;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::Block;
use sha3::{Digest, Sha3_256};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::fields::{add_mod_slice, from_le_bytes_packed, PACK_BYTES};
use super::types::SharedKey;

thread_local! {
    /// Reusable AES-CTR keystream buffer. Grows monotonically; avoids ~`N · 600
    /// KiB` of fresh allocations per `derive_blinding_vector` call.
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
/// On x86_64 with AVX2 detected at runtime, uses 32-byte VPXOR via
/// `_mm256_xor_si256` for the bulk of the buffer and a scalar tail. The
/// pointer loads/stores are unaligned because the buffers come from arbitrary
/// `Vec<u8>` allocations; `vpxor`'s memory-operand form handles that with no
/// penalty on any AVX2 µarch.
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

/// One secret's worth of the field-additive blinding pad. Reads `PACK_BYTES`
/// bytes per element from the AES-CTR keystream; values are `< 2^56 < p`.
///
/// Uses a thread-local keystream scratch buffer to avoid `O(N)` allocations
/// across `derive_blinding_vector`. The 7-byte → u64 unpack is vectorized
/// with AVX2 `vpshufb` when available (4 lanes per iteration).
fn single_field_pad(shared_secret: &SharedKey, round: u32, n_els: usize) -> Vec<u64> {
    let bytes_total = n_els * PACK_BYTES;
    // +2 blocks (32 bytes) of headroom so the AVX2 unpack's 16-byte loads at
    // offset `i*28 + 14` always stay in-bounds even when bytes_total ≡ 15
    // (mod 16).
    let n_blocks = bytes_total.div_ceil(16) + 2;

    let mut round_key_buf = Vec::with_capacity(4 + shared_secret.as_bytes().len());
    round_key_buf.extend_from_slice(&round.to_be_bytes());
    round_key_buf.extend_from_slice(shared_secret.as_bytes());

    let h = Sha3_256::digest(&round_key_buf);
    let key = GenericArray::from_slice(&h[..16]);
    let cipher = Aes128::new(key);

    let mut out = vec![0u64; n_els];
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
        // SAFETY: `Block` is `GenericArray<u8, U16>` ≡ `[u8; 16]`.
        let ks: &[u8] =
            unsafe { std::slice::from_raw_parts(blocks.as_ptr() as *const u8, n_blocks * 16) };
        unpack_7byte_to_u64(ks, &mut out);
    });
    out
}

/// 7-byte → u64 unpack. AVX2 fast path with scalar fallback.
#[inline]
fn unpack_7byte_to_u64(ks: &[u8], out: &mut [u64]) {
    #[cfg(target_arch = "x86_64")]
    {
        if out.len() >= 4 && std::is_x86_feature_detected!("avx2") {
            // SAFETY: feature-detected; caller guarantees `ks.len() >=
            // out.len() * 7 + 16` (AVX2 16-byte load at offset i*28+14 for
            // last i = out.len()/4 - 1 reads up to byte 7*out.len() + 2).
            unsafe { unpack_7byte_to_u64_avx2(ks, out) };
            return;
        }
    }
    unpack_7byte_to_u64_scalar(ks, out);
}

#[inline]
fn unpack_7byte_to_u64_scalar(ks: &[u8], out: &mut [u64]) {
    for (i, dst) in out.iter_mut().enumerate() {
        let start = i * PACK_BYTES;
        *dst = from_le_bytes_packed(&ks[start..start + PACK_BYTES]);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn unpack_7byte_to_u64_avx2(ks: &[u8], out: &mut [u64]) {
    use std::arch::x86_64::*;
    // Per-128-bit-lane shuffle: pack two 7-byte chunks (input bytes 0..7 and
    // 7..14) into two u64s with their high byte zeroed. Same mask in both
    // 128-bit lanes; lane composition handles the boundary at byte 14.
    let mask = _mm256_setr_epi8(
        0, 1, 2, 3, 4, 5, 6, -1, // lane 0 u64[0] ← input[0..7]
        7, 8, 9, 10, 11, 12, 13, -1, // lane 0 u64[1] ← input[7..14]
        0, 1, 2, 3, 4, 5, 6, -1, // lane 1 u64[0] ← input[0..7] (= ks[14..21])
        7, 8, 9, 10, 11, 12, 13, -1, // lane 1 u64[1] ← input[7..14] (= ks[21..28])
    );
    let n = out.len();
    let n4 = n / 4;
    for i in 0..n4 {
        let off = i * 28;
        // Two overlapping 16-byte loads; high lane starts 14 bytes into the
        // 28-byte input so the per-lane shuffle reaches the right bytes.
        let v_lo = _mm_loadu_si128(ks.as_ptr().add(off) as *const __m128i);
        let v_hi = _mm_loadu_si128(ks.as_ptr().add(off + 14) as *const __m128i);
        let v = _mm256_set_m128i(v_hi, v_lo);
        let r = _mm256_shuffle_epi8(v, mask);
        _mm256_storeu_si256(out.as_mut_ptr().add(i * 4) as *mut __m256i, r);
    }
    // Scalar tail.
    for j in (n4 * 4)..n {
        let start = j * PACK_BYTES;
        *out.get_unchecked_mut(j) = from_le_bytes_packed(&ks[start..start + PACK_BYTES]);
    }
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
}
