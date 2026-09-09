//! Field arithmetic over `F_p`, `p = 0x1eeed4e13a526bab`.
//!
//! Field elements are `u64` values in `[0, p)`. Since `2·p < 2^64`, adding
//! canonical elements cannot overflow. Since `2^56 < p`, any 7-byte input
//! packs losslessly into one element.

use negacyclic_rings::ntt64::{add_mod, sub_mod};

/// Prime modulus.
pub const P: u64 = 0x1eeed4e13a526bab;

/// Bytes packed per field element by the IBLT and payload encoders.
pub const PACK_BYTES: usize = 7;

/// Bytes per field element on the wire, encoded as a little-endian `u64`.
pub const WIRE_BYTES: usize = 8;

/// Decode up to `PACK_BYTES` little-endian bytes into a field element. The
/// resulting value is `< 2^56 < p`, so no reduction is needed.
#[inline]
pub fn from_le_bytes_packed(b: &[u8]) -> u64 {
    debug_assert!(b.len() <= PACK_BYTES);
    let mut buf = [0u8; 8];
    buf[..b.len()].copy_from_slice(b);
    u64::from_le_bytes(buf)
}

/// Encode a field element `< 2^56` to `PACK_BYTES` little-endian bytes.
#[inline]
pub fn to_le_bytes_packed(x: u64) -> [u8; PACK_BYTES] {
    debug_assert!(x < (1u64 << (PACK_BYTES * 8)));
    let full = x.to_le_bytes();
    let mut out = [0u8; PACK_BYTES];
    out.copy_from_slice(&full[..PACK_BYTES]);
    out
}

/// Decode a field element from `WIRE_BYTES` little-endian bytes. Used on
/// deserialized wire payloads; values are expected to be canonical (`< p`),
/// callers may choose to enforce that.
#[inline]
pub fn from_le_bytes_wire(b: &[u8; WIRE_BYTES]) -> u64 {
    u64::from_le_bytes(*b)
}

/// Encode a field element to `WIRE_BYTES` little-endian bytes.
#[inline]
pub fn to_le_bytes_wire(x: u64) -> [u8; WIRE_BYTES] {
    x.to_le_bytes()
}

/// Reduce any `u64` modulo p.
#[inline]
pub fn reduce(x: u64) -> u64 {
    x % P
}

// --- Vector helpers --------------------------------------------------------

/// `dst[i] = (dst[i] + src[i]) mod p` for `i in 0..min(dst.len(), src.len())`.
///
/// On x86_64 with AVX2 detected at runtime, processes 4 elements per vector
/// iteration (`vpaddq` + biased `vpcmpgtq` + masked `vpsubq`). Scalar
/// fallback otherwise.
#[inline]
pub fn add_mod_slice(dst: &mut [u64], src: &[u64]) {
    let n = dst.len().min(src.len());
    #[cfg(target_arch = "x86_64")]
    {
        if n >= 4 && std::is_x86_feature_detected!("avx2") {
            // SAFETY: feature-detected at runtime; bounds checked by `n`.
            unsafe { add_mod_slice_avx2(&mut dst[..n], &src[..n]) };
            return;
        }
    }
    for i in 0..n {
        dst[i] = add_mod(dst[i], src[i], P);
    }
}

/// `dst[i] = (dst[i] - src[i]) mod p` for `i in 0..min(dst.len(), src.len())`.
/// Uses the same SIMD strategy as [`add_mod_slice`].
#[inline]
pub fn sub_mod_slice(dst: &mut [u64], src: &[u64]) {
    let n = dst.len().min(src.len());
    #[cfg(target_arch = "x86_64")]
    {
        if n >= 4 && std::is_x86_feature_detected!("avx2") {
            unsafe { sub_mod_slice_avx2(&mut dst[..n], &src[..n]) };
            return;
        }
    }
    for i in 0..n {
        dst[i] = sub_mod(dst[i], src[i], P);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn add_mod_slice_avx2(dst: &mut [u64], src: &[u64]) {
    use std::arch::x86_64::*;
    debug_assert_eq!(dst.len(), src.len());
    let n = dst.len();
    let p_vec = _mm256_set1_epi64x(P as i64);
    let sign_flip = _mm256_set1_epi64x(i64::MIN);
    // For unsigned compare s > (P-1) ⇔ s ≥ P, bias both sides by 2^63 and
    // use signed `vpcmpgtq`.
    let p_minus_1_biased =
        _mm256_xor_si256(_mm256_set1_epi64x((P - 1) as i64), sign_flip);
    let dp = dst.as_mut_ptr();
    let sp = src.as_ptr();
    let mut i = 0usize;
    while i + 4 <= n {
        let a = _mm256_loadu_si256(dp.add(i) as *const __m256i);
        let b = _mm256_loadu_si256(sp.add(i) as *const __m256i);
        let s = _mm256_add_epi64(a, b);
        let s_biased = _mm256_xor_si256(s, sign_flip);
        let mask = _mm256_cmpgt_epi64(s_biased, p_minus_1_biased);
        let to_sub = _mm256_and_si256(mask, p_vec);
        let red = _mm256_sub_epi64(s, to_sub);
        _mm256_storeu_si256(dp.add(i) as *mut __m256i, red);
        i += 4;
    }
    while i < n {
        *dp.add(i) = add_mod(*dp.add(i), *sp.add(i), P);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sub_mod_slice_avx2(dst: &mut [u64], src: &[u64]) {
    use std::arch::x86_64::*;
    debug_assert_eq!(dst.len(), src.len());
    let n = dst.len();
    let p_vec = _mm256_set1_epi64x(P as i64);
    let sign_flip = _mm256_set1_epi64x(i64::MIN);
    let dp = dst.as_mut_ptr();
    let sp = src.as_ptr();
    let mut i = 0usize;
    while i + 4 <= n {
        let a = _mm256_loadu_si256(dp.add(i) as *const __m256i);
        let b = _mm256_loadu_si256(sp.add(i) as *const __m256i);
        let d = _mm256_sub_epi64(a, b);
        // mask = (a < b) unsigned ⇔ (a^sign_flip) < (b^sign_flip) signed.
        let a_biased = _mm256_xor_si256(a, sign_flip);
        let b_biased = _mm256_xor_si256(b, sign_flip);
        let mask = _mm256_cmpgt_epi64(b_biased, a_biased);
        let to_add = _mm256_and_si256(mask, p_vec);
        let red = _mm256_add_epi64(d, to_add);
        _mm256_storeu_si256(dp.add(i) as *mut __m256i, red);
        i += 4;
    }
    while i < n {
        *dp.add(i) = sub_mod(*dp.add(i), *sp.add(i), P);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_is_61_bit() {
        assert_eq!(64 - P.leading_zeros(), 61);
    }

    #[test]
    fn add_wraps() {
        assert_eq!(add_mod(P - 1, 1, P), 0);
        assert_eq!(add_mod(P - 1, P - 1, P), P - 2);
    }

    #[test]
    fn sub_wraps() {
        assert_eq!(sub_mod(0, 1, P), P - 1);
        assert_eq!(sub_mod(3, 5, P), P - 2);
    }

    #[test]
    fn pack_roundtrip() {
        let bytes: [u8; PACK_BYTES] = [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56];
        let x = from_le_bytes_packed(&bytes);
        assert!(x < P);
        assert_eq!(to_le_bytes_packed(x), bytes);
    }

    #[test]
    fn pack_max_value_fits() {
        let max_packed = (1u64 << (PACK_BYTES * 8)) - 1;
        assert!(max_packed < P);
    }

    #[test]
    fn add_mod_slice_matches_scalar() {
        // Sizes spanning the SIMD body (4-lane), a partial-lane tail, and
        // boundary cases.
        for n in [0usize, 1, 3, 4, 5, 8, 17, 256, 1000] {
            let a: Vec<u64> = (0..n).map(|i| (i as u64 * 12345) % P).collect();
            let b: Vec<u64> = (0..n).map(|i| ((i as u64 + 7) * 6789) % P).collect();
            let mut got = a.clone();
            add_mod_slice(&mut got, &b);
            let mut want = a.clone();
            for i in 0..n {
                want[i] = add_mod(want[i], b[i], P);
            }
            assert_eq!(got, want, "n={}", n);
        }
    }

    #[test]
    fn sub_mod_slice_matches_scalar() {
        for n in [0usize, 1, 3, 4, 5, 8, 17, 256, 1000] {
            let a: Vec<u64> = (0..n).map(|i| (i as u64 * 12345) % P).collect();
            let b: Vec<u64> = (0..n).map(|i| ((i as u64 + 7) * 6789) % P).collect();
            let mut got = a.clone();
            sub_mod_slice(&mut got, &b);
            let mut want = a.clone();
            for i in 0..n {
                want[i] = sub_mod(want[i], b[i], P);
            }
            assert_eq!(got, want, "n={}", n);
        }
    }

    #[test]
    fn add_mod_slice_edge_cases() {
        // Carefully chosen near-modulus values that hit the conditional
        // subtract path under SIMD.
        let n = 8;
        let a = vec![P - 1; n];
        let b = vec![1u64; n];
        let mut got = a.clone();
        add_mod_slice(&mut got, &b);
        assert_eq!(got, vec![0u64; n]);

        let a = vec![P - 1; n];
        let b = vec![P - 1; n];
        let mut got = a.clone();
        add_mod_slice(&mut got, &b);
        assert_eq!(got, vec![P - 2; n]);
    }

    #[test]
    fn sub_mod_slice_edge_cases() {
        let n = 8;
        let a = vec![0u64; n];
        let b = vec![1u64; n];
        let mut got = a.clone();
        sub_mod_slice(&mut got, &b);
        assert_eq!(got, vec![P - 1; n]);
    }

    #[test]
    fn reduce_handles_the_full_u64_range() {
        for (input, expected) in [
            (0, 0), (P - 1, P - 1), (P, 0),
            (2 * P - 1, P - 1), (2 * P, 0),
            (u64::MAX, 0x88958f62d6ca2a7),
        ] {
            assert_eq!(reduce(input), expected);
        }
    }
    #[test]
    fn scalar_arithmetic_matches_wide_reference() {
        for a in [0, 1, 2, P / 2, P - 2, P - 1] {
            for b in [0, 1, 2, P / 2, P - 2, P - 1] {
                let expected_add = ((a as u128 + b as u128) % P as u128) as u64;
                let expected_sub = ((a as u128 + P as u128 - b as u128) % P as u128) as u64;
                assert_eq!(add_mod(a, b, P), expected_add);
                assert_eq!(sub_mod(a, b, P), expected_sub);
            }
        }
    }

}
