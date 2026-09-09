//! Auction data encoding, knapsack-based winner selection, and slot assignment.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::fields::PACK_BYTES;

use super::iblt::KEY_BYTES;

/// Knapsack granularity in bytes. Bids round their size up to the next
/// multiple of this constant before the DP runs. Each DP row has
/// `total_bandwidth / KNAPSACK_CHUNK_BYTES + 1` entries.
pub const KNAPSACK_CHUNK_BYTES: u32 = 1024;

/// A client's bid: weight (utility), message size in bytes, and a SHA-256-derived
/// hash so winners can identify themselves by hash without revealing the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionData {
    pub message_hash: [u8; 32],
    pub weight: u32,
    pub size: u32,
}

/// Number of V slots used to carry an [`AuctionData`] inside a multi-V IBLT
/// cell:
///
/// - `V[0]`: weight (u32, big-endian, in low 4 bytes)
/// - `V[1]`: size   (u32, big-endian, in low 4 bytes)
/// - `V[2]`: message_hash[0..7]
/// - `V[3]`: message_hash[7..14]
///
/// Only the first 14 bytes of the SHA-256 hash are carried.
pub const AUCTION_BID_XI: usize = 4;

/// Bytes of `message_hash` actually transmitted (= `2 × PACK_BYTES`).
pub const AUCTION_HASH_TRUNC_BYTES: usize = 2 * PACK_BYTES;

impl AuctionData {
    pub fn from_message(msg: &[u8], weight: u32) -> Self {
        let mut h = Sha256::new();
        h.update(msg);
        let digest = h.finalize();
        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&digest);
        Self {
            message_hash,
            weight,
            size: msg.len() as u32,
        }
    }

    /// Serialize the bid into 4 V-slot byte arrays for IBLT insertion.
    pub fn encode_values(&self) -> [[u8; PACK_BYTES]; AUCTION_BID_XI] {
        let mut v0 = [0u8; PACK_BYTES];
        v0[..4].copy_from_slice(&self.weight.to_be_bytes());
        let mut v1 = [0u8; PACK_BYTES];
        v1[..4].copy_from_slice(&self.size.to_be_bytes());
        let mut v2 = [0u8; PACK_BYTES];
        v2.copy_from_slice(&self.message_hash[0..PACK_BYTES]);
        let mut v3 = [0u8; PACK_BYTES];
        v3.copy_from_slice(&self.message_hash[PACK_BYTES..AUCTION_HASH_TRUNC_BYTES]);
        [v0, v1, v2, v3]
    }

    /// Inverse of [`Self::encode_values`]. `message_hash` is zero-padded past
    /// the truncated prefix.
    pub fn from_values(vs: &[Vec<u8>]) -> Self {
        let weight = u32::from_be_bytes([vs[0][0], vs[0][1], vs[0][2], vs[0][3]]);
        let size = u32::from_be_bytes([vs[1][0], vs[1][1], vs[1][2], vs[1][3]]);
        let mut message_hash = [0u8; 32];
        message_hash[0..PACK_BYTES].copy_from_slice(&vs[2][..PACK_BYTES]);
        message_hash[PACK_BYTES..AUCTION_HASH_TRUNC_BYTES]
            .copy_from_slice(&vs[3][..PACK_BYTES]);
        Self { message_hash, weight, size }
    }

    /// Truncated message hash used for in-band auction identification.
    pub fn truncated_hash(&self) -> [u8; AUCTION_HASH_TRUNC_BYTES] {
        let mut out = [0u8; AUCTION_HASH_TRUNC_BYTES];
        out.copy_from_slice(&self.message_hash[..AUCTION_HASH_TRUNC_BYTES]);
        out
    }
}

/// Number of IBLT key bytes (random nonce per bid; ensures multiple bids with
/// identical `(weight, size, hash)` payloads still land in distinct cells).
pub const AUCTION_KEY_BYTES: usize = KEY_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionWinner {
    pub bid: AuctionData,
    pub slot_idx: u32,
    pub slot_size: u32,
}

/// Knapsack-based auction. Selects bids that maximize total weight under a
/// total-bandwidth constraint and assigns contiguous offsets in the round's
/// message vector.
///
/// Bids are quantized to `chunk_bytes`-byte granularity for the DP, so the
/// solver memory scales as `n · total_bandwidth / chunk_bytes / 8` bytes
/// instead of `n · total_bandwidth` bytes. Allocated slots are always
/// multiples of `chunk_bytes`; the client writes its actual `bid.size` bytes
/// at the slot's start and the remaining padding is zero.
pub struct AuctionEngine {
    pub total_bandwidth: u32,
    pub min_message_size: u32,
    pub chunk_bytes: u32,
}

impl AuctionEngine {
    /// Default constructor — uses [`KNAPSACK_CHUNK_BYTES`] (1 KiB) granularity.
    pub fn new(total_bandwidth: u32, min_message_size: u32) -> Self {
        Self::with_chunk_bytes(total_bandwidth, min_message_size, KNAPSACK_CHUNK_BYTES)
    }

    /// Construct with an explicit quantization granularity. `chunk_bytes = 1`
    /// gives byte-level allocation at a higher memory cost.
    pub fn with_chunk_bytes(total_bandwidth: u32, min_message_size: u32, chunk_bytes: u32) -> Self {
        assert!(chunk_bytes > 0, "chunk_bytes must be positive");
        Self { total_bandwidth, min_message_size, chunk_bytes }
    }

    pub fn run_auction(&self, bids: &[AuctionData]) -> Vec<AuctionWinner> {
        if bids.is_empty() {
            return Vec::new();
        }
        let total_chunks = self.total_bandwidth / self.chunk_bytes;
        if total_chunks == 0 {
            return Vec::new();
        }

        // Filter to valid bids, recording each one's quantized chunk count.
        let mut valid: Vec<(AuctionData, u32)> = Vec::with_capacity(bids.len());
        for &bid in bids {
            let mut b = bid;
            if b.size < self.min_message_size {
                b.size = self.min_message_size;
            }
            if b.weight == 0 || b.size > self.total_bandwidth {
                continue;
            }
            let chunks = b.size.div_ceil(self.chunk_bytes);
            if chunks > total_chunks {
                continue;
            }
            valid.push((b, chunks));
        }
        if valid.is_empty() {
            return Vec::new();
        }

        let mut winners = self.knapsack(&valid, total_chunks);
        let mut cur: u32 = 0;
        for w in winners.iter_mut() {
            w.slot_idx = cur;
            cur += w.slot_size;
        }
        winners
    }

    /// Standard 0/1 knapsack DP over `(weight, chunks)` items. Uses a 1-D
    /// rolling `dp` row plus a compact `keep[i][w]` bit table for trace-back
    /// (one bit per (item, weight) telling whether item `i` was included in
    /// the optimum at capacity `w`).
    fn knapsack(&self, bids: &[(AuctionData, u32)], total_chunks: u32) -> Vec<AuctionWinner> {
        let n = bids.len();
        let cap = total_chunks as usize;
        let row_words = (cap + 1).div_ceil(64);
        // `keep[i * row_words + word]` holds the bits for item `i`.
        let mut keep: Vec<u64> = vec![0u64; n * row_words];
        let mut dp = vec![0u64; cap + 1];

        for (i, &(bid, chunks)) in bids.iter().enumerate() {
            let size = chunks as usize;
            if size > cap {
                continue;
            }
            // Iterate `w` from `cap` down to `size` so each item is used at most
            // once (standard 0/1 knapsack pattern).
            for w in (size..=cap).rev() {
                let include_value = dp[w - size] + u64::from(bid.weight);
                if include_value > dp[w] {
                    dp[w] = include_value;
                    let bit_idx = i * row_words * 64 + w;
                    keep[bit_idx / 64] |= 1u64 << (bit_idx % 64);
                }
            }
        }

        // Trace back: walk items in reverse, consulting `keep[i][w]` to decide
        // whether item `i` was selected at the current remaining capacity `w`.
        let mut selected = vec![false; n];
        let mut w = cap;
        for i in (0..n).rev() {
            let bit_idx = i * row_words * 64 + w;
            let bit = (keep[bit_idx / 64] >> (bit_idx % 64)) & 1;
            if bit == 1 {
                selected[i] = true;
                w -= bids[i].1 as usize;
            }
        }

        let mut winners: Vec<AuctionWinner> = Vec::new();
        for (i, &(bid, chunks)) in bids.iter().enumerate() {
            if selected[i] {
                winners.push(AuctionWinner {
                    bid,
                    slot_idx: 0,
                    slot_size: chunks * self.chunk_bytes,
                });
            }
        }
        winners.sort_by_key(|w| w.bid.message_hash);
        winners
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knapsack_picks_best_combo() {
        // chunk_bytes=1 to keep the test byte-granular.
        let engine = AuctionEngine::with_chunk_bytes(10, 1, 1);
        let bids = vec![
            AuctionData { message_hash: [1; 32], weight: 6, size: 6 },
            AuctionData { message_hash: [2; 32], weight: 5, size: 5 },
            AuctionData { message_hash: [3; 32], weight: 4, size: 4 },
        ];
        let winners = engine.run_auction(&bids);
        // optimal: bids 1 & 3 with sizes 6+4=10 → total weight 10.
        let total_weight: u32 = winners.iter().map(|w| w.bid.weight).sum();
        assert_eq!(total_weight, 10);
        let total_slot: u32 = winners.iter().map(|w| w.slot_size).sum();
        assert_eq!(total_slot, 10);
    }

    #[test]
    fn knapsack_diverges_from_greedy() {
        // 5 items where greedy (by weight/size ratio) picks the wrong subset.
        // capacity = 10. Optimal: {size=6,w=10} + {size=4,w=6} = 16 weight,
        // size 10. Greedy by w/s ratio would pick {size=1,w=2} (ratio 2.0)
        // first then can't pack the size=6 — ends at <16.
        let engine = AuctionEngine::with_chunk_bytes(10, 1, 1);
        let bids = vec![
            AuctionData { message_hash: [1; 32], weight: 10, size: 6 },
            AuctionData { message_hash: [2; 32], weight: 6, size: 4 },
            AuctionData { message_hash: [3; 32], weight: 2, size: 1 },
            AuctionData { message_hash: [4; 32], weight: 3, size: 2 },
            AuctionData { message_hash: [5; 32], weight: 4, size: 3 },
        ];
        let winners = engine.run_auction(&bids);
        let total_weight: u32 = winners.iter().map(|w| w.bid.weight).sum();
        assert_eq!(total_weight, 16, "DP must beat greedy");
        let selected_hashes: Vec<u8> = winners.iter().map(|w| w.bid.message_hash[0]).collect();
        assert_eq!(selected_hashes, vec![1, 2]);
    }

    #[test]
    fn knapsack_quantizes_to_chunks() {
        // Default chunk = 1024 B. A bid of 1500 bytes consumes 2 KiB.
        let engine = AuctionEngine::new(4096, 1);
        let bids = vec![
            // Three bids of 1500 B each → quantized to 2 KiB → total 6 KiB,
            // but capacity is 4 KiB (= 4 chunks). Two of three fit; the
            // highest-weight pair wins.
            AuctionData { message_hash: [1; 32], weight: 5, size: 1500 },
            AuctionData { message_hash: [2; 32], weight: 7, size: 1500 },
            AuctionData { message_hash: [3; 32], weight: 9, size: 1500 },
        ];
        let winners = engine.run_auction(&bids);
        assert_eq!(winners.len(), 2);
        let weights: Vec<u32> = {
            let mut w: Vec<u32> = winners.iter().map(|w| w.bid.weight).collect();
            w.sort();
            w
        };
        assert_eq!(weights, vec![7, 9]);
        // Each slot is rounded up to a 1 KiB multiple.
        for w in &winners {
            assert_eq!(w.slot_size, 2048);
        }
    }

    #[test]
    fn knapsack_memory_is_bounded() {
        // 100 bids, 1 MiB total bandwidth: at byte granularity the old solver
        // would have allocated ~400 MiB. At 1 KiB chunks the keep bitmap is
        // 100 × 1024 bits = 12.5 KiB.
        let engine = AuctionEngine::new(1 << 20, 1);
        let bids: Vec<AuctionData> = (0..100u32)
            .map(|i| AuctionData {
                message_hash: [i as u8; 32],
                weight: i + 1,
                size: 4096 + i,
            })
            .collect();
        let winners = engine.run_auction(&bids);
        assert!(!winners.is_empty());
        let total_slot: u32 = winners.iter().map(|w| w.slot_size).sum();
        assert!(total_slot <= 1 << 20);
    }

    #[test]
    fn values_roundtrip() {
        let a = AuctionData { message_hash: [42; 32], weight: 7, size: 99 };
        let vs = a.encode_values();
        let bs: Vec<Vec<u8>> = vs.iter().map(|v| v.to_vec()).collect();
        let b = AuctionData::from_values(&bs);
        assert_eq!(b.weight, a.weight);
        assert_eq!(b.size, a.size);
        // Only the first 14 bytes of the hash are preserved.
        assert_eq!(&b.message_hash[..14], &a.message_hash[..14]);
    }

    #[test]
    fn knapsack_handles_total_weight_above_u32() {
        let engine = AuctionEngine::with_chunk_bytes(2, 1, 1);
        let bids = [
            AuctionData { message_hash: [1; 32], weight: u32::MAX, size: 2 },
            AuctionData { message_hash: [2; 32], weight: u32::MAX - 1, size: 1 },
            AuctionData { message_hash: [3; 32], weight: u32::MAX - 1, size: 1 },
        ];
        let winners = engine.run_auction(&bids);
        let selected: Vec<_> = winners.iter().map(|w| w.bid.message_hash[0]).collect();
        assert_eq!(selected, vec![2, 3]);
        assert_eq!(winners.iter().map(|w| u64::from(w.bid.weight)).sum::<u64>(),
            2 * u64::from(u32::MAX - 1));
    }

    #[test]
    fn knapsack_handles_zero_size_bids() {
        let engine = AuctionEngine::with_chunk_bytes(1, 0, 1);
        let bids = [
            AuctionData { message_hash: [1; 32], weight: 2, size: 0 },
            AuctionData { message_hash: [2; 32], weight: 3, size: 1 },
            AuctionData { message_hash: [3; 32], weight: 4, size: 0 },
        ];
        let winners = engine.run_auction(&bids);
        let selected: Vec<_> = winners.iter().map(|w| w.bid.message_hash[0]).collect();
        assert_eq!(selected, vec![1, 2, 3]);
        assert_eq!(winners.iter().map(|w| w.slot_size).sum::<u32>(), 1);
        assert_eq!(winners.iter().map(|w| w.bid.weight).sum::<u32>(), 9);
    }

}
