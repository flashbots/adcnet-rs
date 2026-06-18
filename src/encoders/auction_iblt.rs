//! Encode bids into an IBLT and decode winners from the recovered
//! field-element vector. Pure functions; no protocol state.
//!
//! Each bid rides in a single multi-V IBLT cell: the key is a 7-byte random
//! nonce (so identical bids from distinct clients land in distinct cells),
//! and ξ=4 V slots carry the bid's `(weight, size, hash[..14])`.

use rand::Rng;
use thiserror::Error;

use crate::auction::auction::{
    AuctionData, AuctionEngine, AuctionWinner, AUCTION_BID_XI, AUCTION_KEY_BYTES,
};
use crate::auction::iblt::{IbltError, IbltVector};

#[derive(Debug, Error)]
pub enum AuctionDecodeError {
    #[error("IBLT decode failed: {0}")]
    Iblt(#[from] IbltError),
}

/// Create an empty auction-IBLT sized for `estimated_elements`.
pub fn empty_iblt(estimated_elements: u32) -> IbltVector {
    IbltVector::new_with_xi(estimated_elements, AUCTION_BID_XI)
}

/// Insert one bid into the IBLT. `rng` draws the random per-bid key.
pub fn insert_bid<R: Rng>(iblt: &mut IbltVector, bid: &AuctionData, rng: &mut R) -> Result<(), IbltError> {
    let mut key = [0u8; AUCTION_KEY_BYTES];
    rng.fill_bytes(&mut key);
    let values = bid.encode_values();
    let slices: [&[u8]; AUCTION_BID_XI] = [&values[0], &values[1], &values[2], &values[3]];
    iblt.insert(&key, &slices)
}

/// Encode the IBLT into the field-element vector that the field-additive
/// primitive carries.
pub fn encode_iblt(iblt: &IbltVector) -> Vec<u64> {
    iblt.encode_as_field_elements()
}

/// Decode the recovered field-element vector back into bids, then run the
/// auction's knapsack winner selection.
pub fn decode_winners(
    recovered: &[u64],
    estimated_elements: u32,
    total_bandwidth: u32,
    min_message_size: u32,
) -> Result<Vec<AuctionWinner>, AuctionDecodeError> {
    let mut iblt = empty_iblt(estimated_elements);
    iblt.decode_from_elements(recovered)?;
    let entries = iblt.recover()?;
    let bids: Vec<AuctionData> = entries
        .iter()
        .map(|e| AuctionData::from_values(&e.values))
        .collect();
    let engine = AuctionEngine::new(total_bandwidth, min_message_size);
    Ok(engine.run_auction(&bids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn insert_encode_decode_one() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let mut iblt = empty_iblt(8);
        let bid = AuctionData {
            message_hash: [7; 32],
            weight: 50,
            size: 512,
        };
        insert_bid(&mut iblt, &bid, &mut rng).unwrap();
        let els = encode_iblt(&iblt);
        // Bandwidth = 2 KiB (= 2 chunks at the default 1 KiB granularity).
        let winners = decode_winners(&els, 8, 2 * 1024, 1).unwrap();
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].bid.weight, bid.weight);
        assert_eq!(winners[0].bid.size, bid.size);
        assert_eq!(
            &winners[0].bid.message_hash[..14],
            &bid.message_hash[..14]
        );
    }
}
