//! Write payloads into / read payloads out of an XOR-additive message vector
//! at slot offsets allocated by the auction.
//!
//! Pure functions over `&mut [u8]` / `&[u8]`. The slot offsets come from the
//! winners returned by [`crate::encoders::auction_iblt::decode_winners`].

use thiserror::Error;

use crate::auction::auction::AuctionWinner;

#[derive(Debug, Error)]
pub enum SlotError {
    #[error("payload of {payload_len}B does not fit in slot {slot} of vector of {vec_len}B")]
    Overflow {
        slot: usize,
        payload_len: usize,
        vec_len: usize,
    },
}

/// Write `payload` into `vec` at byte offset `slot`. Errors if the write would
/// run past the end of `vec`.
pub fn write_slot(vec: &mut [u8], slot: usize, payload: &[u8]) -> Result<(), SlotError> {
    let end = slot.checked_add(payload.len()).ok_or(SlotError::Overflow {
        slot,
        payload_len: payload.len(),
        vec_len: vec.len(),
    })?;
    if end > vec.len() {
        return Err(SlotError::Overflow {
            slot,
            payload_len: payload.len(),
            vec_len: vec.len(),
        });
    }
    vec[slot..end].copy_from_slice(payload);
    Ok(())
}

/// Read each winner's payload (`slot_size` bytes starting at `slot_idx`).
/// Truncates if a winner's slot would extend past `vec`.
pub fn read_slots(vec: &[u8], winners: &[AuctionWinner]) -> Vec<Vec<u8>> {
    winners
        .iter()
        .map(|w| {
            let start = w.slot_idx as usize;
            let end = start.saturating_add(w.slot_size as usize).min(vec.len());
            if start >= vec.len() {
                Vec::new()
            } else {
                vec[start..end].to_vec()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auction::auction::AuctionData;

    #[test]
    fn write_then_read() {
        let mut buf = vec![0u8; 32];
        write_slot(&mut buf, 4, b"hello").unwrap();
        write_slot(&mut buf, 16, b"world").unwrap();
        let winners = vec![
            AuctionWinner {
                bid: AuctionData { message_hash: [0; 32], weight: 1, size: 5 },
                slot_idx: 4,
                slot_size: 5,
            },
            AuctionWinner {
                bid: AuctionData { message_hash: [0; 32], weight: 1, size: 5 },
                slot_idx: 16,
                slot_size: 5,
            },
        ];
        let payloads = read_slots(&buf, &winners);
        assert_eq!(payloads, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn write_overflow_errors() {
        let mut buf = vec![0u8; 8];
        let err = write_slot(&mut buf, 6, b"too long").unwrap_err();
        assert!(matches!(err, SlotError::Overflow { .. }));
    }
    #[test]
    fn read_truncates_oversized_slots() {
        let winners: Vec<_> = [1, 4, u32::MAX].into_iter().map(|slot_idx| AuctionWinner {
            bid: AuctionData { message_hash: [0; 32], weight: 1, size: 1 },
            slot_idx,
            slot_size: u32::MAX,
        }).collect();
        assert_eq!(read_slots(b"data", &winners), vec![b"ata".to_vec(), vec![], vec![]]);
    }

}
