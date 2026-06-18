//! Auction-scheduling primitives: IBLT vector for blinded bid encoding and
//! a 0/1 knapsack solver to allocate per-round message bandwidth.

#[allow(clippy::module_inception)]
pub mod auction;
pub mod iblt;

pub use auction::{AuctionData, AuctionEngine, AuctionWinner};
pub use iblt::{
    chunk_index, iblt_delta, iblt_field_element_count, IbltError, IbltVector, RecoveredEntry,
    IBLT_GAMMA, IBLT_LOAD_FACTOR, KEY_BYTES,
};
