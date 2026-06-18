//! Stateless encoders that bracket the blinded-broadcast primitives.
//!
//! Each encoder turns protocol-level objects (bids, payloads) into the
//! field-element or byte vectors the primitives carry, and inverts that on
//! the recovered side.
//!
//! - [`auction_iblt`]: encode bids into an IBLT; decode winners from the
//!   recovered field-element vector.
//! - [`message_slots`]: write/read payloads into/from an XOR-additive message
//!   vector at slot offsets allocated by the auction.

pub mod auction_iblt;
pub mod iblt_msg;
pub mod message_slots;
