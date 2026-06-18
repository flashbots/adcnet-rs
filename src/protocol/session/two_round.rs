//! Reference 2-round (auction → broadcast) session.
//!
//! Re-exports the stateful service types that wire the field-additive auction
//! round, the XOR-additive message round, the auction-IBLT encoder, and the
//! message-slots encoder into an end-to-end protocol.

pub use crate::protocol::services::{AggregatorService, ClientService, ServerService};
