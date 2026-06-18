//! Reference compositions of the [`primitives`] and [`encoders`] modules into
//! end-to-end protocol sessions.
//!
//! Two reference sessions ship in-tree:
//! - [`two_round`]: the auction-then-broadcast (2-round) flow with optional
//!   aggregator.
//! - [`one_round`]: scheduling-free IBLT-message flow.
//!
//! These are *examples* of how to compose the library. Downstream consumers
//! that want different transport, scheduling, or threading should build their
//! own session by calling the primitives and encoders directly.
//!
//! [`primitives`]: crate::primitives
//! [`encoders`]: crate::encoders

pub mod one_round;
pub mod two_round;
