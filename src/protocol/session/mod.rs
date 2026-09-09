//! Reference compositions of the [`primitives`] and [`encoders`] modules into
//! end-to-end protocol sessions.
//!
//! Two reference sessions ship in-tree:
//! - [`two_round`]: the auction-then-broadcast (2-round) flow with optional
//!   aggregator.
//! - [`one_round`]: scheduling-free IBLT-message flow.
//!
//! Use these sessions for the provided protocol flows, or compose primitives
//! and encoders for a custom flow. Callers supply transport and scheduling.
//!
//! [`primitives`]: crate::primitives
//! [`encoders`]: crate::encoders

pub mod one_round;
pub mod two_round;
