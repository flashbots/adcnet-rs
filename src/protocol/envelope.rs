//! Signed envelope for any wire-level message.
//!
//! Re-exports [`Signed`] from [`crate::protocol::messages`]. Future work moves
//! the definition here and folds the per-payload error variants into a
//! dedicated `ProtocolError` module.

pub use crate::protocol::messages::Signed;
