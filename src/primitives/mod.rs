//! Stateless blinded-broadcast primitives.
//!
//! These are the building blocks of every adcnet protocol variant. They know
//! nothing about auctions, slots, IBLTs, or what bytes mean — they blind,
//! aggregate, and unblind.
//!
//! Two flavors:
//! - [`field_round`]: field-additive (auction-style) over `Vec<BigUint>`.
//! - [`xor_round`]: XOR-additive (message-style) over `Vec<u8>`.
//!
//! A round is the same shape in either flavor:
//! 1. Each client blinds its plaintext contribution: `client_blind`.
//! 2. An aggregator sums client contributions: `aggregate_clients`.
//! 3. Each server emits its share over the aggregate's shape: `server_share`.
//! 4. Anyone with all server shares recovers the plaintext sum:
//!    `combine_partials`.

pub mod field_round;
pub mod xor_round;

/// Domain-separation prefix used by [`field_round`]. Distinct from
/// [`XOR_ROUND_DOMAIN`] so the same `SharedKey` produces independent pads in
/// each primitive.
pub const FIELD_ROUND_DOMAIN: u8 = 0;

/// Domain-separation prefix used by [`xor_round`].
pub const XOR_ROUND_DOMAIN: u8 = 1;
