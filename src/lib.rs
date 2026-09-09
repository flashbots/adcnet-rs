//! ADCNet — auction-based anonymous DC net.
//!
//! Use the provided sessions or compose stateless primitives and encoders.
//!
//! - [`primitives`]: blinded-broadcast primitives (`field_round`, `xor_round`).
//! - [`encoders`]: payload encoders (`auction_iblt`, `iblt_msg`, `message_slots`).
//! - [`protocol::session`]: reference sessions composing primitives + encoders.
//! - [`auction`], [`crypto`], [`protocol`]: low-level building blocks.

pub mod auction;
pub mod crypto;
pub mod encoders;
pub mod primitives;
pub mod protocol;

pub use crate::primitives::{field_round, xor_round};
pub use crate::encoders::{auction_iblt, iblt_msg, message_slots};
pub use crate::protocol::envelope::Signed;
pub use crate::protocol::session;

pub use crate::auction::{AuctionData, AuctionEngine, AuctionWinner, IbltVector};
pub use crate::crypto::{
    derive_blinding_vector, derive_xor_blinding_vector, PrivateKey, PublicKey, ServerId,
    SharedKey, Signature,
};
pub use crate::protocol::{
    AdcNetConfig, AggregatedClientMessages, AggregationMode, AuctionResult, ClientMessager,
    ClientRoundMessage, ClientService, ProtocolError, Round, RoundBroadcast, RoundContext,
    ServerMessager, ServerPartialDecryptionMessage, ServerService, VerifiedClientMessage,
};
