//! Protocol layer: round state machine, blinded message construction,
//! aggregation (optional), and partial-decryption flow on servers.

pub mod config;
pub mod envelope;
pub mod messages;
pub mod messager;
pub mod round;
pub mod services;
pub mod session;

pub use config::{auction_slots_for_config, AdcNetConfig, AggregationMode, AuctionResult};
pub use messages::{
    AggregatedClientMessages, ClientRoundMessage, ProtocolError, RoundBroadcast,
    ServerPartialDecryptionMessage, Signed,
};
pub use messager::{
    AggregatorMessager, ClientMessager, ServerMessager, VerifiedClientMessage,
    VerifyClientMessages,
};
pub use round::{Round, RoundContext};
pub use services::{AggregatorService, ClientService, ServerService};
