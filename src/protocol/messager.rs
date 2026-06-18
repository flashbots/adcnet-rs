//! Stateless protocol operations: client message preparation/blinding,
//! aggregator union, server unblinding.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::auction::auction::{
    AuctionData, AuctionEngine, AUCTION_BID_XI, AUCTION_HASH_TRUNC_BYTES, AUCTION_KEY_BYTES,
};
use crate::auction::iblt::IbltVector;
use crate::crypto::fields::{add_mod_slice, sub_mod_slice};
use crate::crypto::{
    derive_blinding_vector, derive_xor_blinding_vector, domain_prefixed, xor_inplace, PublicKey,
    ServerId, SharedKey,
};

use super::config::{AdcNetConfig, AuctionResult};
use super::messages::{
    AggregatedClientMessages, ClientRoundMessage, ProtocolError, RoundBroadcast,
    ServerPartialDecryptionMessage, Signed,
};

pub struct ServerMessager<'a> {
    pub config: &'a AdcNetConfig,
    pub server_id: ServerId,
    pub shared_secrets: &'a HashMap<String, SharedKey>,
}

impl<'a> ServerMessager<'a> {
    /// Recover the final broadcast by subtracting all server shares from the
    /// aggregate.
    ///
    /// Validates that:
    /// - `msgs` is non-empty (else `EmptyPartials`).
    /// - All partials reference the *same* `original_aggregate`
    ///   (round_number, all_server_ids, auction_vector, message_vector) —
    ///   else `MismatchingAggregate`. Per-partial `message_vector` lengths
    ///   must agree (else `MismatchingVectorLengths`).
    /// - No two partials carry the same `server_id` after sort (else
    ///   `DuplicatePartial`).
    pub fn unblind_partial_messages(
        &self,
        msgs: &mut [ServerPartialDecryptionMessage],
    ) -> Result<RoundBroadcast, ProtocolError> {
        if msgs.is_empty() {
            return Err(ProtocolError::EmptyPartials);
        }
        msgs.sort_by_key(|m| m.server_id.0);
        // Detect duplicate server_ids.
        for w in msgs.windows(2) {
            if w[0].server_id == w[1].server_id {
                return Err(ProtocolError::DuplicatePartial(w[0].server_id));
            }
        }
        let head = &msgs[0];
        let msg_len = head.message_vector.len();
        for m in &msgs[1..] {
            if m.original_aggregate.round_number != head.original_aggregate.round_number
                || m.original_aggregate.all_server_ids
                    != head.original_aggregate.all_server_ids
                || m.original_aggregate.auction_vector
                    != head.original_aggregate.auction_vector
                || m.original_aggregate.message_vector
                    != head.original_aggregate.message_vector
            {
                return Err(ProtocolError::MismatchingAggregate);
            }
            if m.message_vector.len() != msg_len {
                return Err(ProtocolError::MismatchingVectorLengths);
            }
        }

        let mut auction_vector: Vec<u64> = head.original_aggregate.auction_vector.clone();
        for m in msgs.iter() {
            sub_mod_slice(&mut auction_vector, &m.auction_vector);
        }

        let mut message_vector = head.original_aggregate.message_vector.clone();
        for m in msgs.iter() {
            xor_inplace(&mut message_vector, &m.message_vector);
        }

        let mut iblt = IbltVector::new_with_xi(self.config.auction_slots, AUCTION_BID_XI);
        iblt.decode_from_elements(&auction_vector)?;

        Ok(RoundBroadcast {
            round_number: head.original_aggregate.round_number,
            auction_vector: iblt,
            message_vector,
        })
    }

    /// Compute this server's blinding contribution to a (per-client or aggregated) batch.
    pub fn unblind_aggregate(
        &self,
        current_round: i64,
        aggregate: &AggregatedClientMessages,
    ) -> Result<ServerPartialDecryptionMessage, ProtocolError> {
        if aggregate.round_number != current_round {
            return Err(ProtocolError::WrongRound {
                got: aggregate.round_number,
                expected: current_round,
            });
        }
        if !aggregate.all_server_ids.contains(&self.server_id) {
            return Err(ProtocolError::InvalidServer(self.server_id));
        }

        let mut auction_secrets: Vec<SharedKey> = Vec::with_capacity(aggregate.user_pks.len());
        let mut message_secrets: Vec<SharedKey> = Vec::with_capacity(aggregate.user_pks.len());
        for pk in &aggregate.user_pks {
            let s = self
                .shared_secrets
                .get(&pk.to_hex())
                .ok_or_else(|| ProtocolError::NoSharedKey(pk.to_hex()))?;
            auction_secrets.push(domain_prefixed(s, 0));
            message_secrets.push(domain_prefixed(s, 1));
        }

        let n_auction_els = aggregate.auction_vector.len();
        let msg_vec_len = aggregate.message_vector.len();
        let round_u32 = current_round as u32;

        let auction_blind = derive_blinding_vector(&auction_secrets, round_u32, n_auction_els);
        let message_blind = derive_xor_blinding_vector(&message_secrets, round_u32, msg_vec_len);

        Ok(ServerPartialDecryptionMessage {
            server_id: self.server_id,
            original_aggregate: aggregate.clone(),
            user_pks: aggregate.user_pks.clone(),
            auction_vector: auction_blind,
            message_vector: message_blind,
        })
    }
}

pub struct AggregatorMessager<'a> {
    pub config: &'a AdcNetConfig,
}

/// Pre-verified client message — sig already checked, signer extracted.
#[derive(Clone, Debug)]
pub struct VerifiedClientMessage {
    pub message: ClientRoundMessage,
    pub signer: PublicKey,
}

pub struct VerifyClientMessages;

impl VerifyClientMessages {
    pub fn verify(
        msgs: &[Signed<ClientRoundMessage>],
    ) -> Result<Vec<VerifiedClientMessage>, ProtocolError> {
        let mut out = Vec::with_capacity(msgs.len());
        for m in msgs {
            let (raw, signer) = m.recover()?;
            out.push(VerifiedClientMessage {
                message: raw.clone(),
                signer: signer.clone(),
            });
        }
        Ok(out)
    }
}

impl<'a> AggregatorMessager<'a> {
    pub fn aggregate_verified_messages(
        &self,
        round: i64,
        previous: Option<&AggregatedClientMessages>,
        verified: &[VerifiedClientMessage],
        authorized: &HashMap<String, bool>,
    ) -> Result<AggregatedClientMessages, ProtocolError> {
        let mut agg = AggregatedClientMessages::empty();
        if let Some(p) = previous {
            agg.union_inplace(p)?;
        }
        for v in verified {
            if !authorized.get(&v.signer.to_hex()).copied().unwrap_or(false) {
                return Err(ProtocolError::Unauthorized(v.signer.to_hex()));
            }
            if v.message.round_number != round {
                return Err(ProtocolError::WrongRound {
                    got: v.message.round_number,
                    expected: round,
                });
            }
        }
        if verified.is_empty() {
            return Ok(agg);
        }

        let auction_len = verified[0].message.auction_vector.len();
        let msg_len = verified[0].message.message_vector.len();
        let server_ids = verified[0].message.all_server_ids.clone();
        let round_no = verified[0].message.round_number;
        let zero = || AggregatedClientMessages {
            round_number: round_no,
            all_server_ids: server_ids.clone(),
            auction_vector: vec![0u64; auction_len],
            message_vector: vec![0u8; msg_len],
            user_pks: Vec::new(),
        };

        #[cfg(feature = "parallel")]
        let folded = {
            use rayon::prelude::*;
            verified
                .par_iter()
                .fold(zero, |mut acc, v| {
                    add_mod_slice(&mut acc.auction_vector, &v.message.auction_vector);
                    xor_inplace(&mut acc.message_vector, &v.message.message_vector);
                    acc.user_pks.push(v.signer.clone());
                    acc
                })
                .reduce(zero, |mut a, b| {
                    a.union_inplace(&b).expect("compatible shapes by construction");
                    a
                })
        };
        #[cfg(not(feature = "parallel"))]
        let folded = {
            let mut acc = zero();
            for v in verified {
                add_mod_slice(&mut acc.auction_vector, &v.message.auction_vector);
                xor_inplace(&mut acc.message_vector, &v.message.message_vector);
                acc.user_pks.push(v.signer.clone());
            }
            acc
        };

        agg.union_inplace(&folded)?;
        Ok(agg)
    }

    pub fn aggregate_aggregates(
        &self,
        round: i64,
        msgs: &[AggregatedClientMessages],
    ) -> Result<AggregatedClientMessages, ProtocolError> {
        let mut agg = AggregatedClientMessages::empty();
        for m in msgs {
            if m.round_number != round {
                return Err(ProtocolError::WrongRound {
                    got: m.round_number,
                    expected: round,
                });
            }
            agg.union_inplace(m)?;
        }
        Ok(agg)
    }
}

pub struct ClientMessager<'a> {
    pub config: &'a AdcNetConfig,
    pub shared_secrets: &'a HashMap<ServerId, SharedKey>,
}

impl<'a> ClientMessager<'a> {
    /// Resolve whether this client won a slot in the previous round's auction
    /// and where to place its message.
    pub fn process_previous_auction(
        &self,
        auction_iblt: &IbltVector,
        previous_round_message: &[u8],
    ) -> AuctionResult {
        let entries = match auction_iblt.recover() {
            Ok(c) => c,
            Err(_) => return AuctionResult::default(),
        };

        let bids: Vec<AuctionData> = entries
            .iter()
            .map(|e| AuctionData::from_values(&e.values))
            .collect();
        let engine = AuctionEngine::new(self.config.message_length as u32, 1);
        let winners = engine.run_auction(&bids);

        let total_allocated: usize = winners.iter().map(|w| w.slot_size as usize).sum();

        let our_hash_truncated: [u8; AUCTION_HASH_TRUNC_BYTES] = {
            let mut h = Sha256::new();
            h.update(previous_round_message);
            let out = h.finalize();
            let mut arr = [0u8; AUCTION_HASH_TRUNC_BYTES];
            arr.copy_from_slice(&out[..AUCTION_HASH_TRUNC_BYTES]);
            arr
        };
        for w in &winners {
            if w.bid.truncated_hash() == our_hash_truncated {
                return AuctionResult {
                    should_send: true,
                    message_start_index: w.slot_idx as usize,
                    total_allocated,
                };
            }
        }
        AuctionResult { should_send: false, message_start_index: 0, total_allocated }
    }

    /// Build a (still unsigned) ClientRoundMessage for `current_round`.
    /// Returns the message plus whether the client won the previous-round auction.
    pub fn prepare_message(
        &self,
        current_round: i64,
        previous: &RoundBroadcast,
        previous_round_message: &[u8],
        current_round_auction_data: Option<&AuctionData>,
    ) -> Result<(ClientRoundMessage, bool), ProtocolError> {
        if previous.round_number + 1 != current_round {
            return Err(ProtocolError::UnknownPreviousRound);
        }
        let prev_result =
            self.process_previous_auction(&previous.auction_vector, previous_round_message);

        let mut auction_iblt =
            IbltVector::new_with_xi(self.config.auction_slots, AUCTION_BID_XI);
        if let Some(ad) = current_round_auction_data {
            let values = ad.encode_values();
            let slices: [&[u8]; AUCTION_BID_XI] =
                [&values[0], &values[1], &values[2], &values[3]];
            // Deterministic per-round per-client key — uses the current round
            // number combined with this client's auction bid hash. The
            // randomness comes from the bid contents; if a client never
            // re-uses a bid in a round, keys are effectively unique.
            let mut key = [0u8; AUCTION_KEY_BYTES];
            let mut h = Sha256::new();
            h.update(b"adcnet-auction-key");
            h.update(current_round.to_be_bytes());
            h.update(ad.message_hash);
            let digest = h.finalize();
            key.copy_from_slice(&digest[..AUCTION_KEY_BYTES]);
            auction_iblt.insert(&key, &slices)?;
        }
        let auction_elements = auction_iblt.encode_as_field_elements();

        let mut message_vector = vec![0u8; prev_result.total_allocated];
        if prev_result.should_send {
            let start = prev_result.message_start_index;
            let end = start + previous_round_message.len();
            if end > message_vector.len() {
                return Err(ProtocolError::MessageExceedsAllocatedSlot {
                    needed: previous_round_message.len(),
                    available: message_vector.len().saturating_sub(start),
                });
            }
            message_vector[start..end].copy_from_slice(previous_round_message);
        }

        let client_message = self.blind(current_round, message_vector, auction_elements)?;
        Ok((client_message, prev_result.should_send))
    }

    /// Apply field- and XOR-blinding using shared secrets with all servers.
    pub fn blind(
        &self,
        current_round: i64,
        message_vector: Vec<u8>,
        auction_elements: Vec<u64>,
    ) -> Result<ClientRoundMessage, ProtocolError> {
        let mut server_ids: Vec<ServerId> = self.shared_secrets.keys().copied().collect();
        server_ids.sort();

        let auction_secrets: Vec<SharedKey> = server_ids
            .iter()
            .map(|sid| domain_prefixed(&self.shared_secrets[sid], 0))
            .collect();
        let message_secrets: Vec<SharedKey> = server_ids
            .iter()
            .map(|sid| domain_prefixed(&self.shared_secrets[sid], 1))
            .collect();

        let mut blinded_auction = auction_elements;
        let auction_pad = derive_blinding_vector(
            &auction_secrets,
            current_round as u32,
            blinded_auction.len(),
        );
        add_mod_slice(&mut blinded_auction, &auction_pad);

        let mut blinded_message = message_vector;
        let message_pad = derive_xor_blinding_vector(
            &message_secrets,
            current_round as u32,
            blinded_message.len(),
        );
        xor_inplace(&mut blinded_message, &message_pad);

        Ok(ClientRoundMessage {
            round_number: current_round,
            all_server_ids: server_ids,
            auction_vector: blinded_auction,
            message_vector: blinded_message,
        })
    }
}

