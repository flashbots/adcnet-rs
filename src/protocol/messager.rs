//! Stateless protocol operations: client message preparation/blinding,
//! aggregator union, server unblinding.

use std::collections::HashMap;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::auction::auction::{AuctionData, AuctionEngine, AUCTION_BID_XI, AUCTION_HASH_TRUNC_BYTES};
use crate::auction::iblt::{iblt_field_element_count, IbltVector};
use crate::encoders::auction_iblt;
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
        let auction_len = head.original_aggregate.auction_vector.len();
        if head.auction_vector.len() != auction_len
            || msg_len != head.original_aggregate.message_vector.len()
        {
            return Err(ProtocolError::MismatchingVectorLengths);
        }
        for m in &msgs[1..] {
            if m.original_aggregate.round_number != head.original_aggregate.round_number
                || m.original_aggregate.all_server_ids
                    != head.original_aggregate.all_server_ids
                || m.original_aggregate.auction_vector
                    != head.original_aggregate.auction_vector
                || m.original_aggregate.message_vector
                    != head.original_aggregate.message_vector
                || m.original_aggregate.user_pks != head.original_aggregate.user_pks
            {
                return Err(ProtocolError::MismatchingAggregate);
            }
            if m.message_vector.len() != msg_len || m.auction_vector.len() != auction_len {
                return Err(ProtocolError::MismatchingVectorLengths);
            }
        }

        let expected: std::collections::HashSet<_> =
            head.original_aggregate.all_server_ids.iter().copied().collect();
        if expected.len() != head.original_aggregate.all_server_ids.len()
            || msgs.len() != expected.len()
            || msgs.iter().any(|m| !expected.contains(&m.server_id))
        {
            return Err(ProtocolError::MismatchingServers);
        }
        if msgs.iter().any(|m| m.user_pks != head.original_aggregate.user_pks) {
            return Err(ProtocolError::MismatchingAggregate);
        }
        if head.original_aggregate.auction_vector.iter()
            .chain(msgs.iter().flat_map(|m| &m.auction_vector))
            .any(|&x| x >= crate::crypto::fields::P)
        {
            return Err(ProtocolError::NonCanonicalFieldElement);
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

        if aggregate.auction_vector.len()
            != iblt_field_element_count(self.config.auction_slots, AUCTION_BID_XI)
        {
            return Err(ProtocolError::MismatchingVectorLengths);
        }
        if aggregate.auction_vector.iter().any(|&x| x >= crate::crypto::fields::P) {
            return Err(ProtocolError::NonCanonicalFieldElement);
        }
        let mut seen = std::collections::HashSet::with_capacity(aggregate.user_pks.len());
        for pk in &aggregate.user_pks {
            if !seen.insert(pk) {
                return Err(ProtocolError::DuplicateSubmission(pk.to_hex()));
            }
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
        // Skip bad messages and replays instead of failing the whole batch.
        let expected_auction =
            iblt_field_element_count(self.config.auction_slots, AUCTION_BID_XI);
        let mut shape = (!agg.auction_vector.is_empty())
            .then_some((agg.all_server_ids.as_slice(), agg.message_vector.len()));
        let mut seen: std::collections::HashSet<&PublicKey> = agg.user_pks.iter().collect();
        let fresh: Vec<&VerifiedClientMessage> = verified
            .iter()
            .filter(|v| {
                if v.message.round_number != round
                    || !authorized.get(&v.signer.to_hex()).copied().unwrap_or(false)
                    || v.message.auction_vector.len() != expected_auction
                    || v.message.auction_vector.iter().any(|&x| x >= crate::crypto::fields::P)
                {
                    return false;
                }
                let candidate = (v.message.all_server_ids.as_slice(), v.message.message_vector.len());
                if shape.is_some_and(|expected| expected != candidate) || !seen.insert(&v.signer) {
                    return false;
                }
                shape = Some(candidate);
                true
            })
            .collect();

        if fresh.is_empty() {
            return Ok(agg);
        }

        let auction_len = expected_auction;
        let msg_len = fresh[0].message.message_vector.len();
        let server_ids = fresh[0].message.all_server_ids.clone();
        let round_no = fresh[0].message.round_number;
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
            fresh
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
            for v in &fresh {
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
        if auction_iblt.xi != AUCTION_BID_XI {
            return AuctionResult::default();
        }
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
    pub fn prepare_message<R: Rng>(
        &self,
        current_round: i64,
        previous: &RoundBroadcast,
        previous_round_message: &[u8],
        current_round_auction_data: Option<&AuctionData>,
        rng: &mut R,
    ) -> Result<(ClientRoundMessage, bool), ProtocolError> {
        if previous.round_number + 1 != current_round {
            return Err(ProtocolError::UnknownPreviousRound);
        }
        let prev_result =
            self.process_previous_auction(&previous.auction_vector, previous_round_message);

        let mut auction_iblt =
            IbltVector::new_with_xi(self.config.auction_slots, AUCTION_BID_XI);
        if let Some(ad) = current_round_auction_data {
            auction_iblt::insert_bid(&mut auction_iblt, ad, rng)?;
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


#[cfg(test)]
mod tests {
    use super::*;

    fn contribution(config: &AdcNetConfig, client: u8, server: u32) -> VerifiedClientMessage {
        VerifiedClientMessage {
            signer: PublicKey::from_bytes(&[client; 32]),
            message: ClientRoundMessage {
                round_number: 1,
                all_server_ids: vec![ServerId(server)],
                auction_vector: vec![1; iblt_field_element_count(config.auction_slots, AUCTION_BID_XI)],
                message_vector: Vec::new(),
            },
        }
    }

    fn authorized(messages: &[VerifiedClientMessage]) -> HashMap<String, bool> {
        messages.iter().map(|m| (m.signer.to_hex(), true)).collect()
    }

    #[test]
    fn aggregation_skips_mismatched_rosters_without_consuming_signer() {
        let config = AdcNetConfig::default();
        let messager = AggregatorMessager { config: &config };
        let messages = [
            contribution(&config, 1, 1),
            contribution(&config, 2, 2),
            contribution(&config, 2, 1),
        ];
        let agg = messager.aggregate_verified_messages(1, None, &messages, &authorized(&messages)).unwrap();
        assert_eq!(agg.all_server_ids, vec![ServerId(1)]);
        assert_eq!(agg.user_pks, vec![messages[0].signer.clone(), messages[2].signer.clone()]);
        assert!(agg.auction_vector.iter().all(|&x| x == 2));
    }

    #[test]
    fn aggregation_preserves_previous_roster_and_empty_message_length() {
        let config = AdcNetConfig::default();
        let messager = AggregatorMessager { config: &config };
        let first = [contribution(&config, 1, 1)];
        let previous = messager.aggregate_verified_messages(1, None, &first, &authorized(&first)).unwrap();
        let mut messages = [contribution(&config, 2, 2), contribution(&config, 3, 1), contribution(&config, 4, 1)];
        messages[1].message.message_vector.push(1);
        let agg = messager.aggregate_verified_messages(1, Some(&previous), &messages, &authorized(&messages)).unwrap();
        assert_eq!(agg.user_pks, vec![first[0].signer.clone(), messages[2].signer.clone()]);
        assert!(agg.message_vector.is_empty());
        assert!(agg.auction_vector.iter().all(|&x| x == 2));
    }

    #[test]
    fn aggregation_skips_noncanonical_values_before_selecting_roster() {
        let config = AdcNetConfig::default();
        let messager = AggregatorMessager { config: &config };
        for value in [crate::crypto::fields::P, u64::MAX] {
            let mut messages = [contribution(&config, 1, 2), contribution(&config, 1, 1)];
            messages[0].message.auction_vector[0] = value;
            let agg = messager.aggregate_verified_messages(1, None, &messages, &authorized(&messages)).unwrap();
            assert_eq!(agg.all_server_ids, vec![ServerId(1)]);
            assert_eq!(agg.user_pks, vec![messages[1].signer.clone()]);
            assert!(agg.auction_vector.iter().all(|&x| x == 1));
        }
    }
    #[test]
    fn server_rejects_malformed_aggregates_before_deriving_shares() {
        let config = AdcNetConfig::default();
        let client = PublicKey::from_bytes(&[1; 32]);
        let shared = HashMap::from([(client.to_hex(), SharedKey::from_bytes(&[2; 32]))]);
        let server = ServerMessager { config: &config, server_id: ServerId(1), shared_secrets: &shared };
        let aggregate = AggregatedClientMessages {
            round_number: 1,
            all_server_ids: vec![ServerId(1)],
            auction_vector: vec![0; iblt_field_element_count(config.auction_slots, AUCTION_BID_XI)],
            message_vector: vec![],
            user_pks: vec![client.clone()],
        };
        let len = aggregate.auction_vector.len();
        for bad_len in [0, len - 1, len + 1] {
            let mut bad = aggregate.clone();
            bad.auction_vector.resize(bad_len, 0);
            assert!(matches!(server.unblind_aggregate(1, &bad), Err(ProtocolError::MismatchingVectorLengths)));
        }
        for value in [crate::crypto::fields::P, u64::MAX] {
            let mut bad = aggregate.clone();
            bad.auction_vector[0] = value;
            assert!(matches!(server.unblind_aggregate(1, &bad), Err(ProtocolError::NonCanonicalFieldElement)));
        }
        let mut duplicate = aggregate.clone();
        duplicate.user_pks.push(client);
        assert!(matches!(server.unblind_aggregate(1, &duplicate), Err(ProtocolError::DuplicateSubmission(_))));
        assert!(server.unblind_aggregate(1, &aggregate).is_ok());
    }

    #[test]
    fn previous_auction_rejects_non_bid_layouts() {
        let config = AdcNetConfig::default();
        let shared = HashMap::new();
        let client = ClientMessager { config: &config, shared_secrets: &shared };
        for xi in [0, 1, 2, 3, 5] {
            let mut table = IbltVector::new_with_xi(config.auction_slots, xi);
            let values = vec![&[1u8; 7][..]; xi];
            table.insert(&[2; 7], &values).unwrap();
            let result = client.process_previous_auction(&table, b"payload");
            assert!(!result.should_send);
            assert_eq!(result.total_allocated, 0);
        }
    }

}
