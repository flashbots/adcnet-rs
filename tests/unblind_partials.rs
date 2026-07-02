//! Adversarial-input tests for [`ServerMessager::unblind_partial_messages`].
//!
//! Confirms the guard conditions:
//! - Empty `msgs` → `EmptyPartials`.
//! - Duplicate `server_id` → `DuplicatePartial`.
//! - Mismatching `original_aggregate` across partials → `MismatchingAggregate`.
//! - Mismatching `message_vector.len()` or own `auction_vector.len()` →
//!   `MismatchingVectorLengths`.

use std::collections::HashMap;

use adcnet::crypto::SharedKey;
use adcnet::protocol::messager::ServerMessager;
use adcnet::protocol::messages::{
    AggregatedClientMessages, ProtocolError, ServerPartialDecryptionMessage,
};
use adcnet::protocol::AdcNetConfig;
use adcnet::ServerId;

fn cfg() -> AdcNetConfig {
    AdcNetConfig {
        auction_slots: 4,
        message_length: 1024,
        ..Default::default()
    }
}

fn make_messager<'a>(
    config: &'a AdcNetConfig,
    shared: &'a HashMap<String, SharedKey>,
) -> ServerMessager<'a> {
    ServerMessager {
        config,
        server_id: ServerId(1),
        shared_secrets: shared,
    }
}

fn synth_aggregate(round: i64, all_sids: Vec<ServerId>, len: usize) -> AggregatedClientMessages {
    AggregatedClientMessages {
        round_number: round,
        all_server_ids: all_sids,
        auction_vector: vec![0u64; len],
        message_vector: vec![0u8; 64],
        user_pks: Vec::new(),
    }
}

fn synth_partial(
    server_id: ServerId,
    agg: &AggregatedClientMessages,
) -> ServerPartialDecryptionMessage {
    ServerPartialDecryptionMessage {
        server_id,
        original_aggregate: agg.clone(),
        user_pks: Vec::new(),
        auction_vector: vec![0u64; agg.auction_vector.len()],
        message_vector: vec![0u8; agg.message_vector.len()],
    }
}

#[test]
fn empty_partials_errors() {
    let config = cfg();
    let shared = HashMap::new();
    let m = make_messager(&config, &shared);
    let err = m.unblind_partial_messages(&mut []).unwrap_err();
    assert!(matches!(err, ProtocolError::EmptyPartials), "got {err:?}");
}

#[test]
fn duplicate_server_id_errors() {
    let config = cfg();
    let shared = HashMap::new();
    let m = make_messager(&config, &shared);
    let sids = vec![ServerId(1), ServerId(2), ServerId(3)];
    let agg = synth_aggregate(7, sids, 24);
    let mut msgs = vec![
        synth_partial(ServerId(1), &agg),
        synth_partial(ServerId(1), &agg), // duplicate
    ];
    let err = m.unblind_partial_messages(&mut msgs).unwrap_err();
    assert!(matches!(err, ProtocolError::DuplicatePartial(_)), "got {err:?}");
}

#[test]
fn mismatching_aggregate_errors() {
    let config = cfg();
    let shared = HashMap::new();
    let m = make_messager(&config, &shared);
    let sids = vec![ServerId(1), ServerId(2)];
    let agg_a = synth_aggregate(7, sids.clone(), 24);
    let mut agg_b = agg_a.clone();
    agg_b.auction_vector[0] = 0xdead_beef;
    let mut msgs = vec![
        synth_partial(ServerId(1), &agg_a),
        synth_partial(ServerId(2), &agg_b),
    ];
    let err = m.unblind_partial_messages(&mut msgs).unwrap_err();
    assert!(matches!(err, ProtocolError::MismatchingAggregate), "got {err:?}");
}

#[test]
fn mismatching_vector_lengths_errors() {
    let config = cfg();
    let shared = HashMap::new();
    let m = make_messager(&config, &shared);
    let sids = vec![ServerId(1), ServerId(2)];
    let agg = synth_aggregate(7, sids, 24);
    let mut p1 = synth_partial(ServerId(1), &agg);
    let mut p2 = synth_partial(ServerId(2), &agg);
    p2.message_vector = vec![0u8; 32]; // shorter than head's 64
    let mut msgs = vec![p1.clone(), p2.clone()];
    let err = m.unblind_partial_messages(&mut msgs).unwrap_err();
    assert!(
        matches!(err, ProtocolError::MismatchingVectorLengths),
        "got {err:?}"
    );

    // A partial's own auction vector shorter than the aggregate's must also
    // error, not silently truncate the subtraction.
    p2.message_vector = vec![0u8; 64];
    p2.auction_vector = vec![0u64; 23];
    let mut msgs = vec![p1.clone(), p2];
    let err = m.unblind_partial_messages(&mut msgs).unwrap_err();
    assert!(
        matches!(err, ProtocolError::MismatchingVectorLengths),
        "got {err:?}"
    );
    let _ = &mut p1;
}
