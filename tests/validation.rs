use adcnet::auction::iblt::{IbltError, IbltVector};
use adcnet::crypto::{fields::P, generate_keypair, PrivateKey, PublicKey, ServerId, SharedKey};
use adcnet::protocol::messages::{AggregatedClientMessages, ProtocolError};
use adcnet::session::one_round::{
    combine_round, ClientContribution, IbltMsgParamsOwned, OneRoundConfig, OneRoundError,
    ServerShare,
};
use adcnet::{AuctionData, AuctionEngine};

fn aggregate(round: i64) -> AggregatedClientMessages {
    AggregatedClientMessages {
        round_number: round,
        all_server_ids: vec![ServerId(1)],
        auction_vector: vec![0; 4],
        message_vector: vec![0; 4],
        user_pks: vec![generate_keypair().0],
    }
}

#[test]
fn round_zero_cannot_merge_with_another_round() {
    let mut a = aggregate(0);
    let before = bincode::serialize(&a).unwrap();
    assert!(matches!(
        a.union_inplace(&aggregate(1)),
        Err(ProtocolError::MismatchingRounds)
    ));
    assert_eq!(bincode::serialize(&a).unwrap(), before);
}

#[test]
fn duplicate_members_inside_a_batch_are_rejected_atomically() {
    let mut a = AggregatedClientMessages::empty();
    let mut b = aggregate(1);
    b.user_pks.push(b.user_pks[0].clone());
    let before = bincode::serialize(&a).unwrap();
    assert!(matches!(
        a.union_inplace(&b),
        Err(ProtocolError::DuplicateSubmission(_))
    ));
    assert_eq!(bincode::serialize(&a).unwrap(), before);
}

#[test]
fn noncanonical_aggregate_is_rejected() {
    let mut a = aggregate(1);
    let mut b = aggregate(1);
    b.auction_vector[0] = u64::MAX;
    assert!(matches!(
        a.union_inplace(&b),
        Err(ProtocolError::NonCanonicalFieldElement)
    ));
}

#[test]
fn one_round_rejects_invalid_vectors_without_panicking() {
    let cfg = OneRoundConfig {
        iblt: IbltMsgParamsOwned {
            estimated_messages: 2,
            max_payload_bytes: 32,
        },
    };
    let len = cfg.iblt.as_params().encoded_len();
    for bad_len in [0, len - 1, len + 1] {
        let clients = [ClientContribution {
            round: 7,
            blinded: vec![0; bad_len],
        }];
        let servers = [ServerShare {
            server_id: ServerId(1),
            round: 7,
            share: vec![0; len],
        }];
        assert!(matches!(
            combine_round(&cfg, 7, &clients, &servers, 1),
            Err(OneRoundError::Protocol(
                ProtocolError::MismatchingVectorLengths
            ))
        ));
        let clients = [ClientContribution {
            round: 7,
            blinded: vec![0; len],
        }];
        let servers = [ServerShare {
            server_id: ServerId(1),
            round: 7,
            share: vec![0; bad_len],
        }];
        assert!(matches!(
            combine_round(&cfg, 7, &clients, &servers, 1),
            Err(OneRoundError::Protocol(
                ProtocolError::MismatchingVectorLengths
            ))
        ));
    }
    for bad in [P, u64::MAX] {
        let clients = [ClientContribution {
            round: 7,
            blinded: vec![bad; len],
        }];
        let servers = [ServerShare {
            server_id: ServerId(1),
            round: 7,
            share: vec![0; len],
        }];
        assert!(matches!(
            combine_round(&cfg, 7, &clients, &servers, 1),
            Err(OneRoundError::NonCanonicalFieldElement)
        ));
    }
    let servers = [ServerShare {
        server_id: ServerId(1),
        round: 7,
        share: vec![0; len],
    }];
    assert!(combine_round(&cfg, 7, &[], &servers, 1).unwrap().is_empty());
}

#[test]
fn iblt_rejects_nonzero_residue_with_zero_counters() {
    let mut iblt = IbltVector::new_with_xi(2, 1);
    iblt.values[0] = 1;
    assert!(matches!(iblt.recover(), Err(IbltError::PeelStalled)));
    iblt.values[0] = 0;
    iblt.keys[0] = 1;
    assert!(matches!(iblt.recover(), Err(IbltError::PeelStalled)));
}

#[test]
fn iblt_rejects_malformed_shapes_and_unrepresentable_payloads() {
    let mut iblt = IbltVector::new_with_xi(2, 1);
    iblt.values.clear();
    assert!(matches!(iblt.recover(), Err(IbltError::InvalidShape)));
    let mut iblt = IbltVector::new_with_xi(2, 1);
    iblt.insert(&[1; 7], &[&[2; 7]]).unwrap();
    for (count, value) in iblt.counters.iter().zip(&mut iblt.values) {
        if *count == 1 {
            *value = 1 << 56;
        }
    }
    assert!(matches!(
        iblt.recover(),
        Err(IbltError::InvalidPackedElement)
    ));
    let mut elements = iblt.encode_as_field_elements();
    elements[0] = P;
    assert!(matches!(
        iblt.decode_from_elements(&elements),
        Err(IbltError::NonCanonicalFieldElement)
    ));
}

#[test]
fn auction_handles_zero_size_and_large_total_weight() {
    let bids = [
        AuctionData {
            message_hash: [1; 32],
            weight: u32::MAX,
            size: 0,
        },
        AuctionData {
            message_hash: [2; 32],
            weight: u32::MAX,
            size: 1,
        },
    ];
    let winners = AuctionEngine::with_chunk_bytes(2, 0, 1).run_auction(&bids);
    assert_eq!(winners.len(), 2);
    assert_eq!(
        winners.iter().map(|w| u64::from(w.bid.weight)).sum::<u64>(),
        2 * u64::from(u32::MAX)
    );
}

#[test]
fn reduce_accepts_the_full_u64_range() {
    for x in [0, P - 1, P, 2 * P, u64::MAX] {
        assert_eq!(adcnet::crypto::fields::reduce(x), x % P);
    }
}

#[test]
fn secret_debug_output_is_redacted() {
    assert_eq!(
        format!("{:?}", PrivateKey::from_bytes(&[42; 64])),
        "PrivateKey([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", SharedKey::from_bytes(&[42; 32])),
        "SharedKey([REDACTED])"
    );
}

#[test]
fn aggregator_does_not_mix_server_rosters() {
    use adcnet::protocol::messager::{AggregatorMessager, VerifiedClientMessage};
    use adcnet::{AdcNetConfig, ClientRoundMessage};
    use std::collections::HashMap;
    let config = AdcNetConfig::default();
    let len = adcnet::auction::iblt::iblt_field_element_count(config.auction_slots, 4);
    let keys: Vec<PublicKey> = (0..2).map(|_| generate_keypair().0).collect();
    let authorized: HashMap<_, _> = keys.iter().map(|pk| (pk.to_hex(), true)).collect();
    let messages: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, pk)| VerifiedClientMessage {
            signer: pk.clone(),
            message: ClientRoundMessage {
                round_number: 1,
                all_server_ids: vec![ServerId(i as u32 + 1)],
                auction_vector: vec![0; len],
                message_vector: vec![],
            },
        })
        .collect();
    let agg = AggregatorMessager { config: &config }
        .aggregate_verified_messages(1, None, &messages, &authorized)
        .unwrap();
    assert_eq!(agg.user_pks, vec![keys[0].clone()]);
}
