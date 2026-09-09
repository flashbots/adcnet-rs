//! End-to-end protocol smoke tests.
//!
//! Covers message recovery through the messager, aggregator, and direct-server paths.

use std::collections::HashMap;

use adcnet::auction::auction::{AuctionData, AUCTION_BID_XI};
use adcnet::auction::iblt::IbltVector;
use adcnet::crypto::types::{generate_keypair, ExchangePrivateKey};
use adcnet::crypto::SharedKey;
use adcnet::encoders::auction_iblt;
use adcnet::protocol::messager::{
    AggregatorMessager, ClientMessager, ServerMessager, VerifyClientMessages,
};
use adcnet::protocol::messages::{RoundBroadcast, Signed};
use adcnet::protocol::services::ServerService;
use adcnet::protocol::{AdcNetConfig, AggregationMode, Round, RoundContext};
use adcnet::ServerId;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn shared(path: &str) -> SharedKey {
    SharedKey::from_bytes(path.as_bytes())
}

#[test]
fn blinding_client_roundtrip_against_handcrafted_pads() {
    let config = AdcNetConfig {
        auction_slots: 10,
        message_length: 20,
        ..Default::default()
    };
    let mut secrets = HashMap::new();
    secrets.insert(ServerId(1), shared("c1s1"));
    secrets.insert(ServerId(2), shared("c1s2"));
    let c = ClientMessager { config: &config, shared_secrets: &secrets };

    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let mut auction = IbltVector::new_with_xi(config.auction_slots, AUCTION_BID_XI);
    auction_iblt::insert_bid(
        &mut auction,
        &AuctionData { message_hash: [0; 32], weight: 10, size: 8 },
        &mut rng,
    )
    .unwrap();

    let mut msg = vec![0u8; 20];
    msg[0] = 0x0a;
    let round_msg = c.blind(1, msg.clone(), auction.encode_as_field_elements()).unwrap();

    // Recompute the server-side pads and unblind by XOR with both shares.
    let mut s1 = adcnet::crypto::derive_xor_blinding_vector(
        &[SharedKey::from_bytes(&[&[1u8][..], b"c1s1"].concat())],
        1,
        config.message_length,
    );
    let s2 = adcnet::crypto::derive_xor_blinding_vector(
        &[SharedKey::from_bytes(&[&[1u8][..], b"c1s2"].concat())],
        1,
        config.message_length,
    );
    adcnet::crypto::xor_inplace(&mut s1, &s2);
    let mut unblinded = round_msg.message_vector.clone();
    adcnet::crypto::xor_inplace(&mut unblinded, &s1);
    assert_eq!(unblinded, msg);
}

#[test]
fn e2e_three_clients_three_servers_via_aggregator() {
    let config = AdcNetConfig {
        auction_slots: 10,
        // 2 KiB = 2 × KNAPSACK_CHUNK_BYTES → exactly two 1-KiB slots fit.
        message_length: 2 * 1024,
        ..Default::default()
    };

    // Set up 3 servers (just sharedkey maps) and 3 clients with mutual fake shared secrets.
    let mut servers_secrets: Vec<HashMap<String, SharedKey>> = vec![HashMap::new(); 3];
    let mut client_keys = Vec::new();
    let mut client_pubkeys = HashMap::new();
    let mut client_secrets: Vec<HashMap<ServerId, SharedKey>> = vec![HashMap::new(); 3];

    for (c, csec) in client_secrets.iter_mut().enumerate() {
        let (pk, sk) = generate_keypair();
        client_pubkeys.insert(pk.to_hex(), true);
        client_keys.push(sk);
        for (s, ssec) in servers_secrets.iter_mut().enumerate() {
            let path = format!("c{}s{}", c, s);
            let sec = SharedKey::from_bytes(path.as_bytes());
            csec.insert(ServerId((s + 1) as u32), sec.clone());
            ssec.insert(pk.to_hex(), sec);
        }
    }

    // Construct previous-round broadcast: an IBLT containing 3 bids.
    let mut prev_iblt = IbltVector::new_with_xi(config.auction_slots, AUCTION_BID_XI);
    let msgs_data: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            let mut v = vec![0u8; if i == 0 { 63 } else if i == 1 { 65 } else { 66 }];
            for b in v.iter_mut() {
                *b = (i + 1) as u8;
            }
            v
        })
        .collect();
    let mut prev_rng = ChaCha20Rng::from_seed([7; 32]);
    for m in &msgs_data {
        auction_iblt::insert_bid(
            &mut prev_iblt,
            &AuctionData::from_message(m, 10),
            &mut prev_rng,
        )
        .unwrap();
    }
    let prev_bc = RoundBroadcast {
        round_number: 1,
        auction_vector: prev_iblt,
        message_vector: Vec::new(),
    };

    // Each client prepares a round-2 message, also bidding into round 2's
    // auction. Clients 0 and 1 bid identical content: with a deterministic
    // per-round/content IBLT key the two bids would collide and the
    // round-2 auction vector would fail to recover.
    let identical_bid_msg = vec![9u8; 40];
    let mut cur_rng = ChaCha20Rng::from_seed([9; 32]);
    let mut client_msgs: Vec<Signed<adcnet::protocol::messages::ClientRoundMessage>> = Vec::new();
    let mut talking = 0;
    for c in 0..3 {
        let cm = ClientMessager { config: &config, shared_secrets: &client_secrets[c] };
        let bid = if c < 2 {
            AuctionData::from_message(&identical_bid_msg, 10)
        } else {
            AuctionData::from_message(&msgs_data[c], 10)
        };
        let (msg, won) = cm
            .prepare_message(2, &prev_bc, &msgs_data[c], Some(&bid), &mut cur_rng)
            .unwrap();
        if won {
            talking += 1;
        }
        let signed = Signed::new(&client_keys[c], msg).unwrap();
        client_msgs.push(signed);
    }
    assert_eq!(talking, 2);

    // Aggregator combines them. A replayed copy of client 0's message is
    // folded into the same batch: the duplicate signer is skipped, not
    // erred, so the aggregate and downstream assertions stay unaffected.
    let agg = AggregatorMessager { config: &config };
    let mut replayed_msgs = client_msgs.clone();
    replayed_msgs.push(client_msgs[0].clone());
    let mut verified = VerifyClientMessages::verify(&replayed_msgs).unwrap();
    let client0 = verified[0].clone();
    // A stale previous-round message in the batch is skipped, not a batch
    // error — and, placed first, must not shadow the signer's valid message.
    let mut stale = verified[1].clone();
    stale.message.round_number = 1;
    verified.insert(0, stale);
    // A wrong-length auction vector is likewise skipped, not truncated-folded.
    let mut short = verified[1].clone();
    short.message.auction_vector.truncate(short.message.auction_vector.len() - 1);
    verified.insert(0, short);
    // A non-canonical field element must not survive wire decode.
    let mut noncanonical = client0.message.clone();
    noncanonical.auction_vector[0] = adcnet::crypto::P;
    let bytes = bincode::serialize(&noncanonical).unwrap();
    bincode::deserialize::<adcnet::protocol::messages::ClientRoundMessage>(&bytes).unwrap_err();
    let aggregated = agg
        .aggregate_verified_messages(2, None, &verified, &client_pubkeys)
        .unwrap();
    assert_eq!(aggregated.user_pks.len(), 3, "replayed signer must not double-count");

    // Cross-call replay: re-submitting client 0's already-folded message as a
    // fresh batch against `previous = Some(&aggregated)` is also a no-op.
    let idempotent = agg
        .aggregate_verified_messages(2, Some(&aggregated), std::slice::from_ref(&client0), &client_pubkeys)
        .unwrap();
    assert_eq!(idempotent.user_pks, aggregated.user_pks);
    assert_eq!(idempotent.auction_vector, aggregated.auction_vector);
    assert_eq!(idempotent.message_vector, aggregated.message_vector);

    // Backstop: unioning an aggregate with itself must be rejected, not
    // silently double-added.
    let err = aggregated.clone().union_inplace(&aggregated).unwrap_err();
    assert!(
        matches!(err, adcnet::protocol::messages::ProtocolError::DuplicateSubmission(_)),
        "got {err:?}"
    );

    // Each server computes its partial decryption.
    let mut partials = Vec::new();
    for (s, ssec) in servers_secrets.iter().enumerate() {
        let sm = ServerMessager {
            config: &config,
            server_id: ServerId((s + 1) as u32),
            shared_secrets: ssec,
        };
        partials.push(sm.unblind_aggregate(2, &aggregated).unwrap());
    }

    // Server 0 combines partials → broadcast.
    let final_msger = ServerMessager {
        config: &config,
        server_id: ServerId(1),
        shared_secrets: &servers_secrets[0],
    };
    let bc = final_msger.unblind_partial_messages(&mut partials).unwrap();

    // All 3 round-2 bids (including the two identical ones) must decode.
    assert_eq!(bc.auction_vector.recover().unwrap().len(), 3);

    // The two winning messages must appear somewhere in the message vector.
    let mut found = 0;
    for start in 0..config.message_length {
        for m in &msgs_data {
            if start + m.len() <= bc.message_vector.len()
                && &bc.message_vector[start..start + m.len()] == m.as_slice()
            {
                found += 1;
            }
        }
    }
    assert_eq!(found, 2, "msg vector = {:?}", bc.message_vector);
}

#[test]
fn e2e_disabled_aggregation_via_server_service() {
    let config = AdcNetConfig {
        auction_slots: 10,
        // 3 KiB = 3 × KNAPSACK_CHUNK_BYTES → up to three 1-KiB slots fit.
        message_length: 3 * 1024,
        aggregation: AggregationMode::Disabled,
        ..Default::default()
    };

    // 3 servers — full ServerService instances using real ECDH this time.
    let mut servers: Vec<ServerService> = Vec::new();
    let mut server_pubs: Vec<(ServerId, adcnet::crypto::ExchangePublicKey)> = Vec::new();
    let mut server_signing_pubs: Vec<(ServerId, adcnet::crypto::PublicKey)> = Vec::new();
    for s in 0..3 {
        let (pk, sk) = generate_keypair();
        let xk = ExchangePrivateKey::generate();
        let sid = ServerId((s + 1) as u32);
        server_pubs.push((sid, xk.public()));
        server_signing_pubs.push((sid, pk));
        servers.push(ServerService::new(config.clone(), sid, sk, xk));
    }
    // Cross-register peer signing pubkeys so the trusted server set is known.
    for srv in servers.iter() {
        for (sid, pk) in &server_signing_pubs {
            srv.register_peer_server(*sid, pk.clone());
        }
    }
    for s in servers.iter() {
        s.advance_to_round(Round::new(2, RoundContext::Client));
    }

    // 3 clients. Each does ECDH with each server to derive the same shared secret.
    let mut client_keys = Vec::new();
    let mut client_pubs = Vec::new();
    let mut client_secrets: Vec<HashMap<ServerId, SharedKey>> = vec![HashMap::new(); 3];
    let mut client_xks: Vec<ExchangePrivateKey> = Vec::new();
    for _c in 0..3 {
        let (pk, sk) = generate_keypair();
        let xk = ExchangePrivateKey::generate();
        for (sid, server_xpub) in &server_pubs {
            let s = xk.ecdh(server_xpub);
            client_secrets[client_keys.len()].insert(*sid, s);
        }
        client_pubs.push(pk);
        client_keys.push(sk);
        client_xks.push(xk);
    }
    // Register clients with servers.
    for (i, server) in servers.iter().enumerate() {
        for c in 0..3 {
            server.register_client(&client_pubs[c], &client_xks[c].public()).unwrap();
        }
        let _ = i;
    }

    // Build previous-round broadcast.
    let mut prev_iblt = IbltVector::new_with_xi(config.auction_slots, AUCTION_BID_XI);
    let msgs_data: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            let mut v = vec![0u8; 32 + i * 8];
            for b in v.iter_mut() {
                *b = (i + 7) as u8;
            }
            v
        })
        .collect();
    let mut prev_rng = ChaCha20Rng::from_seed([7; 32]);
    for m in &msgs_data {
        auction_iblt::insert_bid(
            &mut prev_iblt,
            &AuctionData::from_message(m, 10),
            &mut prev_rng,
        )
        .unwrap();
    }
    let prev_bc = RoundBroadcast {
        round_number: 1,
        auction_vector: prev_iblt,
        message_vector: Vec::new(),
    };

    // Each client builds and signs its message directly.
    let mut signed_msgs = Vec::new();
    for c in 0..3 {
        let cm = ClientMessager { config: &config, shared_secrets: &client_secrets[c] };
        let (msg, _won) = cm
            .prepare_message(2, &prev_bc, &msgs_data[c], None, &mut prev_rng)
            .unwrap();
        let signed = Signed::new(&client_keys[c], msg).unwrap();
        signed_msgs.push(signed);
    }

    // Feed each client message directly into every server (aggregation off).
    for signed in &signed_msgs {
        for server in &servers {
            server.process_client_message(signed).unwrap();
        }
    }

    // Replaying client 0's message into a server that already folded it
    // must be rejected, not silently double-folded or self-cancelled.
    let err = servers[0].process_client_message(&signed_msgs[0]).unwrap_err();
    assert!(
        matches!(err, adcnet::protocol::messages::ProtocolError::DuplicateSubmission(_)),
        "got {err:?}"
    );

    // Each server finalizes its partial over its accumulated direct aggregate.
    let mut partials = Vec::new();
    for server in &servers {
        partials.push(server.finalize_partial_for_direct_aggregate().unwrap());
    }

    // Server 0 combines partials.
    let mut last_out = None;
    for p in partials {
        last_out = servers[0].process_partial_decryption_message(p).unwrap();
    }
    let bc = last_out.expect("broadcast finalized");

    // Verify at least one message landed in the vector.
    let mut found = 0;
    for start in 0..config.message_length {
        for m in &msgs_data {
            if start + m.len() <= bc.message_vector.len()
                && &bc.message_vector[start..start + m.len()] == m.as_slice()
            {
                found += 1;
            }
        }
    }
    assert!(found >= 1, "expected at least one winning message; vec = {:?}", bc.message_vector);
}
