//! Integrity tests for the signed-partial intake (PR 5).
//!
//! Verifies that:
//! - A partial signed by peer A but claiming `server_id = B` is rejected
//!   with `SignerIdentityMismatch` against `B`'s registered pubkey.
//! - A partial whose `server_id` has no registered pubkey is rejected with
//!   `UnknownPeerServer`.
//! - Two well-signed partials from the same peer in one round are rejected
//!   with `DuplicatePartial`.
//! - The happy path (S signed partials from S distinct peers) reconstructs
//!   the broadcast.

use std::collections::HashMap;

use adcnet::auction::auction::{AuctionData, AUCTION_BID_XI};
use adcnet::auction::iblt::IbltVector;
use adcnet::crypto::types::{generate_keypair, ExchangePrivateKey};
use adcnet::crypto::SharedKey;
use adcnet::encoders::auction_iblt;
use adcnet::protocol::messager::ClientMessager;
use adcnet::protocol::messages::{ProtocolError, RoundBroadcast, Signed};
use adcnet::protocol::services::ServerService;
use adcnet::protocol::{AdcNetConfig, AggregationMode, Round, RoundContext};
use adcnet::ServerId;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn config() -> AdcNetConfig {
    AdcNetConfig {
        auction_slots: 10,
        message_length: 3 * 1024,
        aggregation: AggregationMode::Disabled,
        ..Default::default()
    }
}

struct Fixture {
    servers: Vec<ServerService>,
    server_pubs: Vec<adcnet::crypto::PublicKey>,
    prev_bc: RoundBroadcast,
    msgs_data: Vec<Vec<u8>>,
    client_priv: Vec<adcnet::crypto::PrivateKey>,
    client_secrets: Vec<HashMap<ServerId, SharedKey>>,
}

fn build_fixture() -> Fixture {
    let config = config();
    let mut servers: Vec<ServerService> = Vec::new();
    let mut server_pubs = Vec::new();
    let mut server_xpubs = Vec::new();
    for s in 0..3 {
        let (pk, sk) = generate_keypair();
        let xk = ExchangePrivateKey::generate();
        let sid = ServerId((s + 1) as u32);
        server_pubs.push(pk.clone());
        server_xpubs.push((sid, xk.public()));
        servers.push(ServerService::new(config.clone(), sid, sk, xk));
    }
    // Cross-register peer pubkeys so signed partials can be verified.
    for (i, srv) in servers.iter().enumerate() {
        for (j, pk) in server_pubs.iter().enumerate() {
            if i != j {
                srv.register_peer_server(ServerId((j + 1) as u32), pk.clone());
            }
        }
    }
    for s in servers.iter() {
        s.advance_to_round(Round::new(2, RoundContext::Client));
    }

    // 2 clients (smaller than e2e to keep this test fast).
    let mut client_priv = Vec::new();
    let mut client_pubs = Vec::new();
    let mut client_xks: Vec<ExchangePrivateKey> = Vec::new();
    let mut client_secrets: Vec<HashMap<ServerId, SharedKey>> = vec![HashMap::new(); 2];
    for _c in 0..2 {
        let (pk, sk) = generate_keypair();
        let xk = ExchangePrivateKey::generate();
        for (sid, xpub) in &server_xpubs {
            client_secrets[client_priv.len()].insert(*sid, xk.ecdh(xpub));
        }
        client_pubs.push(pk);
        client_priv.push(sk);
        client_xks.push(xk);
    }
    for srv in servers.iter() {
        for c in 0..2 {
            srv.register_client(&client_pubs[c], &client_xks[c].public()).unwrap();
        }
    }

    let msgs_data: Vec<Vec<u8>> = (0..2)
        .map(|i| {
            let mut v = vec![0u8; 32 + i * 8];
            for b in v.iter_mut() {
                *b = (i + 7) as u8;
            }
            v
        })
        .collect();
    let mut prev_iblt = IbltVector::new_with_xi(config.auction_slots, AUCTION_BID_XI);
    let mut prev_rng = ChaCha20Rng::from_seed([13; 32]);
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

    Fixture {
        servers,
        server_pubs,
        prev_bc,
        msgs_data,
        client_priv,
        client_secrets,
    }
}

fn build_partials(f: &Fixture) -> Vec<adcnet::protocol::messages::ServerPartialDecryptionMessage> {
    let cfg = config();
    // Each client builds + signs its message; each server folds in.
    for c in 0..2 {
        let cm = ClientMessager { config: &cfg, shared_secrets: &f.client_secrets[c] };
        let (raw, _) = cm.prepare_message(2, &f.prev_bc, &f.msgs_data[c], None).unwrap();
        let signed = Signed::new(&f.client_priv[c], raw).unwrap();
        for srv in &f.servers {
            srv.process_client_message(&signed).unwrap();
        }
    }
    f.servers
        .iter()
        .map(|s| s.finalize_partial_for_direct_aggregate().unwrap())
        .collect()
}

#[test]
fn signer_identity_mismatch_rejected() {
    let f = build_fixture();
    let partials = build_partials(&f);
    // server[1] signs its own partial but rewrites the claimed server_id to 1
    // (impersonating server[0]).
    let mut p = partials[1].clone();
    p.server_id = ServerId(1);
    let forged = f.servers[1].sign_partial(p).unwrap();
    let leader = &f.servers[0];
    let err = leader
        .process_signed_partial_decryption_message(forged)
        .unwrap_err();
    assert!(
        matches!(err, ProtocolError::SignerIdentityMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn unknown_peer_rejected() {
    let f = build_fixture();
    let partials = build_partials(&f);
    // server[2] signs a partial claiming an unregistered server_id 99.
    let mut p = partials[2].clone();
    p.server_id = ServerId(99);
    p.original_aggregate.all_server_ids = vec![ServerId(1), ServerId(2), ServerId(99)];
    let forged = f.servers[2].sign_partial(p).unwrap();
    let leader = &f.servers[0];
    let err = leader
        .process_signed_partial_decryption_message(forged)
        .unwrap_err();
    assert!(matches!(err, ProtocolError::UnknownPeerServer(ServerId(99))), "got {err:?}");
}

#[test]
fn duplicate_from_same_signer_rejected() {
    let f = build_fixture();
    let partials = build_partials(&f);
    let leader = &f.servers[0];
    // First submission of server[1]'s real partial — accepted.
    let signed_first = f.servers[1].sign_partial(partials[1].clone()).unwrap();
    leader
        .process_signed_partial_decryption_message(signed_first)
        .unwrap();
    // Replay: same server_id, same signer. Rejected.
    let signed_dup = f.servers[1].sign_partial(partials[1].clone()).unwrap();
    let err = leader
        .process_signed_partial_decryption_message(signed_dup)
        .unwrap_err();
    assert!(matches!(err, ProtocolError::DuplicatePartial(ServerId(2))), "got {err:?}");
}

#[test]
fn happy_path_reconstructs_broadcast() {
    let f = build_fixture();
    let partials = build_partials(&f);
    let leader = &f.servers[0];
    let mut last = None;
    for (i, srv) in f.servers.iter().enumerate() {
        let signed = srv.sign_partial(partials[i].clone()).unwrap();
        last = leader
            .process_signed_partial_decryption_message(signed)
            .unwrap();
    }
    let bc = last.expect("broadcast reconstructed");
    let mut found = 0;
    for start in 0..f.msgs_data[0].len().max(f.msgs_data[1].len()) + bc.message_vector.len() {
        for m in &f.msgs_data {
            if start + m.len() <= bc.message_vector.len()
                && &bc.message_vector[start..start + m.len()] == m.as_slice()
            {
                found += 1;
            }
        }
    }
    assert!(found >= 1, "expected at least one msg in broadcast; got vec={:?}", bc.message_vector);
    let _ = &f.server_pubs; // silence unused warning
}
