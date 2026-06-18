//! Per-stage micro-benchmark for the ADCNet protocol.
//!
//! Each stage is timed in isolation; end-to-end round time is extrapolated by
//! composing the stage means against a target topology (S servers, N clients).
//! Scheduling and messaging are timed separately because their bottlenecks
//! differ: scheduling is field-add over a wide auction vector, messaging is
//! AES-CTR keystream + AVX2 XOR over a long byte vector.
//!
//! Stages (each measured at the actual batch size an actor sees in production):
//!   A) client_blind         — one client: prepare blinded ClientRoundMessage + sign
//!   B) batch_aggregate      — one aggregator/server: aggregate N client messages
//!                              into one running aggregate
//!   C) batch_unblind        — one server: derive per-user pads for N clients,
//!                              producing a partial-decryption share
//!   D) leader_combine       — leader: field-sub S server partials into the broadcast
//!
//! End-to-end extrapolation (no network):
//!   Disabled aggregation: A + B + C + D   (servers run B+C in parallel boxes)
//!   Enabled aggregation:  A + B + C + D   (aggregator does B; servers do C in parallel)
//!
//! Pipelined throughput (steady state) = payload / max(stage_time).
//! With the `parallel` feature enabled, B and C internally use rayon to
//! parallelize across the N independent per-client work items.
//!
//! A second extrapolation adds the simulated network (see `netsim`): real
//! bincode wire sizes, jittered latency, client vs cloud link classes, every
//! flow gated at both ends. Net time is reported separately from CPU, then
//! composed into one-shot e2e and a pipelined bottleneck that includes the
//! wire phases.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use adcnet::auction::auction::{AuctionData, AUCTION_BID_XI};
use adcnet::auction::iblt::IbltVector;
use adcnet::crypto::fields::add_assign_mod;
use adcnet::crypto::types::{generate_keypair, ExchangePrivateKey};
use adcnet::crypto::SharedKey;
use adcnet::encoders::auction_iblt;
use adcnet::protocol::messager::{ClientMessager, ServerMessager};
use adcnet::protocol::messages::{
    AggregatedClientMessages, RoundBroadcast, ServerPartialDecryptionMessage, Signed,
};
use adcnet::protocol::{AdcNetConfig, AggregationMode};
use adcnet::ServerId;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod netsim;

// Topology assumed for the e2e extrapolation.
const S: usize = 4;
const N: usize = 100;

#[derive(Clone, Copy)]
struct Scenario {
    label: &'static str,
    auction_slots: u32,
    message_bytes: usize,
    /// Data volume per round used for throughput calculations (auction bytes for
    /// scheduling, message bytes for messaging).
    payload_bytes: usize,
}

const SCHEDULING: Scenario = Scenario {
    label: "scheduling",
    auction_slots: 1000,
    message_bytes: 64,
    // ~5478 field elements × ~58 bytes (encoded as big-endian) ≈ 320 KiB on the wire,
    // but the meaningful payload for "what got scheduled" is the chunks themselves.
    // Use auction vector wire size for throughput so it reflects the per-round work.
    payload_bytes: 5478 * 58,
};

const MESSAGING: Scenario = Scenario {
    label: "messaging",
    auction_slots: 10,
    message_bytes: 1 << 20,
    payload_bytes: 1 << 20,
};

fn time<F: FnMut()>(iters: usize, mut f: F) -> Duration {
    // 1 warmup iteration to prime caches/branch predictors, not counted.
    f();
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    t0.elapsed() / iters as u32
}

fn fmt(d: Duration) -> String {
    if d.as_secs_f64() >= 1.0 {
        format!("{:>8.2} s", d.as_secs_f64())
    } else if d.as_millis() >= 1 {
        format!("{:>8.2} ms", d.as_secs_f64() * 1e3)
    } else {
        format!("{:>8.2} µs", d.as_secs_f64() * 1e6)
    }
}

struct BenchSetup {
    config: AdcNetConfig,
    server_secrets: Vec<HashMap<String, SharedKey>>, // per server, keyed by client pubkey hex
    client_priv: Vec<adcnet::crypto::PrivateKey>,
    client_secrets: Vec<HashMap<ServerId, SharedKey>>, // per client, keyed by server id
    server_ids: Vec<ServerId>,
    prev_bc: RoundBroadcast,
    prev_msg: Vec<u8>,
}

fn setup(sc: Scenario) -> BenchSetup {
    let config = AdcNetConfig {
        auction_slots: sc.auction_slots,
        message_length: sc.message_bytes,
        aggregation: AggregationMode::Disabled,
        ..Default::default()
    };

    let mut server_xks: Vec<ExchangePrivateKey> = Vec::with_capacity(S);
    let mut server_ids = Vec::with_capacity(S);
    for s in 0..S {
        server_xks.push(ExchangePrivateKey::generate());
        server_ids.push(ServerId((s + 1) as u32));
    }
    let mut client_priv = Vec::with_capacity(N);
    let mut client_xks: Vec<ExchangePrivateKey> = Vec::with_capacity(N);
    let mut client_secrets: Vec<HashMap<ServerId, SharedKey>> = vec![HashMap::new(); N];
    let mut server_secrets: Vec<HashMap<String, SharedKey>> = vec![HashMap::new(); S];
    for csec in &mut client_secrets {
        let (pk, sk) = generate_keypair();
        let xk = ExchangePrivateKey::generate();
        for s in 0..S {
            let shared = xk.ecdh(&server_xks[s].public());
            csec.insert(server_ids[s], shared.clone());
            server_secrets[s].insert(pk.to_hex(), shared);
        }
        client_priv.push(sk);
        client_xks.push(xk);
    }

    // Previous-round broadcast: one bid placed so a single client wins a slot.
    let prev_msg: Vec<u8> = (0..sc.message_bytes).map(|i| (i & 0xff) as u8).collect();
    let mut prev_iblt = IbltVector::new_with_xi(sc.auction_slots, AUCTION_BID_XI);
    let mut prev_rng = ChaCha20Rng::from_seed([11; 32]);
    auction_iblt::insert_bid(
        &mut prev_iblt,
        &AuctionData::from_message(&prev_msg, 1),
        &mut prev_rng,
    )
    .unwrap();
    let prev_bc = RoundBroadcast {
        round_number: 1,
        auction_vector: prev_iblt,
        message_vector: Vec::new(),
    };

    BenchSetup {
        config,
        server_secrets,
        client_priv,
        client_secrets,
        server_ids,
        prev_bc,
        prev_msg,
    }
}

// ---- stage A: client blind+sign --------------------------------------------
fn stage_client_blind(b: &BenchSetup) -> Duration {
    let cm = ClientMessager { config: &b.config, shared_secrets: &b.client_secrets[0] };
    let priv0 = &b.client_priv[0];
    time(10, || {
        let (msg, _) = cm.prepare_message(2, &b.prev_bc, &b.prev_msg, None).unwrap();
        let _signed = Signed::new(priv0, msg).unwrap();
    })
}

/// Build N signed client messages for the round under test, one per client.
fn signed_batch(b: &BenchSetup) -> Vec<Signed<adcnet::protocol::messages::ClientRoundMessage>> {
    (0..N)
        .map(|c| {
            let prev = if c == 0 { &b.prev_msg } else { &b.prev_msg[..1.min(b.prev_msg.len())] };
            let cm = ClientMessager { config: &b.config, shared_secrets: &b.client_secrets[c] };
            let (raw, _) = cm.prepare_message(2, &b.prev_bc, prev, None).unwrap();
            Signed::new(&b.client_priv[c], raw).unwrap()
        })
        .collect()
}

// ---- stage B: aggregate N client messages into one aggregate ---------------
//
// Per-message work: verify signature → field-add auction → AVX2 XOR message.
// This is what an aggregator does once per round (or what each server does in
// disabled mode). With `parallel` enabled, the per-message verify dominates
// and parallelizes via rayon; the field/XOR merge stays sequential to preserve
// commutative-add into a single owned aggregate.
fn stage_batch_aggregate(_b: &BenchSetup, batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>]) -> Duration {
    let auction_len = batch[0].object.auction_vector.len();
    let msg_len = batch[0].object.message_vector.len();
    let server_ids = batch[0].object.all_server_ids.clone();

    let zero = || AggregatedClientMessages {
        round_number: 2,
        all_server_ids: server_ids.clone(),
        auction_vector: vec![0u64; auction_len],
        message_vector: vec![0u8; msg_len],
        user_pks: Vec::new(),
    };
    time(5, || {
        // Fused verify + fold + reduce. Field-add and XOR are commutative-
        // associative; rayon preserves iterator order so user_pks is identical
        // to the sequential concatenation.
        #[cfg(feature = "parallel")]
        let _agg = {
            use rayon::prelude::*;
            batch
                .par_iter()
                .fold(zero, |mut acc, m| {
                    let (raw, signer) = m.recover().unwrap();
                    for (a, &b) in acc.auction_vector.iter_mut().zip(raw.auction_vector.iter()) {
                        add_assign_mod(a, b);
                    }
                    adcnet::crypto::xor_inplace(&mut acc.message_vector, &raw.message_vector);
                    acc.user_pks.push(signer.clone());
                    acc
                })
                .reduce(zero, |mut a, b| {
                    a.union_inplace(&b).unwrap();
                    a
                })
        };
        #[cfg(not(feature = "parallel"))]
        let _agg = {
            let mut acc = zero();
            for m in batch {
                let (raw, signer) = m.recover().unwrap();
                for (a, &b) in acc.auction_vector.iter_mut().zip(raw.auction_vector.iter()) {
                    add_assign_mod(a, b);
                }
                adcnet::crypto::xor_inplace(&mut acc.message_vector, &raw.message_vector);
                acc.user_pks.push(signer.clone());
            }
            acc
        };
    })
}

// ---- stage C: server unblinds an aggregate with N users --------------------
//
// This is the per-server cost in production; with `parallel` enabled, pad
// derivation across the N users runs on rayon threads.
fn stage_batch_unblind(b: &BenchSetup, batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>]) -> Duration {
    // Build a realistic aggregate of N users with non-zero pads.
    let auction_len = batch[0].object.auction_vector.len();
    let msg_len = batch[0].object.message_vector.len();
    let mut agg = AggregatedClientMessages {
        round_number: 2,
        all_server_ids: batch[0].object.all_server_ids.clone(),
        auction_vector: vec![0u64; auction_len],
        message_vector: vec![0u8; msg_len],
        user_pks: Vec::new(),
    };
    for m in batch {
        let (raw, signer) = m.recover().unwrap();
        for (a, &b) in agg.auction_vector.iter_mut().zip(raw.auction_vector.iter()) {
            add_assign_mod(a, b);
        }
        adcnet::crypto::xor_inplace(&mut agg.message_vector, &raw.message_vector);
        agg.user_pks.push(signer.clone());
    }
    let sm = ServerMessager {
        config: &b.config,
        server_id: b.server_ids[0],
        shared_secrets: &b.server_secrets[0],
    };
    time(5, || {
        let _ = sm.unblind_aggregate(2, &agg).unwrap();
    })
}

// ---- stage D: leader combines S partials -----------------------------------
fn stage_leader_combine(b: &BenchSetup, batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>]) -> Duration {
    let auction_len = batch[0].object.auction_vector.len();
    let msg_len = batch[0].object.message_vector.len();
    let mut agg = AggregatedClientMessages {
        round_number: 2,
        all_server_ids: batch[0].object.all_server_ids.clone(),
        auction_vector: vec![0u64; auction_len],
        message_vector: vec![0u8; msg_len],
        user_pks: Vec::new(),
    };
    for m in batch {
        let (raw, signer) = m.recover().unwrap();
        for (a, &b) in agg.auction_vector.iter_mut().zip(raw.auction_vector.iter()) {
            add_assign_mod(a, b);
        }
        adcnet::crypto::xor_inplace(&mut agg.message_vector, &raw.message_vector);
        agg.user_pks.push(signer.clone());
    }

    let mut partials: Vec<ServerPartialDecryptionMessage> = Vec::with_capacity(S);
    for s in 0..S {
        let sm = ServerMessager {
            config: &b.config,
            server_id: b.server_ids[s],
            shared_secrets: &b.server_secrets[s],
        };
        partials.push(sm.unblind_aggregate(2, &agg).unwrap());
    }
    let leader = ServerMessager {
        config: &b.config,
        server_id: b.server_ids[0],
        shared_secrets: &b.server_secrets[0],
    };
    time(20, || {
        let mut p_clone = partials.clone();
        let _ = leader.unblind_partial_messages(&mut p_clone).unwrap();
    })
}

struct StageTimes {
    a_client_blind: Duration,
    b_batch_aggregate: Duration,
    c_batch_unblind: Duration,
    d_leader_combine: Duration,
}

/// Measured bincode wire sizes (bytes) of the round's messages.
struct Wires {
    /// One signed ClientRoundMessage.
    msg_b: f64,
    /// One AggregatedClientMessages (aggregator → servers, enabled mode).
    agg_b: f64,
    /// One ServerPartialDecryptionMessage (server → leader).
    part_b: f64,
    /// The RoundBroadcast the leader pushes back to all clients.
    bc_b: f64,
}

fn measure_wires(
    b: &BenchSetup,
    batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>],
) -> Wires {
    let auction_len = batch[0].object.auction_vector.len();
    let msg_len = batch[0].object.message_vector.len();
    let mut agg = AggregatedClientMessages {
        round_number: 2,
        all_server_ids: batch[0].object.all_server_ids.clone(),
        auction_vector: vec![0u64; auction_len],
        message_vector: vec![0u8; msg_len],
        user_pks: Vec::new(),
    };
    for m in batch {
        let (raw, signer) = m.recover().unwrap();
        for (a, &v) in agg.auction_vector.iter_mut().zip(raw.auction_vector.iter()) {
            add_assign_mod(a, v);
        }
        adcnet::crypto::xor_inplace(&mut agg.message_vector, &raw.message_vector);
        agg.user_pks.push(signer.clone());
    }
    let sm = ServerMessager {
        config: &b.config,
        server_id: b.server_ids[0],
        shared_secrets: &b.server_secrets[0],
    };
    let partial = sm.unblind_aggregate(2, &agg).unwrap();
    let bc = RoundBroadcast {
        round_number: 2,
        auction_vector: b.prev_bc.auction_vector.clone(),
        message_vector: vec![0u8; b.config.message_length],
    };
    Wires {
        msg_b: netsim::wire_size(&batch[0]),
        agg_b: netsim::wire_size(&agg),
        part_b: netsim::wire_size(&partial),
        bc_b: netsim::wire_size(&bc),
    }
}

fn run_scenario(sc: Scenario) -> (StageTimes, Wires) {
    println!("\n── {} (auction_slots={}, message_bytes={}) ──",
             sc.label, sc.auction_slots, sc.message_bytes);
    let b = setup(sc);
    let batch = signed_batch(&b);
    let a = stage_client_blind(&b);
    let b_agg = stage_batch_aggregate(&b, &batch);
    let c = stage_batch_unblind(&b, &batch);
    let d = stage_leader_combine(&b, &batch);
    println!("  A   one client blind+sign           {}", fmt(a));
    println!("  B   aggregate N={:>3} client msgs    {}", N, fmt(b_agg));
    println!("  C   unblind aggregate (N={:>3})      {}", N, fmt(c));
    println!("  D   leader combine S={} partials     {}", S, fmt(d));
    let w = measure_wires(&b, &batch);
    (StageTimes { a_client_blind: a, b_batch_aggregate: b_agg, c_batch_unblind: c, d_leader_combine: d }, w)
}

fn extrapolate(label: &str, sc: Scenario, st: &StageTimes) {
    let a = st.a_client_blind;
    let b = st.b_batch_aggregate;
    let c = st.c_batch_unblind;
    let d = st.d_leader_combine;

    // Disabled: each server independently runs B (aggregate N msgs) + C (unblind N users).
    // Servers run in parallel across boxes — per-server wall clock = B + C.
    let disabled_per_server = b + c;
    let disabled_latency = a + disabled_per_server + d;
    // Pipelined: each box keeps doing its job; bottleneck = max over actor wall clocks.
    let disabled_pipe = [("client", a), ("server", disabled_per_server), ("leader", d)];
    let disabled_max = disabled_pipe.iter().map(|(_, x)| *x).max().unwrap();
    let disabled_max_name = disabled_pipe.iter().max_by_key(|(_, x)| *x).unwrap().0;

    // Enabled: client → aggregator (B) → servers (C, parallel across S boxes) → leader (D).
    let enabled_latency = a + b + c + d;
    let enabled_pipe = [("client", a), ("aggregator", b), ("server", c), ("leader", d)];
    let enabled_max = enabled_pipe.iter().map(|(_, x)| *x).max().unwrap();
    let enabled_max_name = enabled_pipe.iter().max_by_key(|(_, x)| *x).unwrap().0;

    println!("\n── {} e2e (S={}, N={}) ──", label, S, N);
    println!("  per-actor wall clock:");
    println!("    client            {}", fmt(a));
    println!("    server aggregate  {}", fmt(b));
    println!("    server unblind    {}", fmt(c));
    println!("    leader combine    {}", fmt(d));
    println!();
    let payload_mib = sc.payload_bytes as f64 / 1048576.0;
    println!("  DISABLED aggregation");
    println!("    one-shot latency       {}   (A + B + C + D, server does B+C)", fmt(disabled_latency));
    println!("    pipelined bottleneck   {}   ({})", fmt(disabled_max), disabled_max_name);
    println!("    pipelined throughput   {:>8.2} MiB/s  ({:>6.1} Mb/s)",
             payload_mib / disabled_max.as_secs_f64(),
             payload_mib * 8.0 / disabled_max.as_secs_f64());
    println!();
    println!("  ENABLED aggregation (1 aggregator, S servers)");
    println!("    one-shot latency       {}   (A + B + C + D, B on aggregator)", fmt(enabled_latency));
    println!("    pipelined bottleneck   {}   ({})", fmt(enabled_max), enabled_max_name);
    println!("    pipelined throughput   {:>8.2} MiB/s  ({:>6.1} Mb/s)",
             payload_mib / enabled_max.as_secs_f64(),
             payload_mib * 8.0 / enabled_max.as_secs_f64());
}

/// e2e extrapolation including the simulated network. Wire phases per round
/// (sequential; each gated by both ends of its flows):
///   P1   client upload — disabled mode: each client uplink carries S copies
///        and every server ingests N messages; enabled mode: one copy to the
///        aggregator, which ingests N.
///   P1b  (enabled only) aggregator fans the aggregate out to S servers.
///   P2   servers → leader: S partial decryptions onto the leader's downlink.
///   P3   leader → clients: the RoundBroadcast, N copies up, one per client
///        downlink.
fn network_extrapolate(label: &str, st: &StageTimes, w: &Wires) {
    let a = st.a_client_blind;
    let b = st.b_batch_aggregate;
    let c = st.c_batch_unblind;
    let d = st.d_leader_combine;
    // Round payload on the wire is the broadcast everyone ends up with.
    let payload_mib = w.bc_b / 1048576.0;
    let mut rng = ChaCha20Rng::from_seed([0x5E; 32]);

    println!("\n── {} network sim (S={}, N={}) ──", label, S, N);
    println!(
        "  wire: client msg {}, aggregate {}, partial {}, broadcast {}",
        netsim::fmt_bytes(w.msg_b),
        netsim::fmt_bytes(w.agg_b),
        netsim::fmt_bytes(w.part_b),
        netsim::fmt_bytes(w.bc_b),
    );
    println!("  net = P1 client upload (+P1b agg fan-out) + P2 partials to leader + P3 broadcast");

    for p in netsim::NETWORKS {
        println!("  {}:", p.header());

        // Mode-independent phases.
        let p2 = p.maxlat(&mut rng, S)
            + p.xfer_server(w.part_b).max(p.xfer_server(S as f64 * w.part_b));
        let p3 = p.maxlat(&mut rng, N)
            + p.xfer_server(N as f64 * w.bc_b).max(p.xfer_client(w.bc_b));

        let report =
            |name: &str, net: Duration, latency: Duration, pipe: &[(&str, Duration)]| {
                let e2e = latency + net;
                let (bn_name, bn) = *pipe.iter().max_by_key(|(_, x)| *x).unwrap();
                println!(
                    "    {:<9} net {}  e2e {}  pipe {} ({}) → {:>7.2} MiB/s",
                    name,
                    fmt(net),
                    fmt(e2e),
                    fmt(bn),
                    bn_name,
                    payload_mib / bn.as_secs_f64(),
                );
            };

        // DISABLED: clients send to all S servers; each server runs B+C.
        let p1 = p.maxlat(&mut rng, N)
            + p
                .xfer_client(S as f64 * w.msg_b)
                .max(p.xfer_server(N as f64 * w.msg_b));
        report(
            "DISABLED",
            p1 + p2 + p3,
            a + (b + c) + d,
            &[
                ("client", a),
                ("server", b + c),
                ("leader", d),
                ("net P1", p1),
                ("net P2", p2),
                ("net P3", p3),
            ],
        );

        // ENABLED: clients send once to the aggregator, which fans out.
        let p1 = p.maxlat(&mut rng, N)
            + p.xfer_client(w.msg_b).max(p.xfer_server(N as f64 * w.msg_b));
        let p1b = p.maxlat(&mut rng, S)
            + p.xfer_server(S as f64 * w.agg_b).max(p.xfer_server(w.agg_b));
        report(
            "ENABLED",
            p1 + p1b + p2 + p3,
            a + b + c + d,
            &[
                ("client", a),
                ("aggregator", b),
                ("server", c),
                ("leader", d),
                ("net P1", p1),
                ("net P1b", p1b),
                ("net P2", p2),
                ("net P3", p3),
            ],
        );
    }
}

fn main() {
    println!("ADCNet per-stage benchmark");
    println!("topology assumed for extrapolation: S={S} servers, N={N} clients");
    #[cfg(feature = "parallel")]
    println!("parallel feature: ON  (rayon threads = {})", rayon::current_num_threads());
    #[cfg(not(feature = "parallel"))]
    println!("parallel feature: OFF (single-threaded)");

    let (st_sched, w_sched) = run_scenario(SCHEDULING);
    let (st_msg, w_msg) = run_scenario(MESSAGING);

    extrapolate("SCHEDULING", SCHEDULING, &st_sched);
    extrapolate("MESSAGING",  MESSAGING,  &st_msg);
    network_extrapolate("SCHEDULING", &st_sched, &w_sched);
    network_extrapolate("MESSAGING", &st_msg, &w_msg);
}
