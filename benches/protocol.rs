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
const N: usize = 200;
// n-agg uses AGG aggregators, each ingesting N/AGG clients. Balancing per-agg
// load (∝ N/AGG) against combiner fan-in (∝ AGG) minimizes at AGG = √N.
const AGG: usize = round_sqrt(N);
const N_PER_AGG: usize = N.div_ceil(AGG);

/// Nearest integer to √n (usize::isqrt is 1.84+, const float math is unstable).
const fn round_sqrt(n: usize) -> usize {
    let mut r = 0;
    while (r + 1) * (r + 1) <= n {
        r += 1;
    }
    if n - r * r > (r + 1) * (r + 1) - n {
        r + 1
    } else {
        r
    }
}

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
    let cm = ClientMessager {
        config: &b.config,
        shared_secrets: &b.client_secrets[0],
    };
    let priv0 = &b.client_priv[0];
    let mut rng = rand::rngs::OsRng;
    time(10, || {
        let (msg, _) = cm
            .prepare_message(2, &b.prev_bc, &b.prev_msg, None, &mut rng)
            .unwrap();
        let _signed = Signed::new(priv0, msg).unwrap();
    })
}

/// Build N signed client messages for the round under test, one per client.
fn signed_batch(b: &BenchSetup) -> Vec<Signed<adcnet::protocol::messages::ClientRoundMessage>> {
    (0..N)
        .map(|c| {
            let prev = if c == 0 {
                &b.prev_msg
            } else {
                &b.prev_msg[..1.min(b.prev_msg.len())]
            };
            let cm = ClientMessager {
                config: &b.config,
                shared_secrets: &b.client_secrets[c],
            };
            let (raw, _) = cm
                .prepare_message(2, &b.prev_bc, prev, None, &mut rand::rngs::OsRng)
                .unwrap();
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
fn stage_batch_aggregate(
    _b: &BenchSetup,
    batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>],
) -> Duration {
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
fn stage_batch_unblind(
    b: &BenchSetup,
    batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>],
) -> Duration {
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
fn stage_leader_combine(
    b: &BenchSetup,
    batch: &[Signed<adcnet::protocol::messages::ClientRoundMessage>],
) -> Duration {
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
    /// B over a per-aggregator bucket of N/AGG clients (n-agg).
    b_batch_aggregate_bucket: Duration,
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
    println!(
        "\n── {} (auction_slots={}, message_bytes={}) ──",
        sc.label, sc.auction_slots, sc.message_bytes
    );
    let b = setup(sc);
    let batch = signed_batch(&b);
    let a = stage_client_blind(&b);
    let b_agg = stage_batch_aggregate(&b, &batch);
    let b_bucket = stage_batch_aggregate(&b, &batch[..N_PER_AGG.min(batch.len())]);
    let c = stage_batch_unblind(&b, &batch);
    let d = stage_leader_combine(&b, &batch);
    println!("  A    one client blind+sign           {}", fmt(a));
    println!("  B₁   aggregate N={:>3} client msgs    {}", N, fmt(b_agg));
    println!(
        "  B_n  aggregate N/{}={:>3} clients/agg   {}",
        AGG, N_PER_AGG, fmt(b_bucket)
    );
    println!("  C    unblind aggregate (N={:>3})      {}", N, fmt(c));
    println!("  D    leader combine S={} partials     {}", S, fmt(d));
    let w = measure_wires(&b, &batch);
    (
        StageTimes {
            a_client_blind: a,
            b_batch_aggregate: b_agg,
            b_batch_aggregate_bucket: b_bucket,
            c_batch_unblind: c,
            d_leader_combine: d,
        },
        w,
    )
}

fn extrapolate(label: &str, sc: Scenario, st: &StageTimes) {
    let a = st.a_client_blind;
    let b = st.b_batch_aggregate;
    let b_bucket = st.b_batch_aggregate_bucket;
    let c = st.c_batch_unblind;
    let d = st.d_leader_combine;

    // 0-agg: each server independently runs B (aggregate N msgs) + C (unblind N users).
    // Servers run in parallel across boxes — per-server wall clock = B + C.
    let disabled_per_server = b + c;
    let disabled_latency = a + disabled_per_server + d;
    // Pipelined: each box keeps doing its job; bottleneck = max over actor wall clocks.
    let disabled_pipe = [
        ("client", a),
        ("server", disabled_per_server),
        ("leader", d),
    ];
    let disabled_max = disabled_pipe.iter().map(|(_, x)| *x).max().unwrap();
    let disabled_max_name = disabled_pipe.iter().max_by_key(|(_, x)| *x).unwrap().0;

    // n-agg: client → AGG aggregators (each B over N/AGG) → servers (C, parallel
    // across S boxes) → leader (D).
    let enabled_latency = a + b_bucket + c + d;
    let enabled_pipe = [
        ("client", a),
        ("aggregator", b_bucket),
        ("server", c),
        ("leader", d),
    ];
    let enabled_max = enabled_pipe.iter().map(|(_, x)| *x).max().unwrap();
    let enabled_max_name = enabled_pipe.iter().max_by_key(|(_, x)| *x).unwrap().0;

    println!("\n── {} e2e (S={}, N={}) ──", label, S, N);
    println!("  per-actor wall clock:");
    println!("    client            {}", fmt(a));
    println!("    server aggregate  {}", fmt(b));
    println!("    server unblind    {}", fmt(c));
    println!("    leader combine    {}", fmt(d));
    println!();
    let payload_b = sc.payload_bytes as f64;
    println!("  0-agg (no aggregator; each server runs B+C)");
    println!(
        "    one-shot latency       {}   (A + B + C + D, server does B+C)",
        fmt(disabled_latency)
    );
    println!(
        "    pipelined bottleneck   {}   ({})",
        fmt(disabled_max),
        disabled_max_name
    );
    println!(
        "    pipelined throughput   {:>7.2} MB/s",
        payload_b / disabled_max.as_secs_f64() / 1e6
    );
    println!();
    println!("  n-agg (1 aggregator, S servers)");
    println!(
        "    one-shot latency       {}   (A + B + C + D, B on aggregator)",
        fmt(enabled_latency)
    );
    println!(
        "    pipelined bottleneck   {}   ({})",
        fmt(enabled_max),
        enabled_max_name
    );
    println!(
        "    pipelined throughput   {:>7.2} MB/s",
        payload_b / enabled_max.as_secs_f64() / 1e6
    );
}

/// Combined per-round link load: client→server flows (msg/agg/partial) carry
/// both the auction vector and the payload, so they sum. The broadcast back to
/// all clients carries only the scheduling (auction) result that drives the
/// next round — the recovered message is the delivered output, not re-pushed to
/// every client — so bc_b is the scheduling broadcast alone.
fn combined_wires(sched: &Wires, msg: &Wires) -> Wires {
    Wires {
        msg_b: sched.msg_b + msg.msg_b,
        agg_b: sched.agg_b + msg.agg_b,
        part_b: sched.part_b + msg.part_b,
        bc_b: sched.bc_b,
    }
}

/// Per-round CPU: one round does the auction field work and the messaging
/// crypto, so each stage's cost is the sum across both scenarios.
fn combined_stages(sched: &StageTimes, msg: &StageTimes) -> StageTimes {
    StageTimes {
        a_client_blind: sched.a_client_blind + msg.a_client_blind,
        b_batch_aggregate: sched.b_batch_aggregate + msg.b_batch_aggregate,
        b_batch_aggregate_bucket: sched.b_batch_aggregate_bucket
            + msg.b_batch_aggregate_bucket,
        c_batch_unblind: sched.c_batch_unblind + msg.c_batch_unblind,
        d_leader_combine: sched.d_leader_combine + msg.d_leader_combine,
    }
}

/// e2e extrapolation including the simulated network. Wire phases per round
/// (sequential; each gated by both ends of its flows):
///   P1   client upload — 0-agg: each client uplink carries S copies and every
///        server ingests N messages; n-agg: one copy to an aggregator, each of
///        the AGG aggregators ingesting N/AGG.
///   P1b  (n-agg only) a combiner gathers the AGG partial aggregates and fans
///        the full aggregate out to S servers.
///   P2   servers → leader: S partial decryptions onto the leader's downlink.
///   P3   leader → clients: the RoundBroadcast, N copies up, one per client
///        downlink.
fn network_extrapolate(st: &StageTimes, w: &Wires) {
    let a = st.a_client_blind;
    let b = st.b_batch_aggregate;
    let b_bucket = st.b_batch_aggregate_bucket;
    let c = st.c_batch_unblind;
    let d = st.d_leader_combine;
    let mut rng = ChaCha20Rng::from_seed([0x5E; 32]);

    println!("\n── network sim (S={}, N={}) ──", S, N);
    println!(
        "  wire (auction+payload, shared link): client msg {}, aggregate {}, partial {}, broadcast {}",
        netsim::fmt_bytes(w.msg_b),
        netsim::fmt_bytes(w.agg_b),
        netsim::fmt_bytes(w.part_b),
        netsim::fmt_bytes(w.bc_b),
    );
    println!("  net = P1 client upload (+P1b agg fan-out) + P2 partials to leader + P3 broadcast; e2e = cpu + net");

    // Wire ledger + summary (per round); efficiency = useful / total bytes
    // crossing every link. Useful = the delivered anonymous message; the
    // broadcast (w.bc_b) carries only the scheduling result.
    let useful_b = MESSAGING.message_bytes as f64;
    let partials = S as f64 * w.part_b;
    let broadcast = N as f64 * w.bc_b;
    let client_up_disabled = (N * S) as f64 * w.msg_b;
    let client_up_enabled = N as f64 * w.msg_b;
    let agg_gather = AGG as f64 * w.agg_b;
    let fan_out = S as f64 * w.agg_b;
    let wire_disabled = client_up_disabled + partials + broadcast;
    let wire_enabled = client_up_enabled + agg_gather + fan_out + partials + broadcast;
    println!("  useful {} / round", netsim::fmt_bytes(useful_b));
    println!(
        "    0-agg            wire {} / round  efficiency {:.3e}   [client→S {} (N·S·msg) + partials {} (S·part) + broadcast {} (N·bc)]",
        netsim::fmt_bytes(wire_disabled),
        useful_b / wire_disabled,
        netsim::fmt_bytes(client_up_disabled),
        netsim::fmt_bytes(partials),
        netsim::fmt_bytes(broadcast),
    );
    println!(
        "    n-agg (AGG={:>2})    wire {} / round  efficiency {:.3e}   [client→agg {} (N·msg) + gather {} (AGG·agg) + fan-out {} (S·agg) + partials {} (S·part) + broadcast {} (N·bc)]",
        AGG,
        netsim::fmt_bytes(wire_enabled),
        useful_b / wire_enabled,
        netsim::fmt_bytes(client_up_enabled),
        netsim::fmt_bytes(agg_gather),
        netsim::fmt_bytes(fan_out),
        netsim::fmt_bytes(partials),
        netsim::fmt_bytes(broadcast),
    );
    println!("  per-role wire (out = emitted / in = ingested):");
    println!(
        "    1 client:     out {} (0-agg ×{}S to all servers)   in {} (broadcast)",
        netsim::fmt_bytes(w.msg_b),
        S,
        netsim::fmt_bytes(w.bc_b),
    );
    println!(
        "    1 server:     in {} 0-agg (N·msg) / {} n-agg (1 aggregate)   out {} (partial → leader)",
        netsim::fmt_bytes(N as f64 * w.msg_b),
        netsim::fmt_bytes(w.agg_b),
        netsim::fmt_bytes(w.part_b),
    );
    println!(
        "    1 aggregator: in {} (N/{}={} posts, n-agg)   out {} (1 partial → combiner)",
        netsim::fmt_bytes(N_PER_AGG as f64 * w.msg_b),
        AGG,
        N_PER_AGG,
        netsim::fmt_bytes(w.agg_b),
    );
    println!(
        "    combiner:     in {} (AGG·agg gather)   out {} (S·agg fan-out to servers)",
        netsim::fmt_bytes(agg_gather),
        netsim::fmt_bytes(fan_out),
    );
    println!(
        "    leader:       in {} (S·part)   out {} (N·bc broadcast)",
        netsim::fmt_bytes(partials),
        netsim::fmt_bytes(broadcast),
    );

    for p in netsim::NETWORKS {
        println!("  {}:", p.header());

        // Mode-independent phases.
        let p2 = p.maxlat(&mut rng, S)
            + p.xfer_server(w.part_b)
                .max(p.xfer_server(S as f64 * w.part_b));
        let p3 =
            p.maxlat(&mut rng, N) + p.xfer_server(N as f64 * w.bc_b).max(p.xfer_client(w.bc_b));

        // Throughput is pipelined: consecutive rounds overlap (round r's
        // broadcast P3 runs while round r+1 uploads P1, auction alongside
        // messaging), so steady-state is gated by the slowest stage, not the
        // sequential e2e sum. e2e is reported as the one-round latency.
        let report = |name: &str, phases: String, net: Duration, cpu: Duration, pipe: &[(&str, Duration)]| {
            let e2e = cpu + net;
            let (bn_name, bn) = *pipe.iter().max_by_key(|(_, x)| *x).unwrap();
            println!(
                "    {:<8} net {} [{}]  e2e {}  →  {:>7.2} MB/s pipelined (bottleneck {})",
                name,
                fmt(net),
                phases,
                fmt(e2e),
                useful_b / bn.as_secs_f64() / 1e6,
                bn_name,
            );
        };

        // 0-agg: clients send to all S servers; each server runs B+C.
        let p1 = p.maxlat(&mut rng, N)
            + p.xfer_client(S as f64 * w.msg_b)
                .max(p.xfer_server(N as f64 * w.msg_b));
        report(
            "0-agg",
            format!("P1 {} + P2 {} + P3 {}", fmt(p1), fmt(p2), fmt(p3)),
            p1 + p2 + p3,
            a + (b + c) + d,
            &[
                ("client", a),
                ("server", b + c),
                ("leader", d),
                ("P1", p1),
                ("P2", p2),
                ("P3", p3),
            ],
        );

        // n-agg: AGG aggregators each ingest N/AGG; a combiner gathers the AGG
        // partials and fans the full aggregate to S servers.
        let p1 = p.maxlat(&mut rng, N)
            + p.xfer_client(w.msg_b)
                .max(p.xfer_server(N_PER_AGG as f64 * w.msg_b));
        let p1b = p.maxlat(&mut rng, AGG.max(S))
            + p.xfer_server(AGG as f64 * w.agg_b)
                .max(p.xfer_server(S as f64 * w.agg_b));
        report(
            "n-agg",
            format!(
                "P1 {} + P1b {} + P2 {} + P3 {}",
                fmt(p1),
                fmt(p1b),
                fmt(p2),
                fmt(p3)
            ),
            p1 + p1b + p2 + p3,
            a + b_bucket + c + d,
            &[
                ("client", a),
                ("aggregator", b_bucket),
                ("server", c),
                ("leader", d),
                ("P1", p1),
                ("P1b", p1b),
                ("P2", p2),
                ("P3", p3),
            ],
        );
    }
}

fn main() {
    println!("ADCNet per-stage benchmark");
    println!("topology assumed for extrapolation: S={S} servers, N={N} clients");
    #[cfg(feature = "parallel")]
    println!(
        "parallel feature: ON  (rayon threads = {})",
        rayon::current_num_threads()
    );
    #[cfg(not(feature = "parallel"))]
    println!("parallel feature: OFF (single-threaded)");

    let (st_sched, w_sched) = run_scenario(SCHEDULING);
    let (st_msg, w_msg) = run_scenario(MESSAGING);

    extrapolate("SCHEDULING", SCHEDULING, &st_sched);
    extrapolate("MESSAGING", MESSAGING, &st_msg);
    network_extrapolate(
        &combined_stages(&st_sched, &st_msg),
        &combined_wires(&w_sched, &w_msg),
    );
}
