//! Per-stage micro-benchmark for the 1-round (IBLT-message) protocol.
//!
//! No auction round, no slot scheduling — clients encode their payloads into a
//! multi-V IBLT (key=random, V=length-prefixed payload across ξ field
//! elements), blind under the field-additive primitive, and sign. Servers each
//! emit one share over the aggregate's shape. Anyone with all client
//! contributions + all server shares recovers the payload set by peeling the
//! recovered IBLT.
//!
//! Stages (each measured at the actual batch size an actor sees in production):
//!   A) client_contribute   — one client: IBLT-encode + field_round::client_blind + sign
//!   B) server_share        — one server: field_round::server_share over N client secrets + sign
//!   C) aggregate_clients   — one party: field_round::aggregate_clients across N contributions
//!   D) combine_and_decode  — one party: field_round::combine_partials + iblt_msg::decode_round
//!
//! End-to-end extrapolation (no network):
//!   one-shot latency  = A + max(B over S servers) + C + D
//!                       (B is per-server; servers run in parallel boxes)
//!   pipelined bottleneck = max(A, B, C, D)
//!   pipelined throughput = (N × payload_bytes) / bottleneck
//!
//! A second extrapolation adds the simulated network (see `netsim`): real
//! bincode wire sizes, jittered latency, client vs cloud link classes, every
//! flow gated at both ends. Net time is reported separately from CPU, then
//! composed into one-shot e2e and a pipelined bottleneck that includes the
//! wire phases.
//!
//! Scenarios sweep payload size while keeping N and S fixed; the IBLT shape
//! scales with `estimated_messages` (≈ N) and ξ scales with payload size.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use adcnet::crypto::types::{generate_keypair, ExchangePrivateKey};
use adcnet::crypto::{PrivateKey, PublicKey, ServerId, SharedKey};
use adcnet::protocol::messages::Signed;
use adcnet::protocol::session::one_round::{
    client_contribute, combine_round, server_contribute, ClientContribution, IbltMsgParamsOwned,
    OneRoundConfig, ServerShare,
};

mod netsim;

// Topology assumed for the e2e extrapolation.
const S: usize = 4;
const N: usize = 100;
// The aggregator count trades per-aggregator load (∝ N/AGG) against combiner
// fan-in (∝ AGG); both carry the same per-item wire cost, so N/AGG + AGG is
// minimized at AGG = √N. Derive it rather than hardcoding so the n-agg row
// always reports the model-optimal operating point.
const AGG: usize = round_sqrt(N);
const N_PER_AGG: usize = N.div_ceil(AGG);

/// Nearest integer to √n. `usize::isqrt` lands in 1.84 and const float math is
/// unstable, so spell out the integer version (const-fn loops are fine ≥1.46).
const fn round_sqrt(n: usize) -> usize {
    let mut r = 0;
    while (r + 1) * (r + 1) <= n {
        r += 1;
    }
    // r = ⌊√n⌋; round up when r+1 is the closer integer.
    if n - r * r > (r + 1) * (r + 1) - n {
        r + 1
    } else {
        r
    }
}

#[derive(Clone, Copy)]
struct Scenario {
    label: &'static str,
    payload_bytes: usize,
}

const SCENARIOS: &[Scenario] = &[Scenario {
    label: "4KB-payload",
    payload_bytes: 4096,
}];

fn time<F: FnMut()>(iters: usize, mut f: F) -> Duration {
    f(); // 1 warmup, not counted
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
    cfg: OneRoundConfig,
    server_signing: Vec<PrivateKey>,
    server_ids: Vec<ServerId>,
    server_secrets: Vec<HashMap<PublicKey, SharedKey>>, // per server
    client_signing: Vec<PrivateKey>,
    client_secrets: Vec<HashMap<ServerId, SharedKey>>, // per client
    payloads: Vec<Vec<u8>>,
}

fn setup(sc: Scenario) -> BenchSetup {
    let cfg = OneRoundConfig {
        iblt: IbltMsgParamsOwned {
            estimated_messages: N as u32,
            max_payload_bytes: sc.payload_bytes,
        },
    };

    let mut server_signing = Vec::with_capacity(S);
    let mut server_ids = Vec::with_capacity(S);
    let mut server_xks: Vec<ExchangePrivateKey> = Vec::with_capacity(S);
    for s in 0..S {
        let (_pk, sk) = generate_keypair();
        server_signing.push(sk);
        server_ids.push(ServerId((s as u32) + 1));
        server_xks.push(ExchangePrivateKey::generate());
    }

    let mut client_signing = Vec::with_capacity(N);
    let mut client_pubs: Vec<PublicKey> = Vec::with_capacity(N);
    let mut client_xks: Vec<ExchangePrivateKey> = Vec::with_capacity(N);
    let mut client_secrets: Vec<HashMap<ServerId, SharedKey>> = vec![HashMap::new(); N];
    let mut server_secrets: Vec<HashMap<PublicKey, SharedKey>> = vec![HashMap::new(); S];
    for csec in &mut client_secrets {
        let (pk, sk) = generate_keypair();
        let xk = ExchangePrivateKey::generate();
        for s in 0..S {
            let shared = xk.ecdh(&server_xks[s].public());
            csec.insert(server_ids[s], shared.clone());
            server_secrets[s].insert(pk.clone(), shared);
        }
        client_signing.push(sk);
        client_pubs.push(pk);
        client_xks.push(xk);
    }

    let payloads: Vec<Vec<u8>> = (0..N)
        .map(|i| {
            let mut v = vec![0u8; sc.payload_bytes];
            for (j, b) in v.iter_mut().enumerate() {
                *b = ((i * 31 + j) % 251) as u8;
            }
            v
        })
        .collect();

    BenchSetup {
        cfg,
        server_signing,
        server_ids,
        server_secrets,
        client_signing,
        client_secrets,
        payloads,
    }
}

// ---- stage A: one client encode + blind + sign -----------------------------
fn stage_client_contribute(b: &BenchSetup) -> Duration {
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    time(5, || {
        let _ = client_contribute(
            &b.cfg,
            1,
            &b.client_signing[0],
            &b.client_secrets[0],
            Some(&b.payloads[0]),
            &mut rng,
        )
        .unwrap();
    })
}

// ---- stage B: one server share derivation + sign ---------------------------
//
// Per-server work: derive blinding vector across N client shared secrets, sign
// the resulting share. This is what one server does once per round; with
// `parallel`, the per-client pad derivation parallelizes via rayon.
fn stage_server_share(b: &BenchSetup) -> Duration {
    time(5, || {
        let _ = server_contribute(
            &b.cfg,
            1,
            b.server_ids[0],
            &b.server_signing[0],
            &b.server_secrets[0],
        )
        .unwrap();
    })
}

/// Build N signed client contributions for the round under test (one per client).
fn signed_clients(b: &BenchSetup) -> Vec<Signed<ClientContribution>> {
    let mut rng = ChaCha20Rng::from_seed([29u8; 32]);
    (0..N)
        .map(|c| {
            client_contribute(
                &b.cfg,
                1,
                &b.client_signing[c],
                &b.client_secrets[c],
                Some(&b.payloads[c]),
                &mut rng,
            )
            .unwrap()
        })
        .collect()
}

/// Build S signed server shares.
fn signed_servers(b: &BenchSetup) -> Vec<Signed<ServerShare>> {
    (0..S)
        .map(|s| {
            server_contribute(
                &b.cfg,
                1,
                b.server_ids[s],
                &b.server_signing[s],
                &b.server_secrets[s],
            )
            .unwrap()
        })
        .collect()
}

// ---- stage C: aggregate `batch_size` client contributions ------------------
//
// Per-message work: verify signature (hoisted out — measured separately if
// needed), then field-add via the library's `field_round::aggregate_clients`
// (parallel-aware under the `parallel` feature). Done once per round on
// whichever party (aggregator or combiner) handles that bucket of clients.
fn stage_aggregate_clients(
    _b: &BenchSetup,
    clients: &[Signed<ClientContribution>],
    batch_size: usize,
) -> Duration {
    use adcnet::field_round;

    let batch = &clients[..batch_size.min(clients.len())];
    let raw_blinded: Vec<Vec<u64>> = batch
        .iter()
        .map(|m| {
            let (raw, _) = m.recover().unwrap();
            raw.blinded.clone()
        })
        .collect();
    let slices: Vec<&[u64]> = raw_blinded.iter().map(|v| v.as_slice()).collect();
    time(5, || {
        let _ = field_round::aggregate_clients(&slices);
    })
}

// ---- stage D: combine S partials + IBLT decode -----------------------------
//
// Cost: subtract S server shares from the aggregate (field_sub over the wide
// field-element vector) + peel the multi-V IBLT to recover payloads.
fn stage_combine_and_decode(
    b: &BenchSetup,
    clients: &[Signed<ClientContribution>],
    servers: &[Signed<ServerShare>],
) -> Duration {
    let clients_raw: Vec<ClientContribution> = clients
        .iter()
        .map(|s| s.recover().unwrap().0.clone())
        .collect();
    let servers_raw: Vec<ServerShare> = servers
        .iter()
        .map(|s| s.recover().unwrap().0.clone())
        .collect();
    time(5, || {
        let _ = combine_round(&b.cfg, 1, &clients_raw, &servers_raw, S).unwrap();
    })
}

struct StageTimes {
    a_client: Duration,
    b_server_share: Duration,
    /// Aggregate the full N-client batch (single-aggregator mode).
    c_aggregate_all: Duration,
    /// Aggregate a per-aggregator subset (N_PER_AGG clients).
    c_aggregate_bucket: Duration,
    d_combine_decode: Duration,
}

/// Measured bincode wire sizes (bytes) of the round's messages.
struct Wires {
    /// One signed client contribution.
    contrib_b: f64,
    /// One signed server share.
    share_b: f64,
    /// One (partial) client aggregate forwarded aggregator → combiner —
    /// same blinded-vector shape as a raw contribution.
    agg_b: f64,
    /// The decoded payload multiset the combiner broadcasts back out.
    result_b: f64,
}

fn run_scenario(sc: Scenario) -> (StageTimes, Wires) {
    println!(
        "\n── {} (payload_bytes={}, estimated_messages={}, ξ inferred) ──",
        sc.label, sc.payload_bytes, N
    );
    let b = setup(sc);
    let clients = signed_clients(&b);
    let servers = signed_servers(&b);

    // Sanity: a full round must actually decode all N payloads. Catches
    // regressions where the IBLT is mis-sized for the load factor.
    let clients_raw: Vec<ClientContribution> = clients
        .iter()
        .map(|s| s.recover().unwrap().0.clone())
        .collect();
    let servers_raw: Vec<ServerShare> = servers
        .iter()
        .map(|s| s.recover().unwrap().0.clone())
        .collect();
    let decoded = combine_round(&b.cfg, 1, &clients_raw, &servers_raw, S).unwrap();
    assert_eq!(
        decoded.len(),
        N,
        "decoded set must match all client payloads"
    );

    let a = stage_client_contribute(&b);
    let bsh = stage_server_share(&b);
    let c_all = stage_aggregate_clients(&b, &clients, N);
    let c_bucket = stage_aggregate_clients(&b, &clients, N_PER_AGG);
    let d = stage_combine_and_decode(&b, &clients, &servers);

    println!("  A   one client encode+blind+sign      {}", fmt(a));
    println!("  B   one server share+sign (N={:>3})    {}", N, fmt(bsh));
    println!("  C₁  aggregate N={:>3} clients          {}", N, fmt(c_all));
    println!(
        "  C₄  aggregate N/{}={:>3} clients/agg     {}",
        AGG,
        N_PER_AGG,
        fmt(c_bucket)
    );
    println!("  D   combine S={} + decode IBLT         {}", S, fmt(d));
    let wires = Wires {
        contrib_b: netsim::wire_size(&clients[0]),
        share_b: netsim::wire_size(&servers[0]),
        agg_b: netsim::wire_size(&clients_raw[0]),
        result_b: (N * sc.payload_bytes) as f64,
    };
    (
        StageTimes {
            a_client: a,
            b_server_share: bsh,
            c_aggregate_all: c_all,
            c_aggregate_bucket: c_bucket,
            d_combine_decode: d,
        },
        wires,
    )
}

fn extrapolate(sc: Scenario, st: &StageTimes) {
    let a = st.a_client;
    let bsh = st.b_server_share;
    let c_all = st.c_aggregate_all;
    let c_bucket = st.c_aggregate_bucket;
    let d = st.d_combine_decode;
    let useful_b = (sc.payload_bytes * N) as f64;

    println!("\n── {} e2e (S={}, N={}) ──", sc.label, S, N);
    println!("  per-stage wall clock:");
    println!("    A client encode+blind+sign     {}", fmt(a));
    println!(
        "    B server share+sign            {}  (each of S={} servers, parallel boxes)",
        fmt(bsh),
        S
    );
    println!("    C₁ aggregate N={:>3} clients     {}", N, fmt(c_all));
    println!(
        "    C₄ aggregate N/{}={:>3}/agg       {}  (each of {} aggregators, parallel)",
        AGG,
        N_PER_AGG,
        fmt(c_bucket),
        AGG,
    );
    println!("    D combine + IBLT decode        {}", fmt(d));

    let report = |name: &str, latency_desc: &str, latency: Duration, pipe: &[(&str, Duration)]| {
        let bottleneck = pipe.iter().map(|(_, x)| *x).max().unwrap();
        let bottleneck_name = pipe.iter().max_by_key(|(_, x)| *x).unwrap().0;
        println!();
        println!("  {}", name);
        println!(
            "    one-shot latency        {}   ({})",
            fmt(latency),
            latency_desc
        );
        println!(
            "    pipelined bottleneck    {}   ({})",
            fmt(bottleneck),
            bottleneck_name
        );
        println!(
            "    pipelined throughput    {:>7.2} MB/s  — {} payloads/round",
            useful_b / bottleneck.as_secs_f64() / 1e6,
            N
        );
    };

    // ---- AGG aggregators + S server boxes + combiner -----------------------
    // Pipeline:  client(A) → aggregators(C₄, parallel) → servers(B, parallel)
    //                                                  → combiner(D)
    // Combiner additionally folds AGG partial aggregates into one before
    // decoding — that fold is ~AGG/N × C₁ ≪ D and is absorbed into D's stage.
    report(
        &format!(
            "WITH {} aggregators ({} clients/agg, parallel)",
            AGG, N_PER_AGG
        ),
        "A + C₄ + B + D",
        a + c_bucket + bsh + d,
        &[
            ("client", a),
            ("aggregator", c_bucket),
            ("server", bsh),
            ("combiner", d),
        ],
    );

    // ---- NO aggregator (each of S servers does B + C₁ + D itself) ---------
    {
        let per_server = bsh + c_all + d;
        report(
            "NO aggregator (each of S servers runs B + C₁ + D itself, in parallel)",
            "A + (B + C₁ + D) per server",
            a + per_server,
            &[("client", a), ("server", per_server)],
        );
    }
}

/// e2e extrapolation including the simulated network. Three wire phases per
/// round (sequential; each gated by both ends of its flows):
///   P1  client upload — N parallel client uplinks carrying contributions
///       (one copy per destination), vs the receivers' ingest of N each.
///   P2  fan-in to the combiner — partial aggregates + S server shares
///       (cloud → cloud; aggregate forwarding and shares flow in parallel).
///   P3  result broadcast — combiner pushes the decoded multiset to N
///       clients: its uplink serializes N copies, each client downlink one.
fn network_extrapolate(sc: Scenario, st: &StageTimes, w: &Wires) {
    let a = st.a_client;
    let bsh = st.b_server_share;
    let mut rng = ChaCha20Rng::from_seed([0x5E; 32]);

    println!(
        "\n── {} network sim (S={}, N={}, {} aggs) ──",
        sc.label, S, N, AGG
    );
    println!(
        "  wire: contribution {}, server share {}, aggregate {}, decoded set {}",
        netsim::fmt_bytes(w.contrib_b),
        netsim::fmt_bytes(w.share_b),
        netsim::fmt_bytes(w.agg_b),
        netsim::fmt_bytes(w.result_b),
    );
    println!("  net = P1 client upload + P2 fan-in to combiner + P3 result broadcast; e2e = cpu + net");

    // Wire ledger + summary (per round). Useful = the recovered multiset;
    // efficiency = useful / total bytes crossing every link.
    let useful_b = w.result_b;
    let client_up = N as f64 * w.contrib_b;
    let server_shares = S as f64 * w.share_b;
    let agg_fwd = AGG as f64 * w.agg_b;
    let broadcast = N as f64 * w.result_b;
    let wire_total = client_up + server_shares + agg_fwd + broadcast;
    println!(
        "  useful {} / round   wire {} / round   efficiency {:.3e}",
        netsim::fmt_bytes(useful_b),
        netsim::fmt_bytes(wire_total),
        useful_b / wire_total,
    );
    println!(
        "    contribution {} (N·contrib) + shares {} (S·share) + aggregate {} (AGG·agg) + broadcast {} (N·result)",
        netsim::fmt_bytes(client_up),
        netsim::fmt_bytes(server_shares),
        netsim::fmt_bytes(agg_fwd),
        netsim::fmt_bytes(broadcast),
    );
    println!("  per-role wire (out = emitted / in = ingested):");
    println!(
        "    1 client:     out {} (→ aggregator; 0-agg ×{}S)   in {} (broadcast)",
        netsim::fmt_bytes(w.contrib_b),
        S,
        netsim::fmt_bytes(w.result_b),
    );
    println!(
        "    1 server:     out {} (share → combiner)",
        netsim::fmt_bytes(w.share_b),
    );
    println!(
        "    1 aggregator: in {} ({} posts)   out {} (1 aggregate)",
        netsim::fmt_bytes(N_PER_AGG as f64 * w.contrib_b),
        N_PER_AGG,
        netsim::fmt_bytes(w.agg_b),
    );
    println!(
        "    combiner:     in {} (AGG·agg + S·share)   out {} (N·result broadcast)",
        netsim::fmt_bytes(agg_fwd + server_shares),
        netsim::fmt_bytes(broadcast),
    );
    println!(
        "    0-agg server: in {} (all N posts + {} peer shares)",
        netsim::fmt_bytes(client_up + (S - 1) as f64 * w.share_b),
        S - 1,
    );

    for p in netsim::NETWORKS {
        println!("  {}:", p.header());

        // P3 is topology-independent.
        let p3 = p.maxlat(&mut rng, N)
            + p.xfer_server(N as f64 * w.result_b) // combiner uplink, N copies
                .max(p.xfer_client(w.result_b)); // each client's downlink

        // Throughput is pipelined (rounds overlap), so it is gated by the
        // slowest stage, not the sequential e2e sum; e2e is one-round latency.
        let report = |name: &str, p1: Duration, p2: Duration, cpu: Duration, pipe: &[(&str, Duration)]| {
            let net = p1 + p2 + p3;
            let e2e = cpu + net;
            let (bn_name, bn) = *pipe.iter().max_by_key(|(_, x)| *x).unwrap();
            println!(
                "    {:<6} net {} [P1 {} + P2 {} + P3 {}]  e2e {}  →  {:>7.2} MB/s pipelined (bottleneck {})",
                name,
                fmt(net),
                fmt(p1),
                fmt(p2),
                fmt(p3),
                fmt(e2e),
                useful_b / bn.as_secs_f64() / 1e6,
                bn_name,
            );
        };

        // AGG aggregators: each ingests N/AGG contributions; combiner ingests
        // AGG partial aggregates alongside the S shares.
        let p1 = p.maxlat(&mut rng, N)
            + p.xfer_client(w.contrib_b)
                .max(p.xfer_server((N / AGG) as f64 * w.contrib_b));
        let p2 = (p.maxlat(&mut rng, AGG) + p.xfer_server(AGG as f64 * w.agg_b)).max(
            p.maxlat(&mut rng, S)
                + p.xfer_server(w.share_b)
                    .max(p.xfer_server(S as f64 * w.share_b)),
        );
        report(
            "n-agg",
            p1,
            p2,
            a + st.c_aggregate_bucket + bsh + st.d_combine_decode,
            &[
                ("client", a),
                ("aggregator", st.c_aggregate_bucket),
                ("server", bsh),
                ("combiner", st.d_combine_decode),
                ("P1", p1),
                ("P2", p2),
                ("P3", p3),
            ],
        );

        // No aggregator: each client uplink carries S copies; every server
        // ingests all N; servers exchange shares all-to-all before each
        // decodes locally.
        let p1 = p.maxlat(&mut rng, N)
            + p.xfer_client(S as f64 * w.contrib_b)
                .max(p.xfer_server(N as f64 * w.contrib_b));
        let p2 = p.maxlat(&mut rng, S) + p.xfer_server((S - 1) as f64 * w.share_b);
        let per_server = bsh + st.c_aggregate_all + st.d_combine_decode;
        report(
            "0-agg",
            p1,
            p2,
            a + per_server,
            &[
                ("client", a),
                ("server", per_server),
                ("P1", p1),
                ("P2", p2),
                ("P3", p3),
            ],
        );
    }
}

fn main() {
    println!("ADCNet 1-round (IBLT-message) per-stage benchmark");
    println!("topology assumed for extrapolation: S={S} servers, N={N} clients");
    #[cfg(feature = "parallel")]
    println!(
        "parallel feature: ON  (rayon threads = {})",
        rayon::current_num_threads()
    );
    #[cfg(not(feature = "parallel"))]
    println!("parallel feature: OFF (single-threaded)");

    let mut results: Vec<(Scenario, StageTimes, Wires)> = Vec::new();
    for &sc in SCENARIOS {
        let (st, w) = run_scenario(sc);
        results.push((sc, st, w));
    }
    for (sc, st, w) in &results {
        extrapolate(*sc, st);
        network_extrapolate(*sc, st, w);
    }
}
