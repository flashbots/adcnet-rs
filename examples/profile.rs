//! Profiling driver. Calls the primitive functions directly so each stage
//! isolates one SIMD-able kernel. Setup runs once; pair with `perf record -D
//! <setup_ms + buffer>` to skip the setup samples.
//!
//! Env:
//!   PROFILE_STAGE   one of (field-additive IBLT path, parametrized by
//!                          PROFILE_BYTES = payload bytes per insert):
//!                     `blind`        — `field_round::client_blind`
//!                     `aggregate`    — `field_round::aggregate_clients` × N
//!                     `share`        — `field_round::server_share` × N secrets
//!                     `combine`      — `field_round::combine_partials` × S
//!                   XOR-additive message-vector path (parametrized by
//!                   PROFILE_BYTES = byte-buffer length):
//!                     `xor_blind`, `xor_aggregate`, `xor_share`, `xor_combine`
//!                   IBLT decode-only:
//!                     `decode`
//!                   Roll-ups (for sanity):
//!                     `all`, `xor_all`
//!   PROFILE_N       (default 100)   number of clients
//!   PROFILE_S       (default 4)     number of servers
//!   PROFILE_BYTES   (default 1024)
//!                   For field stages: payload bytes per IBLT insert.
//!                   Use small values (e.g. 24) to approximate the
//!                   auction-bid layout (ξ ~ 4); larger (1024+) for the
//!                   1-round message layout (ξ ~ 147).
//!                   For xor stages: byte-buffer length.
//!   PROFILE_ITERS   (default auto)
//!
//! Build:
//!     cargo build -j 8 --profile profiling --example profile [--features parallel]

use std::env;
use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use adcnet::auction::iblt::iblt_field_element_count;
use adcnet::crypto::SharedKey;
use adcnet::encoders::iblt_msg::{self, IbltMsgParams};
use adcnet::field_round;
use adcnet::xor_round;

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

#[derive(Clone, Copy)]
enum Stage {
    // Field-additive over IBLT field-element vector.
    Blind,
    Aggregate,
    Share,
    Combine,
    Decode,
    All,
    // XOR-additive over flat byte buffer.
    XorBlind,
    XorAggregate,
    XorShare,
    XorCombine,
    XorAll,
}

impl Stage {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "blind" => Stage::Blind,
            "aggregate" => Stage::Aggregate,
            "share" => Stage::Share,
            "combine" => Stage::Combine,
            "decode" => Stage::Decode,
            "all" => Stage::All,
            "xor_blind" => Stage::XorBlind,
            "xor_aggregate" => Stage::XorAggregate,
            "xor_share" => Stage::XorShare,
            "xor_combine" => Stage::XorCombine,
            "xor_all" => Stage::XorAll,
            _ => return None,
        })
    }

    fn is_xor(self) -> bool {
        matches!(
            self,
            Stage::XorBlind | Stage::XorAggregate | Stage::XorShare | Stage::XorCombine | Stage::XorAll
        )
    }
}

/// Per-client × per-server shared secrets. Deterministic synthetic — same
/// shape as ECDH would produce.
fn build_shared_secrets(n_clients: usize, n_servers: usize) -> (Vec<Vec<SharedKey>>, Vec<Vec<SharedKey>>) {
    let mut client_secrets = vec![Vec::with_capacity(n_servers); n_clients];
    let mut server_secrets = vec![Vec::with_capacity(n_clients); n_servers];
    for (c, client) in client_secrets.iter_mut().enumerate() {
        for (s, server) in server_secrets.iter_mut().enumerate() {
            let k = SharedKey::from_bytes(format!("c{:04}s{:02}", c, s).as_bytes());
            client.push(k.clone());
            server.push(k);
        }
    }
    (client_secrets, server_secrets)
}

struct FieldSetup {
    client_secrets: Vec<Vec<SharedKey>>,
    server_secrets: Vec<Vec<SharedKey>>,
    params: IbltMsgParams,
    blinded: Vec<Vec<u64>>,
    shares: Vec<Vec<u64>>,
    agg: Vec<u64>,
    recovered: Vec<u64>,
}

struct XorSetup {
    client_secrets: Vec<Vec<SharedKey>>,
    server_secrets: Vec<Vec<SharedKey>>,
    blinded: Vec<Vec<u8>>,
    shares: Vec<Vec<u8>>,
    agg: Vec<u8>,
}

fn setup_field(n_clients: usize, n_servers: usize, bytes_per_insert: usize) -> FieldSetup {
    let (client_secrets, server_secrets) = build_shared_secrets(n_clients, n_servers);
    let params = IbltMsgParams {
        estimated_messages: n_clients as u32,
        max_payload_bytes: bytes_per_insert,
    };
    let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
    let blinded: Vec<Vec<u64>> = (0..n_clients)
        .map(|c| {
            let payload: Vec<u8> = (0..bytes_per_insert)
                .map(|i| ((c * 17 + i) % 251) as u8)
                .collect();
            let contents = iblt_msg::encode_payload(&params, &payload, &mut rng).unwrap();
            field_round::client_blind(&client_secrets[c], 1, contents)
        })
        .collect();
    let vec_len = blinded[0].len();
    let shares: Vec<Vec<u64>> = (0..n_servers)
        .map(|s| field_round::server_share(&server_secrets[s], 1, vec_len))
        .collect();
    let blinded_slices: Vec<&[u64]> = blinded.iter().map(|v| v.as_slice()).collect();
    let agg = field_round::aggregate_clients(&blinded_slices);
    let share_slices: Vec<&[u64]> = shares.iter().map(|v| v.as_slice()).collect();
    let recovered = field_round::combine_partials(&agg, &share_slices);
    FieldSetup { client_secrets, server_secrets, params, blinded, shares, agg, recovered }
}

fn setup_xor(n_clients: usize, n_servers: usize, bytes: usize) -> XorSetup {
    let (client_secrets, server_secrets) = build_shared_secrets(n_clients, n_servers);
    let blinded: Vec<Vec<u8>> = (0..n_clients)
        .map(|c| {
            let plain: Vec<u8> = (0..bytes).map(|i| ((c * 31 + i) % 251) as u8).collect();
            xor_round::client_blind(&client_secrets[c], 1, plain)
        })
        .collect();
    let shares: Vec<Vec<u8>> = (0..n_servers)
        .map(|s| xor_round::server_share(&server_secrets[s], 1, bytes))
        .collect();
    let blinded_slices: Vec<&[u8]> = blinded.iter().map(|v| v.as_slice()).collect();
    let agg = xor_round::aggregate_clients(&blinded_slices);
    XorSetup { client_secrets, server_secrets, blinded, shares, agg }
}

fn vec_len_field(n_clients: usize, bytes_per_insert: usize) -> usize {
    let params = IbltMsgParams {
        estimated_messages: n_clients as u32,
        max_payload_bytes: bytes_per_insert,
    };
    iblt_field_element_count(params.estimated_messages, params.xi())
}

fn default_iters(stage: Stage, n: usize, vec_len: usize) -> usize {
    let s = 4u64;
    let work: u64 = match stage {
        Stage::Aggregate | Stage::Share | Stage::XorAggregate | Stage::XorShare => {
            n as u64 * vec_len as u64
        }
        Stage::Blind | Stage::Combine | Stage::XorBlind | Stage::XorCombine => {
            s * vec_len as u64
        }
        Stage::Decode => vec_len as u64,
        Stage::All | Stage::XorAll => (n as u64 + s) * vec_len as u64,
    };
    // ~2 ns / u64 (or byte) across the parallel SIMD path on average.
    let ns_per_iter = work.saturating_mul(2);
    let target_ns: u64 = 4_000_000_000;
    (target_ns / ns_per_iter.max(1)).clamp(20, 50_000) as usize
}

fn run_field(stage: Stage, iters: usize, setup: &FieldSetup) {
    let blinded_slices: Vec<&[u64]> = setup.blinded.iter().map(|v| v.as_slice()).collect();
    let share_slices: Vec<&[u64]> = setup.shares.iter().map(|v| v.as_slice()).collect();
    let vec_len = setup.blinded[0].len();
    let c0_secrets = &setup.client_secrets[0];
    let s0_secrets = &setup.server_secrets[0];
    let c0_content = setup.blinded[0].clone();
    for _ in 0..iters {
        match stage {
            Stage::Blind => {
                let _ = field_round::client_blind(c0_secrets, 1, c0_content.clone());
            }
            Stage::Aggregate => {
                let _ = field_round::aggregate_clients(&blinded_slices);
            }
            Stage::Share => {
                let _ = field_round::server_share(s0_secrets, 1, vec_len);
            }
            Stage::Combine => {
                let _ = field_round::combine_partials(&setup.agg, &share_slices);
            }
            Stage::Decode => {
                let _ = iblt_msg::decode_round(&setup.params, &setup.recovered).unwrap();
            }
            Stage::All => {
                let agg = field_round::aggregate_clients(&blinded_slices);
                let _ = field_round::combine_partials(&agg, &share_slices);
            }
            _ => unreachable!(),
        }
    }
}

fn run_xor(stage: Stage, iters: usize, setup: &XorSetup) {
    let blinded_slices: Vec<&[u8]> = setup.blinded.iter().map(|v| v.as_slice()).collect();
    let share_slices: Vec<&[u8]> = setup.shares.iter().map(|v| v.as_slice()).collect();
    let vec_len = setup.blinded[0].len();
    let c0_secrets = &setup.client_secrets[0];
    let s0_secrets = &setup.server_secrets[0];
    let c0_content = setup.blinded[0].clone();
    for _ in 0..iters {
        match stage {
            Stage::XorBlind => {
                let _ = xor_round::client_blind(c0_secrets, 1, c0_content.clone());
            }
            Stage::XorAggregate => {
                let _ = xor_round::aggregate_clients(&blinded_slices);
            }
            Stage::XorShare => {
                let _ = xor_round::server_share(s0_secrets, 1, vec_len);
            }
            Stage::XorCombine => {
                let _ = xor_round::combine_partials(&setup.agg, &share_slices);
            }
            Stage::XorAll => {
                let agg = xor_round::aggregate_clients(&blinded_slices);
                let _ = xor_round::combine_partials(&agg, &share_slices);
            }
            _ => unreachable!(),
        }
    }
}

fn main() {
    let stage_str = env_string("PROFILE_STAGE", "aggregate");
    let stage = Stage::parse(&stage_str).unwrap_or_else(|| {
        eprintln!("unknown PROFILE_STAGE={stage_str}; falling back to aggregate");
        Stage::Aggregate
    });
    let n = env_usize("PROFILE_N", 100);
    let s = env_usize("PROFILE_S", 4);
    let bytes = env_usize("PROFILE_BYTES", 1024);

    let vec_len = if stage.is_xor() {
        bytes
    } else {
        vec_len_field(n, bytes)
    };
    let iters = env_usize("PROFILE_ITERS", default_iters(stage, n, vec_len));

    let elem_label = if stage.is_xor() { "B" } else { "u64" };
    let vec_bytes = if stage.is_xor() { vec_len } else { vec_len * 8 };
    eprintln!(
        "profile: stage={stage_str} N={n} S={s} bytes={bytes} \
         vec_len={vec_len} {elem_label} ({} KiB / vector) iters={iters} parallel={}",
        vec_bytes / 1024,
        cfg!(feature = "parallel"),
    );

    let t_setup = Instant::now();
    let elapsed_setup_ms;
    if stage.is_xor() {
        let setup = setup_xor(n, s, bytes);
        elapsed_setup_ms = t_setup.elapsed().as_millis();
        eprintln!("setup: {} ms", elapsed_setup_ms);
        eprintln!("STAGE_BEGIN delay_ms={}", elapsed_setup_ms);
        let t = Instant::now();
        run_xor(stage, iters, &setup);
        let dt = t.elapsed();
        eprintln!(
            "stage {stage_str}: {iters} iters in {:.2?} ({:.2?} / iter)",
            dt,
            dt / iters as u32
        );
    } else {
        let setup = setup_field(n, s, bytes);
        elapsed_setup_ms = t_setup.elapsed().as_millis();
        eprintln!("setup: {} ms", elapsed_setup_ms);
        eprintln!("STAGE_BEGIN delay_ms={}", elapsed_setup_ms);
        let t = Instant::now();
        run_field(stage, iters, &setup);
        let dt = t.elapsed();
        eprintln!(
            "stage {stage_str}: {iters} iters in {:.2?} ({:.2?} / iter)",
            dt,
            dt / iters as u32
        );
    }
}
