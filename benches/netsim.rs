//! Network simulation shared by the per-stage benches (`mod netsim;`).
//!
//! Wire time is modelled separately from CPU so either can be read as the
//! bottleneck, then composed into e2e numbers by each bench:
//!   - per-message one-way latency = `lat_ms + U[0, jitter_ms)`; parallel
//!     arrivals take the max draw (deterministic rng, seeded by the caller).
//!   - two link classes: client links (residential, the slow side) and
//!     server-side links (servers, aggregators, leader/combiner — cloud,
//!     ~Gbit). Each endpoint serializes its own total bytes at its class
//!     rate, both directions, so every flow is gated by BOTH ends: sender
//!     uplink and receiver downlink.

use rand::Rng;
use rand_chacha::ChaCha20Rng;
use std::time::Duration;

pub struct NetProfile {
    pub label: &'static str,
    pub lat_ms: f64,
    pub jitter_ms: f64,
    /// Client (residential) link rate, Mbit/s, both directions.
    pub client_mbps: f64,
    /// Cloud link rate (servers, aggregators, leader), Mbit/s.
    pub server_mbps: f64,
}

pub const NETWORKS: &[NetProfile] = &[
    NetProfile { label: "LAN  ", lat_ms: 0.5, jitter_ms: 0.2, client_mbps: 1000.0, server_mbps: 1000.0 },
    NetProfile { label: "fiber", lat_ms: 25.0, jitter_ms: 10.0, client_mbps: 100.0, server_mbps: 1000.0 },
    NetProfile { label: "dsl  ", lat_ms: 35.0, jitter_ms: 15.0, client_mbps: 20.0, server_mbps: 1000.0 },
];

impl NetProfile {
    pub fn header(&self) -> String {
        format!(
            "{} ({}+U[0,{})ms, client {} / cloud {} Mbps)",
            self.label, self.lat_ms, self.jitter_ms, self.client_mbps, self.server_mbps
        )
    }

    /// Serialization time of `bytes` over one client-class link.
    pub fn xfer_client(&self, bytes: f64) -> Duration {
        Duration::from_secs_f64(bytes * 8.0 / (self.client_mbps * 1e6))
    }

    /// Serialization time of `bytes` over one cloud-class link.
    pub fn xfer_server(&self, bytes: f64) -> Duration {
        Duration::from_secs_f64(bytes * 8.0 / (self.server_mbps * 1e6))
    }

    /// Max one-way latency over `k` parallel message arrivals.
    pub fn maxlat(&self, rng: &mut ChaCha20Rng, k: usize) -> Duration {
        let ms = (0..k)
            .map(|_| self.lat_ms + rng.gen::<f64>() * self.jitter_ms)
            .fold(0.0, f64::max);
        Duration::from_secs_f64(ms / 1e3)
    }
}

/// Actual bincode wire size of a message, in bytes.
pub fn wire_size<T: serde::Serialize>(t: &T) -> f64 {
    bincode::serialized_size(t).unwrap() as f64
}

pub fn fmt_bytes(b: f64) -> String {
    if b < 1024.0 {
        format!("{:.0} B", b)
    } else if b < 1024.0 * 1024.0 {
        format!("{:.2} KiB", b / 1024.0)
    } else {
        format!("{:.2} MiB", b / (1024.0 * 1024.0))
    }
}
