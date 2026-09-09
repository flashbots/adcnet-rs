use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Whether the protocol uses the optional aggregator layer. When `Disabled`,
/// clients submit signed round messages directly to servers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationMode {
    #[default]
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdcNetConfig {
    pub auction_slots: u32,
    pub message_length: usize,
    pub min_clients: u32,
    #[serde(with = "humantime_serde", default = "default_round")]
    pub round_duration: Duration,
    #[serde(default)]
    pub aggregation: AggregationMode,
}

fn default_round() -> Duration {
    Duration::from_secs(10)
}

impl Default for AdcNetConfig {
    fn default() -> Self {
        Self {
            auction_slots: 10,
            message_length: 0,
            min_clients: 1,
            round_duration: default_round(),
            aggregation: AggregationMode::Enabled,
        }
    }
}

/// Result of running the auction over the previous round's IBLT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuctionResult {
    pub should_send: bool,
    pub message_start_index: usize,
    pub total_allocated: usize,
}

// minimal humantime shim so we don't pull a new dep
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}ms", d.as_millis()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        // accept either "10s" / "500ms" / a bare number meaning seconds
        if let Some(rest) = s.strip_suffix("ms") {
            let n: u64 = rest.trim().parse().map_err(serde::de::Error::custom)?;
            return Ok(Duration::from_millis(n));
        }
        if let Some(rest) = s.strip_suffix('s') {
            let n: u64 = rest.trim().parse().map_err(serde::de::Error::custom)?;
            return Ok(Duration::from_secs(n));
        }
        let n: u64 = s.trim().parse().map_err(serde::de::Error::custom)?;
        Ok(Duration::from_secs(n))
    }
}
