//! Round / phase types for the 4-phase round.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RoundContext {
    Client = 0,
    Aggregator = 1,
    ServerPartial = 2,
    ServerLeader = 3,
}

impl RoundContext {
    fn from_u8(n: u8) -> Self {
        match n & 3 {
            0 => RoundContext::Client,
            1 => RoundContext::Aggregator,
            2 => RoundContext::ServerPartial,
            _ => RoundContext::ServerLeader,
        }
    }

    fn next(self) -> (RoundContext, bool /* wrapped */) {
        match self {
            RoundContext::Client => (RoundContext::Aggregator, false),
            RoundContext::Aggregator => (RoundContext::ServerPartial, false),
            RoundContext::ServerPartial => (RoundContext::ServerLeader, false),
            RoundContext::ServerLeader => (RoundContext::Client, true),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Round {
    pub number: i64,
    pub context: RoundContext,
}

impl Round {
    pub fn new(number: i64, context: RoundContext) -> Self {
        Self { number, context }
    }

    pub fn is_after(self, other: Round) -> bool {
        self.number > other.number
            || (self.number == other.number && self.context > other.context)
    }

    pub fn advance(self) -> Round {
        let (next_ctx, wrapped) = self.context.next();
        Round {
            number: self.number + if wrapped { 1 } else { 0 },
            context: next_ctx,
        }
    }
}

#[derive(Debug, Error)]
pub enum RoundError {
    #[error("round duration must be positive")]
    NonPositiveDuration,
    #[error("round duration too small")]
    TooSmall,
    #[error("time must not be negative")]
    NegativeTime,
}

pub fn round_for_time(instant: SystemTime, round_duration: Duration) -> Result<Round, RoundError> {
    if round_duration.is_zero() {
        return Err(RoundError::NonPositiveDuration);
    }
    let unix_ms = instant
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RoundError::NegativeTime)?
        .as_millis() as i64;
    let tick_ms = (round_duration.as_millis() as i64) / 4;
    if tick_ms == 0 {
        return Err(RoundError::TooSmall);
    }
    let n_ticks = unix_ms / tick_ms;
    Ok(Round {
        number: n_ticks / 4,
        context: RoundContext::from_u8((n_ticks % 4) as u8),
    })
}

pub fn time_for_round(round: Round, round_duration: Duration) -> SystemTime {
    let offset = round_duration * (round.number as u32)
        + Duration::from_millis(
            (round_duration.as_millis() as u64) * (round.context as u64) / 4,
        );
    UNIX_EPOCH + offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_cycles_through_phases() {
        let r0 = Round::new(0, RoundContext::Client);
        let r1 = r0.advance();
        let r2 = r1.advance();
        let r3 = r2.advance();
        let r4 = r3.advance();
        assert_eq!(r1.context, RoundContext::Aggregator);
        assert_eq!(r2.context, RoundContext::ServerPartial);
        assert_eq!(r3.context, RoundContext::ServerLeader);
        assert_eq!(r4, Round::new(1, RoundContext::Client));
    }

    #[test]
    fn is_after_orders_by_number_then_phase() {
        let a = Round::new(1, RoundContext::ServerLeader);
        let b = Round::new(2, RoundContext::Client);
        assert!(b.is_after(a));
    }
}
