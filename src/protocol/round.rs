//! Round / phase types for the 4-phase round.

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RoundContext {
    Client = 0,
    Aggregator = 1,
    ServerPartial = 2,
    ServerLeader = 3,
}

impl RoundContext {
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
