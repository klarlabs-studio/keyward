//! Capabilities — narrow, short-lived, origin-bound grants. The blast-radius
//! minimizer: even a leaked capability is scoped to one item × origin × verb,
//! expires quickly, and is single/few-use.

use crate::action::{ActionVerb, Origin};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// How the credential is delivered. Minted (fresh scoped token) and Secretless
/// (broker performs the action) are preferred; RawSecret is the last resort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primitive {
    /// A fresh, narrowly-scoped, short-TTL token the broker minted (preferred).
    Minted,
    /// No secret handed over; the broker performs the action itself.
    Secretless,
    /// The durable stored secret (off by default; hard-gated).
    RawSecret,
}

/// A grant the broker issues. Bound on item × origin × verb × TTL × uses.
#[derive(Clone, Debug)]
pub struct Capability {
    pub id: Uuid,
    pub item_id: String,
    pub origin: Origin,
    pub verb: ActionVerb,
    pub primitive: Primitive,
    pub expires_at: SystemTime,
    pub uses_remaining: u32,
}

impl Capability {
    pub fn new(
        item_id: String,
        origin: Origin,
        verb: ActionVerb,
        primitive: Primitive,
        now: SystemTime,
        ttl: Duration,
        uses: u32,
    ) -> Capability {
        Capability {
            id: Uuid::new_v4(),
            item_id,
            origin,
            verb,
            primitive,
            expires_at: now + ttl,
            uses_remaining: uses,
        }
    }

    /// Valid iff not expired and it has uses left.
    pub fn is_valid(&self, now: SystemTime) -> bool {
        now < self.expires_at && self.uses_remaining > 0
    }

    /// Spend one use. Returns false if none remain.
    pub fn consume(&mut self) -> bool {
        if self.uses_remaining == 0 {
            return false;
        }
        self.uses_remaining -= 1;
        true
    }
}
