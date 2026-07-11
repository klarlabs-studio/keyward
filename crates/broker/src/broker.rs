//! The broker. Enforces, in order: (1) origin-binding — the anti-confused-deputy
//! guarantee that holds *regardless of approval*; (2) the risk-tiered policy;
//! (3) primitive selection preferring minted/secretless over the raw secret.
//! Every decision is written to a hash-chained audit log.

use crate::action::{Action, Origin};
use crate::audit::AuditLog;
use crate::capability::{Capability, Primitive};
use crate::policy::{Decision, Mode, Policy};
use std::time::{Duration, SystemTime};

/// Secret-free item metadata the broker operates on. It never sees plaintext.
#[derive(Clone, Debug)]
pub struct ItemRef {
    pub id: String,
    pub label: String,
    pub bound_origins: Vec<String>,
    pub mintable: bool,
}

/// What the broker returns to a (successful) request. Never a raw secret.
#[derive(Clone, Debug)]
pub enum Grant {
    /// A scoped capability (minted token or secretless action handle).
    Capability(Capability),
    /// The action needs a human; the reason is surfaced to the approval UI.
    NeedsHumanApproval(String),
    /// Propose-not-commit: the broker offers a reviewable alternative verb.
    Proposed(crate::action::ActionVerb),
}

/// Why a request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The requested origin is not one the item is bound to. Confused-deputy defense.
    OriginMismatch,
    /// Policy refused it; reason included.
    Policy(String),
}

pub struct Broker {
    pub policy: Policy,
    pub audit: AuditLog,
    pub default_ttl: Duration,
    pub default_uses: u32,
}

impl Broker {
    pub fn new(policy: Policy) -> Self {
        Broker {
            policy,
            audit: AuditLog::new(),
            default_ttl: Duration::from_secs(600), // 10 minutes
            default_uses: 1,
        }
    }

    /// Request to *use* a credential. Returns an action/handle, never plaintext.
    pub fn request_use(
        &mut self,
        item: &ItemRef,
        action: &Action,
        mode: Mode,
        want_raw_secret: bool,
        now: SystemTime,
    ) -> Result<Grant, Denied> {
        let item_id = item.id.as_str();
        let origin = action.target.0.as_str();
        let verb = action.verb.as_str();

        // (1) ORIGIN BINDING — enforced before anything else, and independent of
        // any human approval. A manipulated agent cannot redirect the secret.
        let bound = item
            .bound_origins
            .iter()
            .any(|o| Origin::normalized(o) == action.target);
        if !bound {
            self.audit.append(item_id, origin, verb, "DENY:origin-mismatch");
            return Err(Denied::OriginMismatch);
        }

        // (2) POLICY.
        match self.policy.decide(action, mode, want_raw_secret) {
            Decision::Deny(reason) => {
                self.audit
                    .append(item_id, origin, verb, &format!("DENY:{reason}"));
                Err(Denied::Policy(reason))
            }
            Decision::StepUp(reason) => {
                self.audit
                    .append(item_id, origin, verb, &format!("STEPUP:{reason}"));
                Ok(Grant::NeedsHumanApproval(reason))
            }
            Decision::ProposeInstead(v) => {
                self.audit
                    .append(item_id, origin, verb, &format!("PROPOSE:{}", v.as_str()));
                Ok(Grant::Proposed(v))
            }
            Decision::AutoAllow => {
                // (3) PRIMITIVE SELECTION — prefer minting; else secretless.
                // The raw durable secret is never selected here (it's hard-denied
                // by policy above), keeping the durable secret out of reach.
                let primitive = if item.mintable {
                    Primitive::Minted
                } else {
                    Primitive::Secretless
                };
                let cap = Capability::new(
                    item.id.clone(),
                    action.target.clone(),
                    action.verb,
                    primitive,
                    now,
                    self.default_ttl,
                    self.default_uses,
                );
                self.audit.append(
                    item_id,
                    origin,
                    verb,
                    &format!("ALLOW:{:?}:cap={}", primitive, cap.id),
                );
                Ok(Grant::Capability(cap))
            }
        }
    }
}
