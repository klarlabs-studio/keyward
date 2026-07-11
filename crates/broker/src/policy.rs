//! The risk-tiered policy engine. Origin-binding is enforced *before* policy in
//! the broker; this decides, for a bound request, whether to auto-allow, step
//! up to a human, deny, or offer a propose-not-commit alternative.

use crate::action::{Action, ActionVerb};

/// Whether a human is present to approve, or the agent is running unattended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Attended,
    Unattended,
}

/// The policy outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Reversible, low-consequence, bound, pre-approved origin — issue a capability.
    AutoAllow,
    /// Requires a human (novel origin, or high-consequence while attended).
    StepUp(String),
    /// Hard denied (raw-secret export, or irreversible commit with no proposable form).
    Deny(String),
    /// Never-unattended commit → offer its reviewable, proposable counterpart.
    ProposeInstead(ActionVerb),
}

/// Policy configuration. `approved_origins` is the allow-list that lets a bound
/// request skip step-up. Everything else is conservative by default.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub approved_origins: Vec<String>,
}

impl Policy {
    pub fn with_approved_origins(origins: &[&str]) -> Self {
        Policy {
            approved_origins: origins.iter().map(|s| s.to_lowercase()).collect(),
        }
    }

    /// Decide, assuming the request is already origin-bound (checked in broker).
    pub fn decide(&self, action: &Action, mode: Mode, want_raw_secret: bool) -> Decision {
        // 1. Raw durable secret export is off by default — hard deny.
        if want_raw_secret {
            return Decision::Deny("raw durable secret export is disabled by default".into());
        }

        // 2. Never-unattended commits: propose-not-commit floor.
        if action.verb.never_unattended() {
            return match mode {
                Mode::Unattended => match action.verb.propose_variant() {
                    Some(v) => Decision::ProposeInstead(v),
                    None => Decision::Deny(
                        "irreversible high-consequence action cannot run unattended".into(),
                    ),
                },
                Mode::Attended => {
                    Decision::StepUp("high-consequence action requires human approval".into())
                }
            };
        }

        // 3. Novel origin (bound to the item, but not on the auto-approve list).
        let novel = !self
            .approved_origins
            .iter()
            .any(|o| o == &action.target.0);
        if novel {
            return match mode {
                Mode::Attended => Decision::StepUp("novel origin not on the auto-approve list".into()),
                Mode::Unattended => {
                    Decision::Deny("novel origin cannot be auto-approved unattended".into())
                }
            };
        }

        // 4. Reversible, low-consequence, bound, pre-approved → auto-allow.
        Decision::AutoAllow
    }
}
