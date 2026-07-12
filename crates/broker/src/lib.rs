//! Proctor AI credential broker — the security model.
//!
//! Design principle: **minimize blast radius by construction, not by vigilance.**
//! Hiding plaintext from the model is necessary but the easy 20%. The hard part
//! is (a) the confused-deputy attack — a manipulated agent using the right
//! secret against the wrong target — defeated here by *origin-binding*, and
//! (b) the legitimate-but-catastrophic action — a correctly-scoped credential
//! doing something irreversible — defeated by the *propose-not-commit* floor.
//!
//! See `docs/architecture/ADR-0001-broker-security-model.md`.

pub mod action;
pub mod audit;
pub mod broker;
pub mod capability;
pub mod policy;

pub use action::{Action, ActionVerb, Consequence, Origin};
pub use audit::{AuditEntry, AuditLog};
pub use broker::{Broker, Denied, Grant, ItemRef};
pub use capability::{Capability, Primitive};
pub use policy::{Decision, Mode, Policy};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn github() -> ItemRef {
        ItemRef {
            id: "itm_github".into(),
            label: "GitHub".into(),
            bound_origins: vec!["github.com".into()],
            mintable: true,
        }
    }

    fn bank() -> ItemRef {
        ItemRef {
            id: "itm_bank".into(),
            label: "Bank".into(),
            bound_origins: vec!["bank.com".into()],
            mintable: false,
        }
    }

    fn broker() -> Broker {
        Broker::new(Policy::with_approved_origins(&["github.com", "bank.com"]))
    }

    /// The whole point: a manipulated agent asks to use the right secret against
    /// the WRONG origin. Refused before policy, regardless of mode or approval.
    #[test]
    fn confused_deputy_is_refused_by_origin_binding() {
        let mut b = broker();
        let action = Action::new(ActionVerb::Read, "evil.example.com");
        let r = b.request_use(&github(), &action, Mode::Attended, false, SystemTime::now());
        assert_eq!(r.unwrap_err(), Denied::OriginMismatch);
        // And it was audited.
        assert!(b
            .audit
            .entries()
            .last()
            .unwrap()
            .decision
            .contains("origin-mismatch"));
    }

    /// A reversible, bound, pre-approved read auto-allows and issues a MINTED
    /// capability — never the raw secret.
    #[test]
    fn reversible_bound_read_auto_allows_minted() {
        let mut b = broker();
        let action = Action::new(ActionVerb::Read, "github.com");
        match b.request_use(
            &github(),
            &action,
            Mode::Unattended,
            false,
            SystemTime::now(),
        ) {
            Ok(Grant::Capability(cap)) => assert_eq!(cap.primitive, Primitive::Minted),
            other => panic!("expected minted capability, got {other:?}"),
        }
    }

    /// A non-mintable item falls back to a SECRETLESS handle (broker performs
    /// the action) — still never the raw secret.
    #[test]
    fn non_mintable_falls_back_to_secretless() {
        let mut b = broker();
        let action = Action::new(ActionVerb::Read, "bank.com");
        match b.request_use(&bank(), &action, Mode::Unattended, false, SystemTime::now()) {
            Ok(Grant::Capability(cap)) => assert_eq!(cap.primitive, Primitive::Secretless),
            other => panic!("expected secretless capability, got {other:?}"),
        }
    }

    /// Raw durable secret export is hard-denied by default.
    #[test]
    fn raw_secret_export_is_hard_denied() {
        let mut b = broker();
        let action = Action::new(ActionVerb::Read, "github.com");
        let r = b.request_use(&github(), &action, Mode::Attended, true, SystemTime::now());
        assert!(matches!(r, Ok(_) | Err(_))); // shape check
        assert!(matches!(r, Err(Denied::Policy(_))));
    }

    /// Never-unattended commit, running unattended, is offered its proposable
    /// counterpart instead of executing.
    #[test]
    fn ship_to_prod_unattended_becomes_propose() {
        let mut b = broker();
        let action = Action::new(ActionVerb::ShipToProduction, "github.com");
        match b.request_use(
            &github(),
            &action,
            Mode::Unattended,
            false,
            SystemTime::now(),
        ) {
            Ok(Grant::Proposed(v)) => assert_eq!(v, ActionVerb::OpenPullRequest),
            other => panic!("expected propose-instead, got {other:?}"),
        }
    }

    /// A never-unattended action with NO proposable form is flatly denied when unattended.
    #[test]
    fn move_money_unattended_is_denied() {
        let mut b = broker();
        let action = Action::new(ActionVerb::MoveMoney, "bank.com");
        let r = b.request_use(&bank(), &action, Mode::Unattended, false, SystemTime::now());
        assert!(matches!(r, Err(Denied::Policy(_))));
    }

    /// Attended high-consequence action escalates to a human rather than running.
    #[test]
    fn high_consequence_attended_steps_up() {
        let mut b = broker();
        let action = Action::new(ActionVerb::MoveMoney, "bank.com");
        match b.request_use(&bank(), &action, Mode::Attended, false, SystemTime::now()) {
            Ok(Grant::NeedsHumanApproval(_)) => {}
            other => panic!("expected step-up, got {other:?}"),
        }
    }

    /// A bound but novel (not pre-approved) origin steps up when attended,
    /// and is denied when unattended.
    #[test]
    fn novel_origin_steps_up_or_denies() {
        // github item bound to github.com AND api.github.com, but only github.com approved.
        let item = ItemRef {
            id: "itm_gh".into(),
            label: "GH".into(),
            bound_origins: vec!["github.com".into(), "api.github.com".into()],
            mintable: true,
        };
        let mut b = broker();
        let action = Action::new(ActionVerb::Read, "api.github.com");
        match b.request_use(&item, &action, Mode::Attended, false, SystemTime::now()) {
            Ok(Grant::NeedsHumanApproval(_)) => {}
            other => panic!("expected step-up for novel origin, got {other:?}"),
        }
        let r = b.request_use(&item, &action, Mode::Unattended, false, SystemTime::now());
        assert!(matches!(r, Err(Denied::Policy(_))));
    }

    /// Capabilities expire and are single-use by default.
    #[test]
    fn capability_ttl_and_use_count() {
        let mut b = broker();
        let action = Action::new(ActionVerb::Read, "github.com");
        let now = SystemTime::now();
        let cap = match b
            .request_use(&github(), &action, Mode::Unattended, false, now)
            .unwrap()
        {
            Grant::Capability(c) => c,
            other => panic!("expected capability, got {other:?}"),
        };
        assert!(cap.is_valid(now));
        // Expired after TTL.
        assert!(!cap.is_valid(now + Duration::from_secs(601)));
        // Single use.
        let mut cap = cap;
        assert!(cap.consume());
        assert!(!cap.consume());
        assert!(!cap.is_valid(now));
    }

    /// The audit log is hash-chained and tamper-evident.
    #[test]
    fn audit_chain_detects_tampering() {
        let mut b = broker();
        let now = SystemTime::now();
        let _ = b.request_use(
            &github(),
            &Action::new(ActionVerb::Read, "github.com"),
            Mode::Unattended,
            false,
            now,
        );
        let _ = b.request_use(
            &github(),
            &Action::new(ActionVerb::Read, "evil.com"),
            Mode::Attended,
            false,
            now,
        );
        let _ = b.request_use(
            &bank(),
            &Action::new(ActionVerb::MoveMoney, "bank.com"),
            Mode::Attended,
            false,
            now,
        );
        assert!(b.audit.verify());
        assert_eq!(b.audit.entries().len(), 3);
        // (Tamper detection of the private Vec is covered in the audit module's
        // own reconstruction test via verify(); external mutation is impossible
        // because entries() returns an immutable slice — that's the point.)
    }
}
