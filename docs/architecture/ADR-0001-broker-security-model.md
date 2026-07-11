# ADR-0001 — Credential broker security model

> **Status:** Accepted (prototype implemented) · **Date:** July 2026
> **Context:** [Product Spec §6](../product/product-spec.md) · **Implements:** `crates/broker`

## Context

Proctor's wedge (Phase B) is an MCP credential broker that lets AI agents *act*
with credentials without ever possessing the plaintext. The naive framing —
"keep the secret out of the model's context" — is necessary but the easy 20%.
Two harder threats define the design:

1. **Confused deputy / prompt injection.** The *agent* requests the action and
   can be manipulated (poisoned page, repo, doc) into using the right secret
   against the *wrong* target. Hiding plaintext does nothing here.
2. **Legitimate-but-catastrophic action.** A correctly-scoped credential, used
   exactly as authorized by a mistaken/manipulated agent, does something
   irreversible (delete prod DB, ship a broken release). The *authority itself*
   is the vulnerability, not the secret.

Human confirmation cannot be the primary defense: it fails via **habituation**
(rubber-stamping) and **absence** (agents run unattended). The deciding axis for
autonomy is **reversibility × consequence**, not credential narrowness.

## Decision

**Minimize blast radius by construction, not by vigilance.** The system must be
safe even when every human control fails. Concretely:

### 1. Default primitive: mint / secretless, never raw (preference order)
- **Minted** — exchange the stored secret for a fresh, narrowly-scoped, short-TTL
  token (GitHub fine-grained/App tokens, cloud STS, OAuth Token Exchange RFC 8693).
- **Secretless** — when minting isn't possible, the agent gets a handle; the
  broker performs the action. The secret never leaves the broker.
- **RawSecret** — last resort, off by default, hard-gated.

### 2. Origin binding (anti-confused-deputy)
Every request is checked against the item's `bound_origins` **before policy and
independent of any approval**. A mismatch is refused outright. This is the same
insight that makes passkeys phishing-resistant: binding beats confirmation
because it does not depend on human alertness.

### 3. Capabilities with caveats
Grants are scoped on `item × origin × verb × TTL × use-count`. They expire and
are single/few-use. A leaked capability is a near-non-event.

### 4. Risk-tiered policy (confirmation as a rare escalation)
- **AutoAllow** — reversible, low-consequence, bound, pre-approved origin.
- **StepUp** — novel origin, or high-consequence while attended.
- **Deny** — raw-secret export; irreversible commit with no proposable form (unattended).
- **ProposeInstead** — never-unattended commit → offer its proposable counterpart.

### 5. Propose-not-commit (the autonomy floor)
Minted credentials are shaped so the agent **cannot commit an irreversible
action** — it can *open* a PR not *merge*, *draft* an email not *send*, *stage*
not *settle*. High-consequence outputs land as **reviewable artifacts**.

**Never-unattended (locked default, user-editable):** delete/destroy data ·
move money · ship to production · send comms as the user · rotate/revoke *other*
credentials.

### 6. Tamper-evident audit
Every decision is appended to a SHA-256 **hash-chained** log; altering any past
entry breaks `verify()`.

## Where the tension relocates (known limits)

- **Classification is the new single point of failure.** Propose-not-commit only
  works if actions are correctly labeled and minted creds enforce it. Services
  without a propose/commit split (send email, charge card, delete object) fall
  back to human-gate or accept-with-guardrails. → a **capability-risk policy
  layer** is owed.
- **Review-queue fatigue** is approval fatigue in disguise. → the review surface
  must risk-rank and make the dangerous item look dangerous.
- **Irreducible residue:** irreversible + time-critical + must-run-unattended
  actions (e.g. emergency rotation) have no proposable form; grant with tight
  guardrails + loud out-of-band alerts, or forbid. A conscious floor.

## Implementation status

Implemented in `crates/broker` (`action`, `capability`, `policy`, `audit`,
`broker`) with 11 unit tests + a `crates/vault` prototype (Argon2id +
XChaCha20-Poly1305, 4 tests). `cargo run -p proctor-cli -- demo` shows all paths
end-to-end. **Not yet built:** real minting integrations (GitHub/STS/RFC 8693),
MCP transport wiring, unattended-policy pre-authorization + out-of-band alerts,
anomaly detection, and a formal security review before any real use.

## Consequences

- The broker never returns plaintext on the auto-allow path — enforced at the
  type level (`Grant` has no raw-secret variant reachable by default).
- Confirmation becomes rare and meaningful, defeating habituation.
- Safety holds under unattended operation via scoping + propose-not-commit, not
  via a human being present.
