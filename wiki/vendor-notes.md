---
updated: 2026-07-19
tags: [vendors, reference]
---
# Vendor and tooling notes

## nox (own tool)
Keep it current — the installed binary was three minor versions behind (1.6.0 vs
1.9.2) and scans were silently missing rules, including the `CRYPTO-001` analyzer
folded in from the retired sast plugin. **Clear the cache after upgrading**
(`nox cache clear`); a stale cache across an analyzer-set change returns stale
results. Note `nox rules` is an MCP tool, not a CLI command.

Standing caveat: nox flagged two `fetch` sites as TAINT-006/CWE-918 SSRF. That
call is wrong — the tainted value is the request BODY, and a tainted body is not
SSRF. It pointed at the right lines for the wrong reason, and the real bug there
was an unvalidated URL scheme.

## Competitors — audit posture
Both 1Password and Bitwarden have been externally audited repeatedly (Cure53 for
both; ISE for 1Password) and publish results. Neither audited before v1. This is
the precedent behind the audit-timing decision.

## Stripe
Billing is env-gated: `KEYWARD_STRIPE_WEBHOOK_SECRET` unset → webhook 503.
Handlers are public code; nothing is protected by hiding them.

## Sandbox limitations observed
Direct `curl` to external hosts times out, but `gh` has network access — used
`gh api /licenses/agpl-3.0` to fetch canonical licence text rather than
reconstructing it from memory.
