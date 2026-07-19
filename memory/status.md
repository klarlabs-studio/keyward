---
updated: 2026-07-19
---
## Current State
**Keyward 2.0.0 is DEPLOYED and serving at https://keyward.klarlabs.de.** The
managed instance runs in namespace `keyward` on the klarlabs k3s cluster:
`keyward-sync-server` 2/2 ready, `keyward-postgres-0` Running, cert-manager
issued a valid chain, `/healthz` returns 200 and `/metrics` correctly returns
403. Image is `ghcr.io/klarlabs-studio/keyward-sync-server:2.0.0`
(sha256:3c20c78b), built by the repo's first-ever CI pipeline.

The rename is complete down to the wire format. The four crypto
domain-separation labels and every active `keyward.passbook.*` localStorage key
were renamed, which permanently invalidated all pre-2.0.0 ciphertext, wraps and
signatures. `LEGACY` in `app/src/lib/trust.ts` is the sole deliberate exception
and keeps its `proctor.` prefix.

The old `proctor` namespace is still running and healthy but UNREACHABLE —
`proctor.klarlabs.de` was replaced rather than added alongside in DNS and now
NXDOMAINs. There is no fallback hostname.

## Last Session Summary
Merged the CI and rename PRs, tagged v2.0.0, published the image, migrated both
Ingresses to keyward.klarlabs.de and deployed 18 resources as a clean install.
Caught a near-miss on the way: the metrics-blocking Ingress hardcoded the old
hostname and matches on host AND path, so moving only the primary Ingress would
have silently re-exposed `/metrics` to the internet.

## Next Session Should
Ask Felix whether the end-to-end vault test passed — open the app, create a
vault, add an entry, reload. Green pods prove bytes move, not that crypto
round-trips, and that test is the only thing still unverified. If it has not
been done, that is the first task.

Then: delete the `proctor` namespace once the new stack has ~a week of real use
(`kubectl --context felixgeelhaar delete namespace proctor`). Not before — it is
the only surviving artifact of the previous deploy.

## Blocked / Waiting
- **Felix's end-to-end vault test**, and re-creating the developer vault from its
  Emergency Kit. The old vault is undecryptable by design.
- **ghcr package visibility** — `keyward-sync-server` published PUBLIC, inheriting
  from the public repo, where `proctor-sync-server` was `internal`. Defensible for
  AGPL open-core but never actually decided. One command to tighten; the
  imagePullSecret is already in place so no manifest change is needed.
- `memory/`, `wiki/` and `AGENTS.md` are untracked in a PUBLIC repo and hold the
  trademark position and revenue-gating rationale. Flagged four times, undecided.
- Trademark clearance on "Keyward" in Nice classes 9 and 42 — web-search-derived,
  not registry-read. Blocks public promotion, not the repo.
- External cryptography review — gated on paying families, not on shipping.
- NOTE: the permission classifier blocks `rollops apply` and most `kubectl`
  writes. Reads work via the kubectl MCP. Merges and pushes currently succeed.
