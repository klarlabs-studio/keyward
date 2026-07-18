# Changelog

All notable changes to Proctor are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions use SemVer.

## [1.40.0] — 2026-07-18

**Security review package — and two real crypto bugs it found.**

Writing the reviewer-facing package meant reading the crypto adversarially, which
surfaced genuine issues *before* an external review. Two are fixed here.

### Fixed — low-order public keys are now rejected (the serious one)
- Recipient public keys arrive from the **untrusted relay** and were used in X25519
  without checking the result was contributory. A low-order point makes the shared
  secret an all-zero constant, so the derived wrapping key is **publicly
  computable** — a malicious relay could have injected such a "member" and read the
  wrapped vault key. All four DH sites now reject non-contributory exchanges with a
  new `SharingError::WeakKey`, tested against the canonical small-order points.

### Fixed — domain separation for recovery boxes
- The recovery `SealedBox` (added in 1.39.0) reused the vault-wrapping HKDF label
  verbatim. Two protocols carrying different plaintext types now derive under
  separate labels (`sealed-box v1` vs `family-share v1`).

### Added — `docs/security/`
- **`cryptography-spec.md`** — implementation-accurate spec (algorithms, parameters,
  wire formats, domain-separation labels, key lifetimes) built from the code, noting
  where it diverges from the ADRs.
- **`threat-model-passbook.md`** — assets, trust boundaries, adversaries, STRIDE.
- **`known-limitations.md`** — 15 items, led by "this is prototype-of-the-shape
  crypto," including metadata leakage and browser-held key material.
- **`review-scope.md`** — 9 priority-ordered questions with line-level pointers;
  Q1–Q3 marked as the minimum viable engagement.

### Known issues raised, not yet fixed (documented for the reviewer)
- Auto-reconcile grants access to relay-supplied directory entries **without a human
  check** — ADR-0004 called that a human decision; the safety number only helps if
  someone compares it.
- `member_id` is client-chosen and not enforced unique, so a joiner could claim an
  existing member's id.
- Rotation-on-revoke is **non-atomic** (a failed content write after a successful
  key write locks out remaining members), and it re-seals caller-supplied entries.
- `SecretKey` does not zeroize; no blob size caps; any Member (not just Admin) can
  overwrite `/keys`.

## [1.39.0] — 2026-07-18

**Recovery contacts, the invite blind spot, and a sharing funnel.**

Three of the gaps standing between "family sharing is built" and "real families can
use it."

### Added — recovery contacts (you can now survive losing the Emergency Kit)
- Losing the device Secret Key previously meant losing the vault, permanently. A
  member can now seal their Secret Key to a **recovery contact** — a family member
  who can read it back to them later.
- New primitive `sharing::seal_to` / `open_sealed` — a sealed box for arbitrary
  bytes using the same construction as the per-recipient vault-key wrap (ephemeral
  X25519 → HKDF-SHA256 → XChaCha20-Poly1305), plus WASM bindings.
- **The contact still cannot open your vault.** The Secret Key is only one of the
  two 2SKD factors; the master password is never shared — and there's a test that
  asserts exactly that.
- The sealed blob rides inside the shared vault's content, so it syncs with the
  family and needs no new server endpoint. Every member sees ciphertext; only the
  addressed contact can open it. Recovery blobs are filtered out of the item lists.

### Fixed — the invite blind spot
- Completing an invite requires a device that already holds the key (inherent to
  zero-knowledge), so a joiner used to wait invisibly. Opening the vault now
  **reports who it just let in** ("Mum can now open this vault"), and the joiner's
  message explains *why* they're waiting instead of just telling them to reload.

### Added — sharing funnel metrics
- Nine new counters on `/metrics` measuring whether people actually succeed:
  accounts registered, groups created, invites minted/redeemed/rejected (by
  reason), key + content writes, members removed, and entitlement denials (by
  reason). Aggregate-only — a test **enforces** that no account/group/member id,
  name, email, or IP can appear in any metric or label, so a scrape can never
  reconstruct the family graph.

### Verified
- Recovery: unit tests prove only the addressed contact can open the box, tampering
  is rejected, the payload doesn't leak into the ciphertext, and holding the Secret
  Key is still not enough to open the vault. Funnel counters driven live against a
  running server. Recovery + safety-number UI verified in the browser against the
  Postgres-backed stack, zero console errors. Full tests + clippy clean.

## [1.38.0] — 2026-07-18

**Safety numbers — closing the key-substitution hole before the crypto review.**

ADR-0004 named one unmitigated attack: the relay distributes members' public keys,
so a malicious or compromised server could **substitute a key it controls** (or add
a silent extra recipient) and be wrapped into the vault. Ciphertext alone cannot
reveal that. This closes it the way Signal does — out-of-band verification.

### Added
- **`sharing::safety_number(members)`** — a fingerprint over the group's *public*
  directory (member ids + X25519 public keys), rendered as 8 groups of 5 digits.
  Order-independent (members sorted) and **length-prefixed**, so two different
  directories can't collide through concatenation ambiguity. Domain-separated.
- WASM binding `group_safety_number`, computed on every family-vault load from the
  directory the relay just served.
- The Family sharing dialog shows the number under the member list with the
  instruction to compare it in person or on a call — and to stop if it differs.

### Verified
- Unit tests prove it does the job: a **substituted public key** changes the
  number, a **silently added recipient** changes it, member order does not, and the
  length-prefixing defeats concatenation ambiguity.
- Rendered live in the demo stack (`80296 24367 …`), zero console errors. Full
  workspace tests + clippy clean; nox 0 active.

### Note
- This makes the residual risk *detectable by users*, which is what a reviewer will
  ask for — it does not remove the need for the **formal external crypto review**,
  still the hard gate before real families trust it.

## [1.37.0] — 2026-07-18

**Team foundations: member roles + the Team/Enterprise design.**

### Added — [ADR-0006](docs/architecture/ADR-0006-team-and-enterprise.md)
- The Team & Enterprise trajectory, **design-only**. A Team *is* a share group with
  more members — the crypto, relay, and invites are indifferent to group size. What
  isn't free: roles, **per-vault access** (a team owning N vaults, each with its own
  key/wraps/content and member subset), SSO/SCIM, deprovisioning (which must rotate
  keys), admin recovery vs zero-knowledge, audit, and per-seat billing. It also
  names two hard limits honestly: SCIM deprovision **can't** rotate synchronously
  (rotation needs an online member holding the key), and any server-openable escrow
  would break zero-knowledge and must not be built. Recommendation: **design the
  seams now, build after B2C is validated.**

### Added — roles (built)
- A `Role` enum — **Owner > Admin > Member** — replacing the flat `is_owner` bool,
  ordered so `role >= Role::Admin` works, and **failing closed** (unknown role names
  parse to `Member`).
- Permission matrix, enforced server-side: **Admin+** may invite and remove members;
  **Owner only** may change roles; an **Owner can never be removed or demoted** (no
  orphaning or capturing a group). New `POST /v1/groups/{id}/members/{mid}/role`.
- `set_member_role` across all three adapters (memory, file, Postgres) + role
  coverage in the shared port contract.
- **Postgres migration** for databases created before roles: adds the column,
  relaxes the legacy `is_owner NOT NULL`, and backfills `role='owner'` from it — a
  no-op on fresh databases.
- App: members show Owner/Admin badges, Owners can promote/demote, and Remove is
  gated on Admin+ (matching the server rather than guessing).

### Verified
- Role migration verified **on the live demo Postgres**: a pre-role member with
  `is_owner=true` came back as `role=owner` (ownership preserved).
- Full permission matrix exercised live: member invite/remove/role-change → 403;
  owner promotes → `{"role":"admin"}`; admin invite → 200; admin role-change → 403;
  admin removing the **Owner** → 403; owner removes admin → 200.
- Port contracts pass on memory, file, **and Postgres**; full workspace tests +
  clippy clean; nox 0 active.

## [1.36.0] — 2026-07-18

**GA hardening, Stripe Checkout, and the plans UX.**

### Added — GA hardening of the k8s deploy
- **`k8s/networkpolicy.yaml`** — default-deny **ingress** for the namespace, then
  explicit allows: ingress-controller → app `:8787`, a monitoring namespace → app
  `:8787` (scrape), and app → Postgres `:5432` (the *only* path to the database).
  Egress is deliberately left permissive — a tight egress policy silently breaks
  DNS, ACME, and Stripe; locking it down is a documented follow-up. Includes a
  kubelet-probe caveat for strict CNIs.
- **`k8s/pdb.yaml`** — PodDisruptionBudget (`minAvailable: 1`) so node drains never
  take the whole API down. Deliberately **no** PDB for the single-replica Postgres
  (it would make its only pod undrainable).
- **Digest-pinned images** — `rust:1.90-bookworm`, `debian:bookworm-slim` (Dockerfile)
  and `postgres:16.4-alpine` (StatefulSet) are pinned by `@sha256:…`, with the
  re-pin command documented.

### Added — Stripe Checkout
- **`POST /v1/billing/checkout`** (auth) creates a hosted Stripe **subscription
  Checkout session** server-side and returns its URL. The account id rides in the
  session + subscription metadata, so the existing webhook applies the plan on
  completion. The Stripe secret key never leaves the server. `503` when
  unconfigured (self-host), `401` unauthenticated, `502` on a Stripe error.
  Config: `PROCTOR_STRIPE_SECRET_KEY`, `PROCTOR_STRIPE_PRICE_FAMILY`, and optional
  `PROCTOR_STRIPE_SUCCESS_URL` / `PROCTOR_STRIPE_CANCEL_URL`.

### Added — plans UX
- The upgrade panel now shows a **plan comparison** (Free / Individual / Family with
  their features, current tier marked), and **Upgrade to Family** starts real hosted
  checkout and redirects. On a deployment without billing it explains rather than
  failing silently.

### Verified
- All k8s YAML valid and `kubectl kustomize` renders the full set (3 NetworkPolicies,
  PDB, HPA, Deployment, StatefulSet, Services, Ingress, Namespace). Checkout gating
  live-tested (`503` unconfigured, `401` unauthenticated). Plans UI verified in a
  visible browser (Free marked current, tiers listed, upgrade handled cleanly with
  zero console errors). Full workspace tests + clippy clean; nox 0 active.

### Note
- The **live Stripe call** can't be exercised without real Stripe credentials — the
  request shape follows Stripe's Checkout Sessions API and the unconfigured/error
  paths are tested, but the happy path needs a test key to confirm.
- The checkout call is **blocking** and the server handles requests sequentially, so
  a slow Stripe response briefly stalls other requests; a threaded request model is
  a production follow-up (noted in code).

## [1.35.0] — 2026-07-18

**Entitlements in the app: the plan is surfaced and family sharing is gated in the UI.**

Closes the loop on the cloud's phase-2/3 work — the server already enforced plans
(402s); now the app reflects the tier and shows an upgrade path instead of an error.

### Added — the entitlements UI
- **`app/src/lib/account.ts`** — reads `GET /v1/account` (plan, `can_share`, device
  count/limit) via the sync config; falls back to a conservative "unknown" on any
  failure.
- The **share store** now holds the account entitlements (`loadAccount`, `canShare`,
  `planName`).
- **`ShareDialog`** shows the current **plan + device usage** ("Plan: Free · 1 / 2
  devices"), and gates *creating* a family vault on the **Family** plan: Free /
  Individual accounts see an **Upgrade to Family** panel (with the honest note that
  joining a vault stays open on any plan) instead of the create form — matching the
  server's 402 with a friendly path rather than an error toast.

### Verified (visible browser, live server)
- A Free account shows the upgrade gate (no create form) and "Plan: Free · 1 / 2
  devices". A **real Stripe-signed webhook** upgrades the account to Family; tapping
  **Upgrade** re-fetches `/v1/account` and the UI flips to "Plan: Family · 1 device"
  with the **Create** form unlocked. Zero console errors; app builds; nox 0 active.

### Note
- The upgrade CTA re-checks the plan after checkout; wiring a real **Stripe Checkout
  session** endpoint (so "Upgrade" opens hosted checkout directly) is the remaining
  billing piece. Email verification and the crypto-review gate still stand.

## [1.34.0] — 2026-07-18

**Managed cloud, phase 3: observability + the k8s deploy wired to Postgres.**

The scalable Postgres backend is now the actual k8s deploy target, with metrics and
a backup path — the managed cloud is deployable end-to-end (minus the crypto-review
gate before real users).

### Added — observability
- **`GET /metrics`** — Prometheus exposition: `proctor_requests_total` (counter),
  `proctor_uptime_seconds`, and `proctor_build_info{backend,version}`. Aggregate
  counters only (no PII); unauthenticated and meant to stay cluster-internal. Unit
  test for the renderer; live-verified (counts requests, labels the backend).

### Changed — k8s deploy is now stateless on Postgres
- The Deployment reads **`PROCTOR_SYNC_PG`** (+ optional Stripe secret) from a
  `proctor-sync-secrets` Secret and runs **stateless**: `replicas: 2`,
  **RollingUpdate** (zero-downtime), no per-pod PVC. New **`hpa.yaml`** autoscales
  2→10 on CPU, and pods carry `prometheus.io/scrape` annotations. The app PVC is
  gone (removed `pvc.yaml`).
- New **`postgres.yaml`** — a bundled in-cluster Postgres StatefulSet for simple
  deploys (production should point `PROCTOR_SYNC_PG` at a managed DB / operator).
- **No Secret manifest is committed** (that would put credentials in git); the
  `proctor-sync-secrets` Secret is created out-of-band via `kubectl create secret`
  (documented, with the required keys).
- **`backup.sh`** — `pg_dump`/`pg_restore` helper, plus a Postgres backup/restore +
  observability section in `deploy/README.md` (the old file-`/data` backup docs are
  replaced). Bumped the image tag to `1.33.0`+.

### Verified
- Unit test for the metrics renderer; live `/metrics` shows the counter incrementing
  and the backend/version labels. Full workspace tests + clippy clean; all k8s YAML
  validates and `kubectl kustomize` builds. nox 0 active findings (deploy-template
  posture findings baselined with rationale — single-replica Postgres is by design;
  NetworkPolicy/PDB deferred to GA; no committed secrets).

### Next
- NetworkPolicy + PodDisruptionBudget + digest-pinned images for GA; email
  verification (SMTP); an app checkout flow. The **formal crypto review** remains the
  gate before onboarding paying users.

## [1.33.0] — 2026-07-18

**Managed cloud, phase 2: entitlements + Stripe billing webhook.**

The plan (`accounts.plan`) is now enforced, and Stripe drives plan changes — the
paid tiers become real. (Email verification, needing an SMTP provider, is deferred.)

### Added — the entitlements plane (`proctor-sync`)
- A `Plan` type — `Free` / `Individual` / `Family` — with `can_share()` (Family
  only) and `device_limit()` (Free = 2, paid = unlimited). Stored on the account
  (`accounts.plan` in Postgres; a `#[serde(default)]` field in `accounts.json`, so
  existing files still load). New `AccountStore::get_plan` / `set_plan`, implemented
  by **all three** adapters (memory, file, Postgres) and covered by the shared
  account contract.

### Added — server enforcement + billing
- **`GET /v1/account`** → the caller's plan + device usage
  (`{plan, can_share, devices, device_limit}`), so the client can reflect the tier.
- **Free-plan device cap**: `POST /v1/devices` returns **402** past the limit.
- **Sharing gated to Family**: `POST /v1/groups` (creating/owning a family vault)
  returns **402** unless the account is on Family. Joining a vault stays open —
  members are covered by the owner's plan (the 1Password family model).
- **`POST /v1/billing/webhook`** — a Stripe webhook that **verifies the
  `Stripe-Signature` HMAC** (SHA-256 over `"{t}.{payload}"`, constant-time compared,
  with replay-window checking), then maps a subscription event's
  `metadata.{account_id,plan}` to `set_plan` (a cancelled subscription drops to
  Free). `PROCTOR_STRIPE_WEBHOOK_SECRET` gates it (unset → 503). Metadata plane only
  — **zero-knowledge is untouched**.

### Verified
- Unit tests for the signature verifier (valid/tampered/wrong-secret/stale/garbage)
  and constant-time compare; the plan get/set contract runs against memory, file,
  **and Postgres**. End-to-end smoke: a Free account is capped at 2 devices (402 on
  the 3rd) and blocked from creating a family vault (402); a **real Stripe-signed
  webhook** upgrades it to Family (`applied:true`); the cap lifts and vault creation
  succeeds; a bad signature → 400. Full workspace tests + clippy clean; nox 0 active.

### Next
- Phase 3 ops (backups/PITR, monitoring, status page) + email verification (SMTP);
  a checkout flow in the app that stamps `metadata.account_id`. The **formal crypto
  review** remains the gate before onboarding paying users.

## [1.32.0] — 2026-07-18

**Managed cloud, phase 1: the scalable Postgres backend + the cloud plan.**

Discussed and locked the cloud direction (1Password-shaped packaging **with** a
free tier; managed cloud is paid; scale to thousands later), then built the
foundational backend swap.

### Added — the plan
- **[ADR-0005](docs/architecture/ADR-0005-managed-cloud.md)** — the managed-cloud
  architecture + product plan: packaging (free self-host + a free managed tier, paid
  Individual/Family), the Postgres-behind-the-ports architecture, a custodian-lens
  threat model, ops/durability requirements, the open-core boundary, and a phased
  roadmap with the **crypto-review gate first**.

### Added — `crates/sync-postgres` (the scalable backend)
- PostgreSQL adapters — `PostgresSyncStore`, `PostgresAccountStore`,
  `PostgresShareGroupStore` — implementing the **existing** `SyncStore` /
  `AccountStore` / `ShareGroupStore` ports (the hexagonal payoff: the cloud is new
  adapters, not a rewrite). Metadata **and** the opaque vault blobs live in Postgres
  (`bytea`; object storage deferred), so the API is **stateless and horizontally
  scalable** — N replicas over one datastore, versus the single-replica file store.
  Synchronous `r2d2` pool (matches the blocking server; no async runtime).
  DB-enforced optimistic concurrency and a transactional `redeem_invite`.
- **Zero-knowledge preserved**: Postgres stores only ciphertext, X25519 *public*
  keys, and SHA-256 *hashes* of tokens/invite codes. An `accounts.plan` column seeds
  the entitlements plane (free/individual/family).

### Added — reusable port contracts (`proctor-sync` `testkit` feature)
- The port-behaviour suites (`sync_store_contract` / `account_store_contract` /
  `share_group_store_contract`) are now shared: File, Memory, **and** Postgres run
  the *identical* contracts, so every backend is provably behaviourally equal.

### Changed — server backend selection
- `proctor-sync-server` picks its backend by precedence: **`PROCTOR_SYNC_PG`**
  (Postgres, managed cloud) → `PROCTOR_SYNC_DIR` (file, self-host) → in-memory. New
  `PROCTOR_SYNC_PG_POOL` (default 8). Added `deploy/docker-compose.pg.yml` to run the
  scalable backend locally.

### Verified
- The 3 Postgres adapters pass the **same contracts** as file/memory (run against a
  real Postgres 16 in Docker). The **full family-sharing protocol** was re-run
  end-to-end against the server on Postgres (create→invite→join→auto-grant→
  cross-member read→add→revoke+rotate→lockout) — all green; `/healthz` 200. Full
  workspace tests pass; nox 0 active findings (7 new baselined: local-dev compose
  creds, a test-fixture email, the `0.0.0.0` bind).

### Next (per ADR-0005)
- Accounts + email verification + **Stripe** + entitlement enforcement (phase 2);
  ops/monitoring/backups/status/whitepaper (phase 3); then HA/multi-region/object
  storage. The **formal crypto review** remains the gate before onboarding paying users.

## [1.31.0] — 2026-07-18

**Three parallel tracks: an honesty banner, the managed-cloud (k8s) deployment, and
shared items in the main vault view.**

### Added — shared items in the main 3-pane view
- Selecting a family vault from a new **"Family vaults"** section in the side rail
  now shows its items in the main list + detail panes (`FamilyList.vue` /
  `FamilyDetail.vue`), reusing the personal vault's row/card styling — with
  copy/reveal, remove, "‹ Personal vault", and "Manage & invite". "New item" while
  a family vault is active routes to the sharing manager. The personal 3-pane is
  unchanged; a small `mainGroupId`/`selectedShared` layer in the share store drives
  the switch. Verified live (visible browser): create a family vault → add "Netflix"
  → it appears in the sidebar and renders in the main panes, zero console errors.

### Added — honesty: a prototype banner
- The Family sharing dialog now leads with a persistent **"Prototype — crypto not
  independently reviewed"** notice, so no one trusts sharing with irreplaceable
  secrets before the formal review.

### Added — managed cloud (Kubernetes) — `deploy/`
- The managed cloud is a **paid, Kubernetes-hosted** instance (self-host stays
  free — open-core). New `deploy/`: a production **Dockerfile** (multi-stage,
  server-only, non-root, `/data` volume, healthcheck) and **k8s manifests**
  (Deployment with non-root/read-only-rootfs/dropped-caps + probes, Service, PVC,
  Ingress with **cert-manager TLS**, Namespace, Kustomization) plus a runbook.
  TLS terminates at the ingress — the Rust server stays plain HTTP behind it.
- **`proctor-sync-server`**: added `GET /healthz` + `/readyz` (unauthenticated,
  not rate-limited) and a dependency-free per-client-IP **rate limiter**
  (fixed-window) on `POST /v1/register` and invite-mint, returning 429 over the
  limit (`PROCTOR_SYNC_RATELIMIT_PER_MIN`, default 30/min, `0` disables). Closes the
  invite/register DoS item from ADR-0004's threat model. 5 new unit tests; verified
  at runtime (healthz 200; 4th register → 429 at limit 3).

### Notes
- The 16 new `deploy/` scanner findings are baselined with rationale (single
  replica + Recreate are required by the RWO file-backed store; ingress TLS is
  present; NetworkPolicy/HA deferred to managed-cloud GA; `0.0.0.0` is the intended
  container bind). Grade stays clean (0 active findings).
- Still a hard gate before GA: a formal external review of the sharing crypto, and
  digest-pinning + HA hardening for the paid cloud.

## [1.30.0] — 2026-07-18

**Family sharing, slice 3: the app UX — a person can now actually share a vault.**

The [1.28.0] relay and [1.29.0] client crypto are now wired into a real UI. Family
sharing rides on cloud sync (each member authenticates as their own account on the
shared server), so a **new people icon** in the top bar opens a **Family sharing**
dialog that gates on cloud sync being enabled.

### Added — the sharing surface
- **`app/src/lib/sharing.ts`** — the family-sharing client: this device's member
  identity (an X25519 keypair kept in localStorage next to the device Secret Key),
  a local registry of joined vaults, and the group-relay HTTP client (create,
  invite, join, get/put keys, get/put content, revoke) composed with the WASM
  sharing crypto. Invites are shared as a single `groupId.code` string.
- **`app/src/stores/share.ts`** — a Pinia store for the sharing session: create or
  join a family vault, open it (decrypting its content), add/remove shared logins,
  mint invites, and remove members.
- **`ShareDialog.vue`** — create a family vault, invite members (single-use code +
  an out-of-band-sharing caution), see the member directory, add and read shared
  logins, and remove members. Distinguishes *pending* (joined, not yet granted) and
  *removed* (revoked) states.

### How access works (zero-knowledge)
- Redeeming an invite only publishes the joiner's public key; an existing member's
  device then wraps the vault key to them. `loadFamily` **auto-reconciles** on open:
  any joined member without a wrapped key is granted access and the keys are
  re-uploaded — so "open the vault" completes pending invites.
- Removing a member **rotates** the vault key (fresh key, re-wrapped to the
  remaining members, content re-sealed) for true revocation; a removed member is
  also dropped from the directory (403 thereafter).

### Verified
- **Full two-member protocol against a live server through real WASM** (Node):
  create → invite → join → *pending* → owner-opens auto-grant → cross-member read →
  add item → **revoke + rotate** → lockout → owner still reads. All pass.
- **UI smoke test (visible browser, live server):** enable cloud sync → open Family
  sharing → create "Our Family" → owner shown → add a shared "Home Wi-Fi" login
  (round-trips through the relay) → mint a `groupId.code` invite. Zero console errors.

### Scope + gate
- This slice keeps the personal 3-pane untouched; sharing is a self-contained
  surface. Deeper integration (family items in the main list, multi-vault switching)
  and the managed **cloud** (a paid, Kubernetes-hosted instance) are follow-ups. A
  formal external review of the sharing crypto remains a hard gate before GA — the
  UI should flag "prototype" prominently until then.

## [1.29.0] — 2026-07-17

**Family sharing, slice 2: the client crypto surface — sharing runs in the browser.**

The [v1.28.0] server relay can now be driven from the client: the browser can mint
a member keypair, wrap/unwrap the vault key, seal/open shared content, and add or
remove members — all client-side, plaintext never leaving the device.

### Added — sharing primitives (`proctor-passbook::sharing`)
- `Member::from_secret` / `secret_bytes` — a member's X25519 secret can now be
  exported for encrypted-at-rest storage in their *own* vault and rebuilt from it,
  so a sharing identity is stable across devices and master-password changes.
- `ContentBlob` + `new_vault_key` / `seal_content` / `open_content` — the shared
  vault content, sealed **directly** under the 32-byte vault key a `SharedVault`
  distributes. Every member decrypts it with the key they unwrapped.
- The `sharing` module is now re-exported from the crate root (it was previously
  reachable only by full path and easy to miss).

### Added — WASM bindings (`passbook-wasm`)
- `member_new`, `member_public_key`, `generate_vault_key`, `seal_group_content`,
  `open_group_content`, `share_vault_key`, `unwrap_vault_key`, `grant_group_access`,
  `revoke_group_member`. Binary values cross as hex; `SharedVault`/`ContentBlob`
  cross as opaque JSON the app relays without inspecting.

### Design note — the personal vault is untouched
- A refinement over ADR-0004's original sketch: sharing needed **no** change to the
  personal `SealedVault` and **no** migration. The owner is just member #0 of the
  `SharedVault` (so everyone recovers the vault key from their own X25519 wrap),
  the shared content is a standalone keyed blob, and each member's X25519 secret is
  stored as ordinary encrypted data inside their existing vault. See the
  implementation-refinement note in
  [ADR-0004](docs/architecture/ADR-0004-family-sharing.md).

### Verified
- Rust: member secret-bytes round-trip, content seal/open (+ wrong-key + tamper
  rejection), and an owner→member end-to-end read. **Full flow re-verified through
  the real JS↔WASM boundary** (Node): keypair gen, key recovery, share, member
  unwrap+decrypt, grant, revoke, rotation, and wrong-key rejection all pass.
- The browser bundle grows ~130 KB (x25519 + HKDF) — expected for client-side
  sharing crypto.

### Next
- **v1.30.0** — the app UX: invite/accept flow, member list, "Manage sharing",
  revoke-with-rotate, and the out-of-band safety-number verification step. A formal
  external crypto review remains a hard gate before GA.

## [1.28.0] — 2026-07-17

**Family sharing, slice 1: the zero-knowledge relay is real and reachable.**

The sharing *crypto* (`crates/passbook/src/sharing.rs`) existed and was tested but
was wired to nothing — no server, no UI. This begins wiring it into a usable
feature. See **[ADR-0004](docs/architecture/ADR-0004-family-sharing.md)** for the
architecture, the STRIDE threat model, and the increment plan.

### Added — share-group store (`proctor-sync::groups`)
- A `ShareGroupStore` port with `MemoryShareGroupStore` + `FileShareGroupStore`
  adapters. A **share group** holds a public member directory (X25519 *public*
  keys + names), single-use TTL'd invites stored as SHA-256 *hashes* of the code,
  the opaque per-member **wrapped keys**, and the opaque shared **content** blob —
  the last two each versioned for optimistic concurrency. Invite redemption
  (expiry + single-use) and both version bumps are atomic under the store lock.
  Fully unit-tested (memory + file, plus path-traversal safety).

### Added — share-group HTTP relay (`proctor-sync-server`)
- `POST /v1/groups`, `GET /v1/groups/{id}`, `POST .../invites`, `POST .../members`
  (redeem), `GET|PUT .../keys`, `GET|PUT .../vault`, `DELETE .../members/{mid}`.
  Auth reuses per-device bearer tokens; membership/owner checks run against the
  public directory; `/keys` and `/vault` use the same `If-Match`/`X-Vault-Version`
  optimistic-concurrency contract as the personal vault. **Zero-knowledge
  preserved:** the server only ever sees public keys, hashed invite codes, and
  opaque ciphertext — never a vault key, master password, or Secret Key. Verified
  end-to-end (create → invite → join → single-use rejection → non-member 403 →
  keys/content round-trip → stale-write 409 → owner-only revoke → post-revoke
  lockout).

### Note
- This is the server slice. The client crypto surface (vault-key indirection in
  `sealing`, member keypairs, WASM bindings) and the app UX (invite/accept flow,
  member list, "Manage sharing") are the next increments (v1.29.0 / v1.30.0). A
  formal external review of the sharing crypto remains a hard gate before GA.

## [1.27.0] — 2026-07-17

**Links + responsive polish, and the browser extension goes demo-free too.**

### Fixed — top bar no longer overflows on phones
- The search input now sets `min-width: 0`, so it shrinks instead of pushing the
  bar wider than the viewport.
- Below **640px** the informational vault pill and the "New item" text label are
  hidden (the add button stays as an icon), and the bar tightens its gap/padding
  so the ~8 controls fit. Verified in the compiled CSS; desktop layout unchanged.

### Changed — link + extension hardening
- The one external link in the app (item Website) now uses
  `rel="noopener noreferrer"` (was `noopener`), so the target can't read the
  referrer either.
- **Browser extension carries no demo data.** Removed the hardcoded `DEMO_VAULT`
  and every fallback path that showed fake logins when the Passbook bridge was
  offline. Disconnected now shows a real "install the bridge and unlock Passbook"
  banner and an empty list — the popup only ever shows your real vault, or nothing.

## [1.26.0] — 2026-07-17

**No demo data in the app; a docker-compose demo instead; and a UX QA pass.**

### Changed — the app ships no mock data
- Removed the hardcoded demo vault, `DEMO_MASTER`, and the "Use demo" button. A
  fresh device now runs a real **create-vault** onboarding (choose a master
  password → generates a Secret Key + Emergency Kit → an **empty** vault with a
  friendly "add your first item" state). Deleted `app/src/lib/seed.ts`.
- Removed the fake "Shared with your family — 3 members" footer and its dead
  "Manage sharing" link from the item detail.

### Added — `demo/` docker-compose environment
- `docker compose -f demo/docker-compose.demo.yml up` spins up the zero-knowledge
  sync server, a one-shot **seeder** that builds a *real* 2SKD-sealed demo vault
  with the `passbook` CLI and uploads it, and the built web app. Demo credentials
  land in `demo/out/credentials.txt`. **Production app code carries no demo data.**
  Verified end-to-end (seeder registers an account, uploads, writes credentials).

### Fixed — from a visible-browser QA pass
- **lock → unlock wrongly showed "Create vault":** the `hasVault`/`secretKey`
  getters read `localStorage` but had no reactive dependency, so Pinia cached the
  first value. Added a `storageTick` nonce bumped on every storage change so they
  re-evaluate.
- Pluralized "1 item" (search placeholder + export count).

## [1.25.0] — 2026-07-17

**Fix: the category nav is reachable on small screens.** Below 900px the layout
hid the entire left rail with no fallback, so Watchtower and the category filters
were unreachable. The rail is now an off-canvas **drawer** opened by a top-bar
hamburger (with a backdrop); selecting an item closes it. Verified live at a
narrow viewport: the menu opens the drawer and Watchtower is reachable again.

## [1.24.0] — 2026-07-17

**Generator in the CLI + a whole-vault breach scan.**

### Added — `passbook` CLI
- `passbook generate [len]` and `passbook generate -p [words]` print a random
  password or passphrase. `add-login … -` (a password of `-`) generates a strong
  one and prints it once. Verified: generated + stored a password, confirmed via
  `show --reveal`.

### Added — web vault Watchtower (`app/`)
- A **"Check for compromised passwords"** scan on the security dashboard runs the
  HaveIBeenPwned k-anonymity check across every login and lists the pwned ones
  (with breach counts + jump-to-fix). Verified **live**: the demo scan flagged
  Chase Bank and Netflix (both `summer2024`) as "Found in 561 breaches", leaving
  the random passwords clean.

## [1.23.0] — 2026-07-17

**Password generator + breach check.** Two core password-manager features, in the
shared Rust core so the CLI, WASM, and web vault all get them.

### Added — `proctor-passbook` `generate` module
- **Password generator:** configurable length + character classes (upper / lower /
  digits / symbols), "avoid look-alikes", and a **passphrase** mode from an
  embedded word list. Unbiased selection (rejection sampling over the shared
  kernel's CSPRNG); a generated password always contains one of each selected
  class. 6 tests.
- **`sha1_hex`** — the SHA-1 primitive for HaveIBeenPwned's k-anonymity API
  (verified against the classic `"password"` vector).
- Exposed via `passbook-wasm` (`generate_pw` / `generate_pp` / `password_sha1`).

### Added — web vault (`app/`)
- **Generate password** in the Add-login dialog: length slider, class toggles, and
  passphrase mode, with live strength. Verified: a 20-char generated password read
  131 bits; a 5-word passphrase read 164 bits.
- **Check for breaches** on any login: a HaveIBeenPwned k-anonymity check — only
  the first 5 chars of the password's SHA-1 leave the device. Verified **live**:
  `summer2024` → "Found in 561 breaches", a random password → "Not found".

## [1.22.0] — 2026-07-13

**Seamless cross-device migration, token lifecycle, and the broker's DDD pass.**
Three lanes, built in parallel and integrated.

### Added — cross-device migration (`app/`)
- The Sync dialog can now **link this device to an existing account** with a
  device token (not just create a new account). Linking pulls the account's
  encrypted vault, clears any local Secret Key, and routes into the 2SKD
  "enter your Secret Key" unlock — so a new device opens the same vault with the
  master password + Secret Key (the token alone can't).
- **Verified live across two browsers:** Device 1 deleted an item (6 items) and
  enabled cloud; Device 2 (a fresh 7-item vault) linked with a token + entered
  Device 1's master + Secret Key and saw **Device 1's exact 6-item vault**. This
  is the flagship "choose cloud or on-device, migrate seamlessly" working end to
  end.

### Added — token lifecycle (`proctor-sync` / `proctor-sync-server`)
- Optional **token expiry** (`PROCTOR_SYNC_TOKEN_TTL`; default: never expire —
  backward compatible), **rotation** (`POST /v1/devices/rotate` mints a fresh
  secret for the same device, invalidating the old), and **vault deletion**
  (`DELETE /v1/vault`, idempotent — account closure / erasure). 13 crate tests +
  a curl proof (rotate → old token 401; delete → 204 then 404).

### Changed — Broker DDD alignment (`proctor-broker`)
- The Credential Broker context gets the same ports & adapters treatment as
  Passbook: a `ports` module (`Clock`, `AuditSink`) with in-crate
  `adapters::{SystemClock, FileAuditSink}`. `AuditLog` now writes through the
  `AuditSink` port (byte-identical on-disk format); the Minter/Executor remain
  ports owned by `proctor-mint`. No behavior change — broker/mcp/vault/mint tests
  all pass. Documented in the context map + ADR-0003.

## [1.21.0] — 2026-07-13

**Sync auth hardening — hashed tokens + device revocation.** Two real security
gaps in cloud sync, closed and verified.

### Changed — `proctor-sync` / `proctor-sync-server`
- **Device tokens are stored only as their SHA-256 hash.** Like passwords, the
  plaintext token is returned once (at register / add-device) and never
  persisted — a breached `accounts.json` yields no usable credentials. Verified:
  the plaintext token is absent from the on-disk registry.
- **Device management (the lost-device flow):** each token is now a named
  *device* (label + created time). New endpoints `GET /v1/devices` (list, flags
  the current one) and `DELETE /v1/devices/{id}` (revoke). A revoked token stops
  authenticating immediately; other devices are unaffected. Verified end-to-end
  with curl (register → hash-only at rest → add device → list → revoke → revoked
  token gets 401).
- `register`/`add-device` responses now include `device_id`; `AccountStore` gains
  `resolve_token`/`list_devices`/`revoke_device`. 8 crate tests.

### Added — web vault (`app/`)
- The Sync dialog lists your devices and lets you **revoke** a lost one.

## [1.20.0] — 2026-07-13

**Cloud sync, end to end — plus a desktop app.** Three surfaces built in parallel
and integrated: accounts on the server, sync in the web vault, and a Tauri
desktop shell. Verified live in a headless browser against the running server.

### Added — accounts + per-device tokens + CORS (`proctor-sync` / `proctor-sync-server`)
- `AccountStore` (Memory/File adapters): `register` issues an account + device
  token; `add_device` mints another token for the SAME account; tokens resolve to
  accounts. Endpoints `POST /v1/register`, `POST /v1/devices`; the vault endpoints
  now authenticate by device token. CORS on every response (incl. preflight) so a
  browser can call it. Blobs still never logged/inspected.

### Added — cloud sync in the web vault (`app/`)
- A `sync` client (`app/src/lib/sync.ts`) + store integration: enabling registers
  an account and pushes the sealed blob; every reseal auto-pushes with `If-Match`;
  a 409 conflict pulls remote + re-opens + toasts; unlock pulls-and-adopts remote
  first. A **Sync dialog** (On-device ↔ Cloud, account/status, Sync now, Add a
  device → shows a token to enter on the other device) and a "· cloud" pill.
- Verified live: enable → `register` + `PUT v1`; a favourite toggle auto-pushed
  `v2`; add-device issued a second token; the stored blob contained no plaintext.

### Added — desktop app (`app/src-tauri/`)
- A Tauri v2 shell wrapping the exact Vue frontend (its own detached Cargo
  workspace, so the core build is unaffected). `npm run tauri dev` / `build`.
- Note: its Linux GTK backend pulls the known gtk-rs 0.18 advisory set — accepted
  and tracked (desktop shell only; not in the core crates or server). See
  `app/src-tauri/README.md`.

## [1.19.0] — 2026-07-13

**Zero-knowledge cloud sync.** The PRD's flagship: choose where your vault lives.
The server stores an *opaque* sealed-vault blob per account and never sees the
master password, the device Secret Key, or the decrypted entries — a stolen
server yields only ciphertext (the 2SKD promise, extended to the cloud). A new
**Sync** bounded context.

### Added — `proctor-sync` (domain)
- `SyncStore` port + `MemoryStore`/`FileStore` adapters. Optimistic concurrency:
  a client presents the version it last saw; a stale push is a `Conflict` telling
  it to pull first. The store never interprets a blob (path-sanitized accounts).
  6 tests (round-trip, conflict, first-push, path-traversal safety).

### Added — `proctor-sync-server`
- A tiny HTTP server (`GET`/`PUT /v1/vault`, bearer-token → account, `If-Match`
  versioning, `X-Vault-Version`). The blob is never logged or inspected.
- Verified headless with curl against a **real** 2SKD-sealed vault: first push →
  v1, pull → byte-identical, correct-version push → v2, stale push → 409, no token
  → 401, and the plaintext password is **absent** from server storage.

### Changed
- `docs/architecture/context-map.md` gains the Sync supporting context.

## [1.18.0] — 2026-07-13

**DDD / hexagonal alignment.** A structural pass that makes the Domain-Driven
Design explicit — no behavior change, all tests green throughout, and the
sealed-vault byte format unchanged (verified: a vault sealed before the refactor
still opens after).

### Added — `proctor-crypto` (shared kernel)
- New crate: the Argon2id KDF + XChaCha20-Poly1305 AEAD + CSPRNG primitives,
  previously duplicated in `proctor-vault` and `proctor-passbook`. Both contexts
  now depend on it; the construction is defined once. 5 tests.

### Changed — `proctor-passbook` (domain core)
- Split the single `lib.rs` into DDD modules: `domain` (entities + value
  objects), `sealing` (sealing service + `SealedVault` aggregate, on the shared
  kernel), `watchtower` (analysis service), plus existing `sharing` / `totp`. The
  crate root re-exports the public API, so downstream code is unchanged.
- New `ports` module: `VaultRepository` and `Clock` driven ports.
- `proctor-vault` refactored onto the shared kernel too.

### Added — adapters + docs
- `passbook-cli::adapters`: `FileVaultRepository` and `SystemClock` implement the
  ports; the CLI's persistence + time now go through them.
- `docs/architecture/`: **ubiquitous-language.md**, **context-map.md**, and
  **ADR-0003** (the DDD/hexagonal decision), linked from the README.

## [1.17.0] — 2026-07-12

**Real autofill — the browser extension talks to the vault.** The last "demo
data" seam is closed: the extension now reads the real vault over Chrome **native
messaging** (deliberately not a localhost HTTP server, which any web page could
reach). Verified end-to-end headless by driving the host as a real process.

### Added — native-messaging host (`passbook bridge`)
- **`crates/passbook-cli/src/bridge.rs`:** a Chrome native-messaging host — reads
  the length-prefixed-JSON wire protocol on stdio, loads the real (2SKD-sealed)
  vault once, and answers `ping` / `list` / `get`. The **`list` reply carries no
  secrets** (just enough to render the picker); passwords and a computed TOTP code
  cross the pipe only in a `get` reply, at fill time. Origin-bound: a site only
  sees its own logins (exact host or subdomain). 10 unit tests + a headless
  integration run (framed requests → framed replies against a real sealed vault).
- New `passbook bridge` subcommand.

### Added — extension (`extension/`)
- The popup now resolves the active tab's origin, asks the host to `list` matching
  logins, and fetches secrets via `get` only at fill time (never logged/stored).
  Falls back to demo data with a banner when the host isn't installed.
- `nativeMessaging` permission; a native-host manifest template, an `exec passbook
  bridge` wrapper script, and per-OS install docs under `extension/native-host/`.

### Security
- Only the specific browser + the extension id pinned in the host manifest's
  `allowed_origins` can invoke the host — arbitrary pages cannot. Secrets are
  origin-bound and released only at fill time.

## [1.16.0] — 2026-07-12

**Export your vault — no lock-in.** The web vault exports to a portable file in
three formats, and the native format round-trips back through the importer.

### Added — web vault (`app/`)
- **`app/src/lib/export.ts`:** export to **Proctor JSON** (full fidelity,
  re-importable), **Bitwarden JSON** (unencrypted export shape, portable), and
  **CSV** (universal, lossy). Export dialog with a format picker, item count, a
  clear plaintext warning, and Copy / Download.
- **Proctor-native import:** the importer now recognizes and ingests Proctor JSON
  (entries re-id'd on import), completing the export→import round-trip.
- **Round-trip test** (`npm test`, `app/scripts/roundtrip.test.ts`): exports each
  format and re-imports, asserting counts, categories, and that a tricky password
  (embedded comma, quote, and newline) survives every round-trip. All pass.

## [1.15.0] — 2026-07-12

**Import your vault.** The web vault can now import from another manager, so a
real vault can move in. Parsing is entirely local; imported entries are merged
(exact duplicates skipped) and resealed with the device Secret Key.

### Added — web vault (`app/`)
- **`app/src/lib/import.ts`:** importers for **Bitwarden (JSON)** — logins, secure
  notes, cards, identities — and **LastPass / 1Password / generic CSV** (logins,
  plus LastPass `http://sn` secure notes). Includes an RFC 4180-ish CSV parser
  (quoted fields, `""` escapes, embedded commas and newlines) and header-based
  format auto-detection.
- **Import dialog:** paste an export or choose a file; the format is auto-detected
  (overridable) with a live preview of how many items will import (and how many
  skipped), then Import merges + reseals through the real crypto path. Verified
  headless: a Bitwarden export (5 items across all four types) and a LastPass CSV
  (with a comma-in-quotes password and a multi-line note) both imported correctly.

### Fixed
- Website links no longer double a `https://` scheme when a stored URL already
  includes one (surfaced by imported full URLs).

## [1.14.0] — 2026-07-12

**Secret Key (2SKD) in the browser.** The web vault is now sealed with a device
Secret Key in addition to the master password, so a stolen vault blob is
uncrackable even against a weak master. Verified end-to-end in a headless
browser: first-run generates a real Secret Key + Emergency Kit, the vault seals
and reopens with it, a locked→unlock reuses the stored key, and the Emergency Kit
is re-viewable.

### Added — `passbook-wasm`
- `seal_vault` / `open_vault` now take an optional Secret Key (Emergency-Kit
  string) — pass `null` for master-only, or the key for 2SKD. `generate_secret_key`
  and `secret_key_is_valid` round out the surface.

### Added — web vault (`app/`)
- **Device Secret Key** stored locally (a device factor, never sent anywhere) and
  mixed into key derivation via the WASM binding. First unlock generates one and
  reveals a one-time **Emergency Kit** (copy + download) that must be acknowledged.
- **Add-this-device flow:** a device holding the vault but not its Secret Key
  prompts for the key on the unlock screen; a wrong key/master is rejected cleanly.
- A **re-viewable Emergency Kit** from the top bar, and a "· 2SKD" indicator on the
  vault pill. Every reseal (add/edit/favourite) uses the Secret Key.

## [1.13.0] — 2026-07-12

**The web vault — a real Vue app on the WASM crypto core.** The polished UX
prototype is now a working application: unlock, browse, reveal, copy, live 2FA,
and a security dashboard, all backed by the same tested Rust that ships in the
CLI and MCP server. Verified running headless (real seal → open round-trip; a
117-bit strength read and a live RFC-6238 code rendered from WASM).

### Added — `app/` (Vue 3 + Vite + TypeScript + Pinia)
- **WASM-backed core:** `app/src/lib/passbook.ts` instantiates `passbook-wasm`
  once and routes all crypto through it (`seal_vault`/`open_vault`/`totp_code`/
  `watchtower_json`/`password_strength`). The vault persists as a single
  **encrypted blob in localStorage**; the master password never leaves the module.
- **Pinia store** (`app/src/stores/vault.ts`): unlock/lock, filtered category
  views, favourites, add-login, delete — every mutation reseals + repersists and
  recomputes Watchtower.
- **Component layer** (faithful port of the design prototype): unlock screen,
  3-pane shell (brand / nav with live counts / list / detail), item detail with
  password strength bar + reveal + copy, a live TOTP field with a countdown ring,
  the Watchtower score gauge + issue cards, an add-item dialog, and a copy toast.
  Teal/emerald "Passbook" identity, theme-aware.
- Build: `npm run build:wasm` (wasm-pack → `app/src/wasm/pkg/`, gitignored) then
  `npm run build` (`vue-tsc --noEmit && vite build`); the `.wasm` (97 KB gzipped)
  is bundled as a Vite asset. `npm run dev` for local development.

## [1.12.0] — 2026-07-12

**Phase A build-out — four surfaces in parallel.** Built by four isolated agents in
their own file lanes, then integrated into one green workspace (all tests pass,
clippy/fmt clean, `wasm32` build succeeds, warden gate passed).

### Added — `passbook` CLI (`crates/passbook-cli`)
- Manage the consumer vault from the terminal: `init` (generates + persists the
  device Secret Key, prints the Emergency Kit), `add-login`, `list [category]`,
  `show <id> [--reveal]`, `totp <id>` (live code + seconds remaining),
  `watchtower` (weak/reused report + 0–100 score), `emergency-kit`.
- Vault persisted as an encrypted `SealedVault` JSON; 2SKD transparently reused.
  Config via `PROCTOR_PASSBOOK`, `PROCTOR_PASSBOOK_MASTER_FILE`,
  `PROCTOR_PASSBOOK_SECRETKEY_FILE`. 4 tests (incl. a roundtrip that asserts the
  on-disk file is ciphertext, not plaintext).

### Added — family sharing (`crates/passbook/src/sharing.rs`)
- **Per-recipient sealed-box key wrapping:** the 32-byte vault key is wrapped to
  each member via ephemeral X25519 + HKDF-SHA256 + XChaCha20-Poly1305, so only a
  member's private key can unwrap it. `Member`/`MemberPublic`/`SharedVault` with
  `share_to`/`unwrap_for`/`revoke`.
- **Account recovery is intrinsic:** any existing member can `grant_access` to a
  new member without the original key-holder. Secrets held in `Zeroizing`/zeroize
  on drop. 6 tests (member unwraps, non-member rejected, recovery re-grants).

### Added — WebAssembly bindings (`crates/passbook-wasm`)
- `wasm-bindgen` surface so the tested Rust crypto runs client-side:
  `password_strength`, `totp_code`, `totp_seconds_remaining`, `watchtower_json`,
  `seal_vault`, `open_vault`. Target-gated `getrandom` `js` feature for browser
  entropy; builds clean for `wasm32-unknown-unknown`. README with a full HTML
  usage example and `wasm-pack build --target web` instructions.

### Added — browser extension (`extension/`)
- Manifest V3 autofill extension for Proctor Passbook: content script detects
  username/password fields and fills them through the native value setter with
  proper `input`/`change` events (SPA-safe); `background.js` service worker relays
  popup→tab messages; a branded, theme-aware popup lists items with a
  "matches this site" indicator. Prototype uses demo data; README documents the
  native-messaging bridge a production build would use so secrets are never bundled.

### Notes
- Prototype crypto throughout `proctor-passbook`; a formal external review remains
  before any real use (tracked in the threat model).

## [1.11.0] — 2026-07-12

**Phase A kickoff — the consumer credential manager (the "1Password equivalent").**

The broker (Phase B) is the developer wedge; this begins the mainstream family
product, sharing the crypto core.

### Added — `proctor-passbook` (foundation, tested)
- **Rich item model:** logins (username/password/URLs/TOTP/passkey), secure notes,
  cards, identities — with titles, tags, favorites.
- **Secret Key (2SKD):** a 128-bit device key combined with the master password
  (`key = SHA256(argon2id(master) || secret_key)`), so a server breach yields
  uncrackable data even against a weak master — verified: right master but no
  Secret Key can't open. Emergency-Kit format + parse.
- **TOTP (RFC 6238):** rolling 2FA codes (verified against the RFC test vectors),
  so the manager shows codes inline — no separate authenticator app.
- **Watchtower:** weak-password (entropy) + reused-password analysis with a
  security score. 9 tests.

### Added — UX prototype
- A polished, interactive **web-vault UI prototype** (design artifact): 3-pane app
  shell, category nav, search, item detail with reveal/copy/live-TOTP, and a
  Watchtower security dashboard — the visible "1Password equivalent" to steer the UX.



The last two threat-model residuals (R4, R5).

### Added / hardened
- **R4 — signed audit log.** With `PROCTOR_AUDIT_KEY` (hex), the hash chain is
  **HMAC-SHA256**-signed instead of plain SHA-256, so an attacker with only
  filesystem write (no key) cannot forge a valid chain — tamper-*resistant*, not
  just tamper-evident. (`AuditLog::with_file_signed`, `Broker::with_audit_file_signed`.)
- **R5 — real STS XML parser.** The AWS `AssumeRoleWithWebIdentity` response is now
  parsed with `roxmltree` (namespace-agnostic on local name, scoped to
  `<Credentials>`), replacing the hand-rolled tag extractor; malformed/junk XML
  yields a clean error instead of silent mis-parse.

### Threat-model status
All seven expert findings (T1–T7) and all self-review residuals except a formal
external human review are now addressed. R4/R5 fixed here; R1 (zeroize), R2 (trust
gate), R3 (shell block) fixed earlier.



Supply-chain gate + lint hygiene.

### Added
- **Warden commit/push gate** (`.warden.yaml`): pre-commit runs `fmt --check` +
  `clippy -D warnings`; pre-push additionally runs the full test suite and a
  **nox security scan** (fails on active high findings). Provides commit
  provenance/attestation (SLSA/Sigstore-style). Every commit is now gated on a
  clean build, clean lint, green tests, and a clean security scan.

### Changed
- Codebase is now `cargo fmt`-clean and `clippy -D warnings`-clean; refreshed the
  `proctor-mcp` module docs to list the current tool + config surface.

## [1.9.0] — 2026-07-12

External security-expert review — all seven findings fixed — plus nox scanning.

### Security fixes (from red-team review; see THREAT-MODEL §6a)
- **T1 network egress:** untrusted mode now denies subprocess egress by default
  (container `--network none`, bubblewrap `--unshare-net`); `run_command` reports
  the `egress` posture. Isolation now contains the network, not just /proc + FS.
- **T2 origin-binding teeth:** the GitHub executor refuses an origin it doesn't
  actually serve — the credential is bound to the request *destination*, not a label.
- **T3 master + env inheritance:** master is read from `PROCTOR_MASTER_FILE` (not
  env/`/proc`); the runner **`env_clear()`s** the child and re-adds only a minimal
  baseline + the injected credential — the broker's env (incl. the master) no
  longer leaks into subprocesses.
- **T4 minter endpoints:** must be https (reject cleartext identity exfil).
- **T5 profile trust:** group/world-writable profile files are rejected at load.
- **T6 audit fail-open:** persistent-write failures surface as `audit_warning`.
- **T7 redaction:** documented as hygiene; real defense is T1 + short-TTL.

### Dependencies
- **jsonwebtoken 9.3.1 → 10.4.0** — clears **CVE-2026-25537** (type confusion in
  claim validation; not exploitable here, we only sign).

### Tooling
- **nox** security scanning wired in: **grade A, 0 active findings**
  (`docs/security/badge.svg`). Test fixtures scrubbed of secret-shaped strings;
  verified false positives baselined in `.nox/baseline.json`.



Trust gate for the exec path (threat-model R2).

### Added
- **`PROCTOR_TRUST=untrusted`** makes the safe posture enforceable: `run_command`
  is **refused** when isolation is `none`, directing the operator to set
  `PROCTOR_ISOLATION` (`docker:<image>` / `bwrap`) or explicitly choose trusted
  mode. Default remains trusted (local interactive use). The refusal is a hard
  gate at the top of the run path, before any credential is touched.



Zeroize secrets in memory (threat-model R1, the top open risk).

### Changed / hardened
- **Vault `Item.secret` is wiped on `Drop`**, and the **decrypted vault plaintext**
  is held in `Zeroizing` during load.
- **The broker's long-lived secret map** (`AppState.secrets`) and the transient
  `secret` / `inject` handles in `run_command` / `use_credential` are now
  `Zeroizing<String>` (minted token values already were).
- Result: secrets no longer linger as plain `String` in the long-lived stores; a
  core dump exposes far less. *Residual:* a few short-lived copies and `Item`'s
  `Debug` derive can still surface plaintext (follow-ups noted in the threat model).



Security review artifact + the first hardening it surfaced.

### Added
- **[Threat Model & Security Posture](docs/security/THREAT-MODEL.md)** — a rigorous
  self-review (STRIDE by component, trust boundaries, assumptions, prioritized
  residual risks R1–R7, recommendations, reviewer checklist). Frames an external
  review; explicitly not a substitute for one.

### Changed / hardened
- **Shell interpreters are blocked by default on `run_command`** (R3). A profile
  that authorizes `sh`/`bash`/`python`/… as the run program is refused unless it
  sets `allow_shell = true`, because a shell runs arbitrary work past
  command-binding. Allowed shells still carry a `shell_warning` in the response.
- Profiles gained an `allow_shell` field (default false) and `is_shell_interpreter`
  in `proctor-profiles`.

### Top open items for the auditor (from the threat model)
- R1 secrets not zeroized in memory · R2 `isolation=none` default · R4 audit log
  unsigned · R5 minimal STS XML parse. **A formal external security review + fuzzing
  remains required before any real use.**



Multi-field minted credentials + per-provider minter routing — the two edges
left open by v1.4.0.

### Added
- **`proctor-mint::aws` — AWS STS `AssumeRoleWithWebIdentity` minter.** Exchanges a
  held OIDC web-identity token for short-lived role credentials and emits the
  **trio** (access key id / secret / session token) as JSON, so a minted cred
  composes directly into a multi-field (`env_map`) profile. HTTP injected for
  offline tests; real reqwest behind `net`; wired via `PROCTOR_AWS_ROLE_ARN`.
- **Per-provider minter routing.** Provider profiles declare their minter with a
  `mint` field (`"github-app"`, `"token-exchange"`, `"aws-sts"`). The server keeps
  a minter map keyed by kind and routes each item's mint through
  `minter_for(provider)` — so an `aws` item mints via STS while a `github` item
  mints via the App, data-driven from the profile. Seed profiles updated (aws →
  `aws-sts`, github → `github-app`).

### Result
- Minted credentials now fill both single-token (`env_var`) and multi-field
  (`env_map`) profiles, and the minter is chosen per provider from external config.
  Verified end-to-end: an AWS item routes to the STS minter, the JSON trio composes
  into `AWS_ACCESS_KEY_ID`/`_SECRET_ACCESS_KEY`/`_SESSION_TOKEN`, redacted in output.

### Still deferred
- Per-item role/audience overrides (single global role/endpoint per kind today),
  Azure/GCP-specific minters, and a **formal security review before real use**.



Protocol minters + prefer-minted on the exec path (ADR-0002 Phase 3) — the last
unbuilt axis. ADR-0002 is now fully implemented.

### Added
- **`proctor-mint::exchange` — RFC 8693 OAuth 2.0 Token Exchange minter.** Present
  a held subject token (an OIDC identity / JWT) to an STS token endpoint and get a
  short-lived scoped access token. One minter, any conforming STS — the mechanism
  behind OIDC Workload Identity Federation (GCP WIF, generic STS). HTTP injected
  for offline tests; real reqwest form-post behind `net`. Wired via
  `PROCTOR_STS_ENDPOINT` (+ `_AUDIENCE` / `_SCOPE` / `_SUBJECT_TYPE`).
- **Prefer minted short-TTL creds on the `run_command` exec path.** A mintable
  item mints a short-lived token and injects *that* into the subprocess (not the
  durable secret), bounding how long a leaked value stays useful. Falls back to
  the stored secret for non-mintable items or multi-field profiles. Responses
  report `credential_source: minted | stored`.

### Result
- The exec-path security posture is complete: **OS isolation** (v1.3.0) contains
  *where* a credential can be scanned; **short-TTL minting** (this release) bounds
  *how long* a leaked one is useful. ADR-0002's five axes are all implemented.

### Still deferred (beyond ADR-0002)
- AWS `AssumeRoleWithWebIdentity` multi-field minting (the exchange minter returns
  a single access token today; multi-field cloud creds compose from JSON later),
  per-provider minter selection, and a **formal security review before real use**.



OS-level isolation for `run_command` (ADR-0002 Phase 4) — the exec path can now
run the credential-bearing command in a container/namespace, so `/proc` and the
filesystem don't cross to the host.

### Added
- **`Isolation` backend** (`proctor-mint::run`): `none` (default), `bubblewrap`
  (Linux user/pid/mount namespaces, remounted `/proc`), and `container`
  (docker/podman: separate `/proc` + filesystem, `--rm`). Configured via
  `PROCTOR_ISOLATION` = `none` | `bwrap` | `docker:<image>` | `podman:<image>`
  (network via `PROCTOR_ISOLATION_NETWORK`, default `bridge`).
- The credential is passed with `--env NAME` (value from the runtime's env),
  **never in argv** — verified by test that the secret value never appears in the
  wrapped command line.
- `run_command` responses now report the `isolation` posture; the server logs a
  warning when isolation is `none` (safe for trusted use only).

### Verified
- Real containerized run (docker:alpine): the command ran inside the container
  (confirmed via `/etc/alpine-release`), the credential injected via `--env`, and
  the output returned redacted.

### Still deferred
- **Prefer minted short-TTL creds on the exec path** + RFC 8693 / OIDC-WIF
  protocol minters (ADR-0002 Phase 3). Isolation + short-TTL together are the full
  posture for untrusted-content-driven autonomy; only isolation is done.



The generic exec-injection executor (ADR-0002 Phase 1) — one engine covers the
CLI long tail via the external profiles.

### Added
- **`run_command` MCP tool** — runs a CLI command with the item's credential
  injected into the subprocess **environment (never argv)**, and returns only the
  (redacted) output. The credential never reaches the model.
  - **Command-binding** (anti-confused-deputy): the program must be authorized by
    the item's provider profile (`commands`); e.g. an AWS credential can't run
    `curl`.
  - **Risk gate**: profile classification decides — read commands run; mutating /
    unknown commands step-up (attended) or are denied (unattended).
  - **Output redaction**: injected credential values are stripped from
    stdout/stderr before returning (so even `echo $TOKEN` yields `***REDACTED***`).
- **`proctor-mint::run`** — the generic subprocess runner (`run_with_env`).
- Vault items gain an optional **`provider`** field linking them to a profile;
  `proctor add`'s new trailing `[provider]` arg sets it.

### Security (see ADR-0002)
- Env injection is hygiene, not an isolation boundary (`/proc/environ`, `ps`,
  child inheritance). This build injects via env only (never argv) and redacts the
  return channel; **OS-level isolation and short-TTL creds remain required for
  untrusted-content-driven autonomy** and are not yet implemented.



Providers become **external config** (ADR-0002 registry, made concrete).

### Added
- **`proctor-profiles`** — external, pluggable provider profiles loaded from TOML
  at runtime (`$PROCTOR_PROFILES` or `~/.proctor/profiles`). A profile declares
  how a credential is injected (`env_var` for single-token, `env_map` for
  multi-field JSON credentials) and argv risk patterns
  (`read_patterns` / `mutate_patterns`, **default-gate** when unmatched, so it's
  safe when incomplete). One profile serves every tool that shares the provider's
  env-var convention (the `aws` profile → aws-cli, Terraform, Pulumi, SDKs).
- Seed profiles ship in `profiles/` (aws, azure, github, gitlab, hetzner) plus a
  `profiles/README.md`. **Adding a provider is dropping a `<id>.toml` file — no
  recompile.**
- **`proctor profiles`** CLI command lists what's loaded (proves pluggability:
  drop a file → it appears).



## [1.0.0] — 2026-07-12

The Phase B wedge is complete end-to-end: the interactive approval loop closes
the last behavioral gap.

### Added
- **Interactive step-up via MCP elicitation** — when the risk-tiered policy
  returns a step-up (e.g. a bound-but-not-pre-approved origin, attended), the
  broker prompts the user through the client (`peer.elicit`). Approve → the
  action is performed and tagged `approved_via: human elicitation`; reject →
  denied; no elicitation support → falls back to a step-up note.
- An `Approver` abstraction (`ElicitApprover` in production, `MockApprover` in
  tests) so the whole step-up path is unit-tested (approve / reject / unavailable).
- Refactor: decision + execution logic extracted into `handle_use` + `execute`,
  making the broker's behavior fully testable independent of the MCP transport.

### Complete end-to-end (this is what "the wedge" now does)
- Origin-binding (anti confused-deputy) · risk-tiered policy · **interactive
  step-up** · propose-not-commit (refuse → downgrade → perform as a draft PR) ·
  two credential-use models (vault-read *or* mint) · secretless read + write
  execution with real params · persistent hash-chained audit · kill switch —
  all driveable from Claude Code over MCP. 37 tests.

### Still deferred (post-wedge)
- OAuth Token Exchange (RFC 8693) / cloud STS minters, more executable
  operations, unattended out-of-band alerts, anomaly detection, sync/self-host,
  and a **formal security review before any real use**.

## [0.6.0] — 2026-07-12

Accountability + capability lifecycle.

### Added
- **Persistent audit log** — set `PROCTOR_AUDIT` to append every broker decision
  to a JSON-lines file (hash-chained, tamper-evident). `AuditLog::with_file` /
  `Broker::with_audit_file`.
- **Kill switch** — `revoke_all` MCP tool revokes all server-held minted tokens
  immediately (audited); `list_minted` shows held tokens (reference + provider +
  masked, never values).

## [0.5.0] — 2026-07-12

Threads real operation parameters through the tool, making the GitHub write a
genuine, parameterized action rather than a fixed demo.

### Added
- **`use_credential` accepts a `params` object** carried through to the performed
  action — e.g. `OpenPullRequest`: `{ owner, repo, head, base, title }`. Verified
  end-to-end (the PR title/repo reach the executor).
- `ExecAction` params flow through both the minted and vault-read execution paths.

### Changed
- `GitHubExecutor::OpenPullRequest` now builds the draft PR from the supplied
  params (the real POST is fully specified; still exercised offline via mock).
- `MockExecutor` echoes the params so callers can confirm they flowed through.

### Security invariants (tested)
- Params flow to the executor while the credential still never appears in any
  response.

## [0.4.0] — 2026-07-12

Closes the **propose-not-commit** loop at runtime: an irreversible action is
downgraded to a reviewable artifact, and that artifact is actually performed.

### Added
- **Write-side secretless execution** — `ExecKind::OpenPullRequest`:
  - `ShipToProduction` (unattended) → the broker proposes `OpenPullRequest`.
  - `OpenPullRequest` → the broker performs it as a **draft pull request** (a
    reviewable artifact, never a merge), via a `pull_requests:write`-scoped
    credential (minted) or the stored token (vault-read). The credential never
    reaches the model.
  - `GitHubExecutor` posts a draft PR (`draft: true`) from supplied params;
    `MockExecutor` demonstrates it offline.
- Verb-appropriate mint scopes: `OpenPullRequest` mints `contents:read +
  pull_requests:write`; reads stay read-only.

### Changed
- `Executor` HTTP is now a single injected `HttpClient` (get + post); the real
  client is `ReqwestClient` (behind `net`).
- **CLI**: `proctor add`'s `mintable` is now an optional trailing arg defaulting
  to **false** — the vault-read model is the default (`add <id> <label>
  <origins> <secret> [mintable] [kind]`).

### Security invariants (tested)
- The proposed write executes as a **draft PR only** (`draft: true`, "not
  merged") — the never-unattended commit is never performed.
- Neither minted tokens nor stored credentials appear in any response.

## [0.3.0] — 2026-07-12

Two ways to use a credential, selected per item by the `mintable` flag — you are
not forced to mint.

### Added
- **Secretless execution from the vault** (`mintable = false`): the broker **reads
  the durable token stored in the vault and uses it directly** to perform the
  action — nothing is fetched or created. The token is used inside the broker and
  never returned to the model (`primitive: "secretless_exec"`, `source: "vault"`).
- The `Executor` now takes a bearer credential (from either source), so the same
  execution path serves both:
  - `mintable = true`  → mint a short-lived scoped token, then perform (`source: "minted"`).
  - `mintable = false` → read the stored token from the vault, then perform (`source: "vault"`).

### Changed
- `Executor::perform` takes `bearer: &str` instead of a `MintedToken`, decoupling
  execution from where the credential came from.

### Security invariants (tested)
- On a vault-read execution, the stored token never appears in the response
  (verified end-to-end); credentials are masked in summaries.

## [0.2.0] — 2026-07-12

Closes the loop: **secretless execution**. The broker mints a scoped token,
*performs the action itself*, and returns only a sanitized result — the model
gets a result, not a value.

### Added
- **`proctor-mint::exec`** — an `Executor` layer:
  - `Executor` trait + `ExecAction`/`ExecResult`; HTTP GET injected as `GetHttp`
    for offline tests.
  - `GitHubExecutor` — uses a minted installation token to list the repositories
    the installation can access (real read), returning only repo names/count.
  - `MockExecutor` for offline demos/tests.
- **`proctor-mcp`** — `use_credential` on a `Read`/`FetchData` verb now **mints +
  performs** the action and returns `primitive: "secretless_exec"` with a
  sanitized `result` — the base secret and the minted token never reach the model.
  Non-executing verbs still mint-and-hold. GitHub executor wired when configured,
  else mock.

### Security invariants (tested)
- On a secretless read, the response carries the *result* but never the base
  secret or the minted token value (verified end-to-end).

### Still not built
- More execution operations (writes via propose-not-commit artifacts), OAuth
  Token Exchange / cloud STS minters, `elicitation` step-up, sync/self-host,
  anomaly detection — and a **formal security review before any real use**.

## [0.1.0] — 2026-07-12

First working version of the **Phase B wedge**: the AI credential broker, backed
by a real vault and minting, driveable as an MCP server.

### Added
- **`proctor-broker`** — the credential-broker security model:
  - Origin-binding (defeats the confused-deputy / prompt-injection attack,
    independent of any human approval).
  - Capabilities scoped on `item × origin × verb × TTL × use-count`.
  - Risk-tiered policy: auto-allow / step-up / deny / propose-instead.
  - **Propose-not-commit** autonomy floor with a locked never-unattended list
    (delete data · move money · ship to prod · comms-as-you · rotate/revoke creds).
  - Default primitive preference: minted → secretless → (raw, hard-denied).
  - Tamper-evident, hash-chained audit log.
- **`proctor-vault`** — file-backed encrypted vault (Argon2id + XChaCha20-Poly1305);
  `seal`/`open`/`save_to_file`/`load_from_file`; secret-free `ItemRef` for the broker.
- **`proctor-mint`** — "mint, don't inject": `Minter` trait, `MockMinter`, and a
  real `GitHubAppMinter` (RS256 JWT + installation access-token flow) with signer
  and HTTP injected as traits (tested offline; real `jsonwebtoken`/`reqwest` behind
  the `net` feature). Minted values are zeroized and never model-facing.
- **`proctor-mcp`** — the broker+vault+minting exposed as an MCP server (stdio) via
  the official `rmcp` SDK. Tools: `list_credentials`, `use_credential`, `audit_log`.
  On an allowed mintable item it mints a token held server-side and returns only a
  `token_ref` + masked view. Real GitHub App minter wired when configured, else mock.
- **`proctor` CLI** — `init` / `add` / `list` to manage a real on-disk vault, plus
  a `demo` walkthrough of the broker.
- **Docs** — market & feature research, product spec (PRD), and ADR-0001 (broker
  security model).

### Security invariants (tested)
- The base secret and any minted token value never appear in a tool response.
- A credential is refused against any origin it is not bound to.
- Irreversible high-consequence actions cannot run unattended (proposed or denied).

### Not yet built
- Secretless **execution** ("perform the action" with a minted token on the
  agent's behalf) — today the minted token is held server-side, not yet used.
- `elicitation`-based human step-up approval through MCP.
- Vault sync / self-host / on-device migration surfaces.
- Anomaly detection, unattended-policy pre-authorization + out-of-band alerts.
- **Formal security review** — required before any real use.
