# ADR-0005 — Managed cloud (paid, Kubernetes)

- Status: Proposed
- Date: 2026-07-18
- Supersedes: none
- Related: [ADR-0003](ADR-0003-ddd-hexagonal-structure.md) (DDD/hexagonal),
  [ADR-0004](ADR-0004-family-sharing.md) (family sharing, zero-knowledge stance),
  [product-spec.md](../product/product-spec.md) (§9 pricing, §5 trust model),
  `crates/sync` (the ports), `crates/sync-server` (the HTTP API),
  `deploy/` (the k8s manifests + Dockerfile)

## Context

Keyward's server today is a **single-node, file-backed prototype**. It is correct
and it is genuinely zero-knowledge — but it is not a business, and it is not a
cloud you could put a paying family on.

Concretely, as shipped:

- `crates/sync-server` is a `tiny_http` server whose request loop is a plain
  `for request in server.incoming_requests() { handle(request, &app) }` — **fully
  synchronous, blocking, no async runtime.**
- Persistence is the filesystem: `FileStore` writes one JSON `SyncEnvelope`
  (`{version, blob}`) per account; `FileAccountStore` writes a single
  `accounts.json`; `FileShareGroupStore` writes one JSON file per group. Every
  mutating path is serialized by a **process `Mutex`** — a read-modify-write
  guard that only works because there is exactly one process.
- The k8s deploy (landed with the `deploy/` subtree, v1.30.0) reflects that
  constraint honestly: a **ReadWriteOnce PVC**, `replicas: 1`, `strategy:
  Recreate`. The README says it in as many words — *"Do NOT scale this beyond 1
  without moving to a shared backing store."* Register/invite **rate limiting**
  (v1.31.0) is in-memory and therefore **per-pod**, which is coherent only at one
  replica.

The single-writer file store is the sole thing standing between us and a
horizontally-scalable service. Everything else the managed cloud needs — TLS at
the ingress, non-root hardening, health probes, resource limits, hashed tokens,
hashed invite codes, an optional per-account `email`, optimistic concurrency —
already exists.

The decisive architectural fact is that **the storage layer is already a set of
hexagonal ports** (ADR-0003): `SyncStore`, `AccountStore`, and `ShareGroupStore`
are traits, and the file backends are just adapters. The managed cloud is
therefore **new adapters behind existing ports, not a rewrite.** The domain, the
crypto, the wire protocol, and the clients do not move.

This ADR pins the packaging, the datastore, the trust boundaries, the threat
model, the operations bar, the open-core line, and the sequencing for a **paid,
managed, zero-knowledge cloud** — designed to scale to **thousands of families**
while starting with a modest footprint. The decisions below are **locked**; this
document records them and the reasoning, it does not relitigate them.

## Decision

### 1. Business model & packaging — open-core, 1Password-shaped, *with a free tier*

The core server and all clients stay **AGPL open** (self-hostable forever, per
product-spec §3/§9). The managed cloud is **paid** — that is where the premium
value and the revenue live. We follow the **1Password model** (managed E2E cloud,
polished, family-first) with **one deliberate departure: a real free managed
tier.** 1Password has no free tier; that gap is our product-led-growth (PLG) hook
and the reason a switcher tries us at all.

Four packages, three of them managed:

| Package | Price | Hosting | What you get |
|---|---|---|---|
| **Self-host / on-device** | **Free forever** (AGPL) | Yours | Full clients + server, all core item types, Watchtower, family sharing if you run the relay yourself. Unlimited. No Keyward account. |
| **Free (managed)** | **$0** | Keyward cloud | **Single user, personal vault only.** Core item types + Watchtower. Small **device cap (e.g. 2)**. **No** family sharing, **no** AI credential broker. The PLG on-ramp. |
| **Individual** (paid) | placeholder | Keyward cloud | **Unlimited devices**, the **AI credential broker**, **priority sync**. |
| **Family** (paid) | placeholder | Keyward cloud | Everything in Individual **+ family sharing**: shared vaults, **seats (e.g. up to 5–6)**, **guest single-item share**, **account / social recovery**. |

Prices are **placeholders, set later**, positioned **between Bitwarden (cheapest)
and 1Password (premium)** per product-spec §9. The comparison we are threading:

| | Bitwarden | 1Password | **Keyward** |
|---|---|---|---|
| Open source | Yes | No | **Yes (AGPL core)** |
| Self-host | Yes (free) | No | **Yes (free forever)** |
| Free managed tier | Yes (generous) | **No** | **Yes (single-user PLG hook)** |
| Family sharing | Paid | Paid | **Paid** |
| AI credential broker | No | No | **Yes (paid — the wedge)** |
| Zero-knowledge / 2SKD | Partial | Yes | **Yes (2SKD, ADR-0004)** |

The free managed tier is deliberately *narrow* — single user, personal vault, a
2-device cap, no sharing, no broker — so it demonstrates the product and seeds the
household champion (product-spec §2.4) **without cannibalizing** the paid tiers.
Family sharing and the broker are the paid pulls; they are gated in the metadata
plane (§4), never by touching vault plaintext. The exact generosity dial is an
open product question (product-spec §14) but the *shape* is locked here.

**Scale target:** thousands of families, later. Design to scale horizontally from
day one; deploy a **modest** initial footprint (a few small replicas + one
managed Postgres) and grow by adding replicas and read capacity, not by
re-architecting.

### 2. Architecture — swap the backend behind the existing ports

**Datastore: PostgreSQL**, for *both* planes of data:

- **Metadata:** accounts, per-device token hashes, group membership directories,
  invites (hashed), plan/subscription state.
- **Vault blobs:** the opaque sealed-vault ciphertext and the opaque group
  content/wrapped-keys blobs, stored as **`bytea`**.

Storing blobs in Postgres (rather than object storage) is a **deliberate, and
reversible, simplification**: a sealed vault is small — the `SyncEnvelope.blob`
is tens of KB of ciphertext, not a media file — so `bytea` in Postgres is
comfortably within its operating envelope, keeps everything transactional, and
removes an entire moving part. Object storage (S3/GCS) for blobs is a real
optimization, but it is **deferred until large scale** (see roadmap "later"). The
blob is opaque either way, so moving it later is an adapter change, not a schema
or protocol change.

This one swap is what makes the API **stateless and horizontally scalable**.
Every handler in `sync-server` already carries no session state between requests;
the only shared mutable state is the file store's process `Mutex`. Replace the
file adapters with Postgres adapters and the server becomes **N identical
replicas behind the ingress** — a real `RollingUpdate` (no more `Recreate`), a
`readiness`-gated rollout, and a **HorizontalPodAutoscaler** — versus today's
single-replica RWO-PVC. The optimistic-concurrency contract that makes this safe
is *already there*: `next_version(current, expected)` and the `If-Match` /
`X-Vault-Version` protocol move the conflict-resolution burden to the client, so
concurrent replicas need no coordination beyond the database row.

**New adapters, behind unchanged ports:**

- `PgStore: SyncStore` — `get`/`put`/`delete` over a `vault_blobs` row. `put`
  enforces the version check as an atomic `UPDATE … WHERE version = $expected`
  (or `INSERT` when `expected` is `None`), returning `SyncError::Conflict` when
  zero rows match — the exact semantics of `next_version`, now enforced by the DB
  instead of a process mutex.
- `PgAccountStore: AccountStore` — `register` / `add_device` / `resolve_token`
  (`… WHERE token_hash = $1 AND (expires_epoch IS NULL OR expires_epoch >= $now)`)
  / `rotate_token` / `list_devices` / `revoke_device`. Token hashing and TTL
  logic are unchanged; only the persistence moves. The optional `email` field
  already on `AccountRecord` becomes the account-plane column (§3).
- `PgShareGroupStore: ShareGroupStore` — the group directory, invites, and the two
  versioned blobs (`wrapped_keys`, `content`) as rows; `redeem_invite`'s
  single-use + TTL + membership mutation runs inside **one SQL transaction** so
  the read-modify-write that the file adapter guards with a mutex becomes a
  proper atomic DB transaction. This is strictly *stronger* than today: the
  atomicity comment on the trait (`groups.rs`) is honored by the database, not by
  a single process.

> The migrated crate is being built now, in parallel, as **`crates/sync-postgres`**
> (roadmap phase 1). It is additive: `sync-server`'s `main` already boxes the
> three ports and selects an adapter by env var (`KEYWARD_SYNC_DIR` →
> file/memory); a `KEYWARD_SYNC_DATABASE_URL` simply selects the Postgres trio.

**Connection pooling with `r2d2` (synchronous), no async runtime.** The server is
`tiny_http` — blocking. A **synchronous** Postgres client (`postgres` +
`r2d2` / `r2d2_postgres`) fits this model exactly: each request borrows a pooled
connection for the duration of the blocking handler and returns it. We
deliberately do **not** introduce `tokio` / `sqlx` — that would mean rewriting the
server's execution model for no benefit at this scale. (Note: `tiny_http`'s
default loop is single-threaded; horizontal scaling comes from **multiple pods**,
and per-pod concurrency, if ever needed, is a worker-thread pool over the same
blocking pool — not an async rewrite. The pool sizing must respect the DB's
`max_connections` across all replicas.)

**Two logically separated planes.** Zero-knowledge (ADR-0004) is preserved and
paramount. Postgres holds **only**:

- ciphertext (sealed-vault blobs, group content, wrapped group keys),
- public keys (members' X25519 publics),
- **hashed** secrets (SHA-256 device-token hashes, SHA-256 invite-code hashes),
- **minimal account/billing metadata** — email, plan, subscription state.

We keep the **vault-data plane** and the **account/billing/PII plane** *logically
separated* — separate schemas/tables, and ideally separable blast radius (distinct
credentials/roles, and the option to split them onto different databases later).
The rule: a breach of the **metadata plane never yields plaintext** (the crypto
holds; it holds nothing but email + plan + hashes), and a breach of the
**vault-data plane never yields PII or plaintext** (it holds nothing but
ciphertext + public keys). Neither plane on its own, and not even both together,
yields a decryptable vault — `K_vault`, the master password, and the Secret Key
never reach the server (ADR-0004 §3).

### 3. Entitlements plane

Add a **`plan`** (`free` | `individual` | `family`) and **subscription state** to
the account record — the account plane, alongside the existing optional `email`.
The server **enforces free-tier limits entirely in the metadata plane, never
touching vault plaintext**:

- **Device cap** — `add_device` (and/or `register`'s follow-ups) checks
  `list_devices(account).len()` against the plan's cap (free ≈ 2; paid unlimited)
  and refuses over-cap with a clear error. Purely a count over the account plane.
- **Sharing gated to paid** — `POST /v1/groups` (create) and invite mint are
  refused for a `free` account. Group membership is metadata; gating it never
  reads a blob.
- **Broker gated to paid** — the broker is a client/edge capability, but its
  managed entitlement is the same `plan` check.

**Billing via Stripe.** Subscription lifecycle (checkout, renewal, cancellation,
dunning) is owned by Stripe; a **webhook** updates the account's plan +
subscription state. Billing is a **later increment** (roadmap phase 2), but the
schema **anticipates it now**: the account plane carries `plan`,
`subscription_status`, and a `stripe_customer_id` column from the first Postgres
migration, defaulting every existing/self-registered account to `free`. This
keeps entitlement enforcement and billing decoupled — the server enforces `plan`
regardless of *how* `plan` got set, so entitlements ship before Stripe does.

### 4. Deployment shape

The existing manifests become the base; the changes are the natural consequences
of a stateless backend:

- **`Deployment`**: `replicas: N` (start small, e.g. 2–3), **`strategy:
  RollingUpdate`** (safe now — no shared RWO volume to contend), keep the
  hardening that already exists (`runAsNonRoot`, `readOnlyRootFilesystem`,
  `drop: ALL`, `seccompProfile: RuntimeDefault`), keep the `/healthz` liveness
  and `/readyz` readiness probes verbatim.
- **Drop the PVC** from the server; state now lives in **managed Postgres**
  (cloud provider's managed offering, or an operator-run in-cluster Postgres with
  its own storage). `readyz` should reflect DB reachability so a replica that
  cannot reach Postgres fails readiness instead of serving errors.
- **Add an `HPA`** keyed on CPU (and later request-rate) to ride demand.
- **Ingress unchanged in shape**: TLS still terminates at nginx-ingress via
  cert-manager; the server still speaks plain HTTP on `:8787` behind it; the
  `proxy-body-size: 16m` allowance for larger sealed blobs stays.
- **Rate limiting must move off per-pod.** The v1.31.0 in-memory limiter is
  correct at one replica but leaky across N (each pod counts independently). The
  managed cloud enforces register/invite limits at a **shared layer** — the
  ingress (nginx `limit-req`) and/or a shared store — so the DoS mitigation in
  ADR-0004 holds under horizontal scale. (The in-memory limiter remains a fine
  per-pod backstop and the correct default for self-hosters.)

Nothing above changes the wire protocol or the clients.

## Threat model (STRIDE, custodian lens)

Running the managed cloud means **becoming custodian of many encrypted vaults**,
which makes Keyward a **high-value target** in a way a single self-hoster is not —
the concentration *is* the risk. Zero-knowledge means a server/DB breach yields
**only ciphertext** *if the crypto holds* — but a host owns a set of **new** risks
that a library does not. Enumerated:

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Stolen bearer token replayed; fake group member (per ADR-0004 key-substitution) | Tokens stored **hashed** (SHA-256), TTL'd + rotatable (already in `AccountStore`); TLS at ingress in transit; group key-substitution mitigated by ADR-0004's out-of-band safety-number verification (**part of the crypto review gate**). |
| **Tampering** | Attacker/MITM/DB-writer alters a blob or wrapped key | AEAD (XChaCha20-Poly1305) on every blob — a tampered blob fails to open client-side; TLS in transit; DB integrity + backups. The server cannot forge a vault it cannot decrypt. |
| **Repudiation** | Disputed account/membership/billing action | Append-only audit of account-plane and membership events (member-signed group entries per ADR-0004 remain a later increment); Stripe holds the billing record of truth. |
| **Information disclosure — plaintext** | Full DB breach | **Zero-knowledge holds:** DB has only ciphertext + public keys + hashes + email/plan. No `K_vault`, master, or Secret Key ever reaches the server. This is the whole design. |
| **Information disclosure — metadata** | Breach or insider reads the metadata plane | **The residual leak a host cannot fully avoid:** account existence (email), device counts, the **family graph** (who shares with whom), blob sizes, and **sync timing**. Minimize (store only what's needed, §2 plane separation), name it plainly in the security whitepaper, and treat the account plane's PII as the sensitive asset it is. |
| **Account takeover via the billing side-channel** | Attacker seizes the **email/billing** identity to hijack the account plane | **Email verification** on register/change; account recovery that **explicitly does NOT recover the vault** — recovering account/billing access returns control of the *account plane* only; without the master password + Secret Key the vault stays sealed. This boundary must be loud in the UX so no one believes "reset my account" means "recover my passwords." |
| **Elevation / insider & operator access** | An operator or compromised control-plane credential reads/writes the DB | Plaintext is out of reach by construction; for metadata: least-privilege DB roles, plane-separated credentials, audit of operator access, encryption at rest, no standing prod access. |
| **Supply chain** | Compromised dependency or image | Minimal image (already server-only, non-root, `debian:bookworm-slim`); pin + eventually **digest-pin** images; SBOM + dependency scanning in CI; reproducible builds (product-spec §11). |
| **Denial of service** | Register/invite spam; oversized blobs; connection exhaustion | Register + invite **rate limiting** (v1.31.0) moved to a shared/ingress layer (§4); `proxy-body-size` cap on blobs; DB connection-pool limits; HPA for load. |
| **Availability & durability** | Losing a vault | **The worst outcome for a password manager** — for a user, losing their vault is worse than most breaches. Durability is existential: backups + PITR + tested restore (see Operations). |

**Hard gate — non-negotiable.** A **formal external review** of the sharing
crypto and the 2SKD construction (the open items in ADR-0004 §"Known open item":
directory trust / key-substitution / safety numbers) is **required before
onboarding any paying user.** You cannot run a paid zero-knowledge cloud on
unreviewed crypto — the entire value proposition is "a breach yields only
ciphertext," and that claim is only worth what its review is worth. This gate sits
**first** in the roadmap, before billing, before onboarding.

## Operations

For a password-manager cloud, **durability is existential** and uptime
expectations **rise the moment money changes hands.** The operations bar:

- **Backups + point-in-time recovery (PITR).** Managed Postgres with automated
  backups + WAL/PITR; because the payload is ciphertext, backups are safe on
  ordinary infrastructure (as the deploy README already notes for the PVC) — but
  they protect **availability and integrity**, which are now the point.
- **Tested restore drills.** A backup you have never restored is a hope, not a
  backup. Scheduled, documented restore rehearsals with a target RPO/RTO.
- **Monitoring + alerting** on the golden signals (latency, errors, saturation),
  DB health, cert expiry, and the abuse endpoints.
- **Public status page** — a paid service owes users visible uptime.
- **Incident-response plan** — runbooks, on-call, breach-notification procedure
  (the metadata plane is PII; disclosure obligations apply).
- **Trust deliverables:** a **public security whitepaper** (the crypto, the plane
  separation, the explicit "what the server can and cannot see," the metadata
  caveats) and, as we grow, a **third-party audit / SOC 2**. These are not
  paperwork — for a zero-knowledge custodian they *are* the product's credibility.

## Open-core boundary

The line, and the moat:

- **Open (AGPL):** the core **server = the data plane** (`crates/sync`,
  `crates/sync-server`, `crates/sync-postgres`) and all clients. Self-hosters run
  exactly this, unmodified, for free — including family sharing if they run their
  own relay. This keeps the promise in `deploy/README.md` and product-spec §9/§22.
- **Proprietary (the moat):** the cloud **control plane** — billing
  (Stripe integration + webhooks), multi-tenant operations and **entitlement
  tooling**, admin/support surfaces, fleet dashboards, and the abuse/anti-fraud
  layer. None of this is needed to *use* Keyward; it is needed to *run the paid
  cloud*.

**Recommended structure (a decision to confirm):** keep the open server as the
**pure zero-knowledge data plane** and put billing/entitlement logic in a
**separate, closed control-plane service** that either (a) **fronts** the data
plane (the control plane is the public edge, authenticates + checks entitlements,
then proxies to the internal data-plane service), or (b) is called **alongside**
it (a thin entitlements check the data plane consults). Option (a) keeps the open
server entitlement-agnostic (cleanest open-core line, easiest to keep the OSS
build honest); option (b) keeps a single network hop but bleeds a little
entitlement awareness into the open server. The `plan` column lives in the shared
DB either way. **This split — and which of (a)/(b) — is flagged as a decision to
confirm**, not settled here; the locked part is only that the control plane is
proprietary and the data plane stays open.

## Roadmap / sequencing

**Gate 0 — Crypto review (blocks everything paid).** Formal external review of
`crates/passbook/src/sharing.rs` + the 2SKD construction; close ADR-0004's
key-substitution / directory-trust open item (safety numbers, member-signed
directory). No paying user is onboarded before this passes.

**Phase 1 — Postgres backend + stateless API + backups.** *(building now, in
parallel, as `crates/sync-postgres`.)* The three Postgres adapters behind the
existing ports; `sync-server` selects them by env var; DB-enforced optimistic
concurrency and transactional `redeem_invite`; `r2d2` pool; drop the PVC; move to
`replicas: N` + `RollingUpdate` + HPA; managed Postgres with automated backups +
PITR; move rate limiting to a shared/ingress layer.

**Phase 2 — Accounts + email verification + Stripe + entitlements.** Email
verification on register/change; the `plan` / `subscription_status` /
`stripe_customer_id` account-plane columns and their **enforcement** (device cap,
sharing/broker gating); Stripe subscription lifecycle + webhook → entitlement
update; the account-recovery-that-does-not-recover-the-vault flow.

**Phase 3 — Operations & trust.** Monitoring/alerting, public status page,
incident-response runbooks, tested restore drills on a schedule, and the **public
security whitepaper**.

**Later — Scale & assurance.** HA / multi-region; **SOC 2** and a recurring
third-party audit; **object storage** for vault blobs at large scale (S3/GCS
adapter behind `SyncStore`, blobs out of Postgres); **digest-pinned** images and
hardened supply chain.

## Consequences

- **Positive:** the managed cloud is a set of **new adapters behind unchanged
  ports** — the domain, crypto, wire protocol, and clients are untouched, which
  is exactly the payoff ADR-0003 was built for. The API becomes horizontally
  scalable with no new coordination primitive because optimistic concurrency
  already pushes conflict resolution to the client. Zero-knowledge (ADR-0004) is
  preserved verbatim; the *only* new plaintext the host holds is email + plan, and
  it is quarantined in a separate plane. A free managed tier gives PLG a hook
  1Password structurally cannot match.
- **Negative / cost:** we take on **custodial risk at scale** (a concentrated
  target), **operational burden** (durability, uptime, incident response), and
  the **metadata-leak** residue that no zero-knowledge host fully escapes. Running
  managed Postgres and a control plane is real ongoing cost and a new failure
  surface. A synchronous DB client caps per-pod throughput — acceptable at this
  scale, revisited only if a single pod ever becomes the bottleneck.
- **Gated:** **no paying user before the crypto review passes** (Gate 0). This is
  the one consequence that can stop the roadmap, and it is meant to.
- **Deliberately deferred:** object storage for blobs (Postgres `bytea` is fine at
  tens-of-KB vaults until large scale); async runtime (`tokio`/`sqlx`); the
  control-plane fronting-vs-alongside decision; SOC 2; multi-region.

## Alternatives considered

- **Shared filesystem (NFS/EFS RWX) instead of Postgres.** Would let multiple
  replicas mount `/data` and change the least code. Rejected: the file adapters'
  correctness rests on a *single-process* `Mutex` for read-modify-write; a shared
  filesystem across pods reintroduces exactly the interleaving that mutex prevents
  (no cross-node lock), and it gives us no transactions, no PITR, and no query
  surface for entitlements. Postgres gives atomic version checks, transactional
  invite redemption, backups/PITR, and the account/billing plane in one move.
- **Object storage (S3) for blobs from day one.** The right answer *at large
  scale*, but premature now: vaults are tens of KB, and splitting metadata
  (Postgres) from blobs (S3) buys operational complexity and cross-store
  consistency headaches we don't need yet. Kept as a documented later step behind
  the unchanged `SyncStore` port.
- **Rewrite the server on `tokio` + `sqlx` (async).** Rejected: the server is
  deliberately blocking `tiny_http`; a synchronous pooled client (`r2d2`) fits
  without an async runtime, and horizontal scaling comes from replicas, not from
  async concurrency inside one pod. An async rewrite is cost with no benefit at
  this scale.
- **No free managed tier (pure 1Password model).** Rejected as the packaging:
  1Password's lack of a free tier is precisely the seam we exploit (product-spec
  §2.2, §9). A narrow single-user free managed tier is the PLG on-ramp and the
  household-champion seed; the discipline is keeping it narrow enough not to
  cannibalize paid.
- **Entitlements/billing inside the open server.** Rejected for the open-core
  line: mixing Stripe and multi-tenant entitlement logic into the AGPL server
  muddies what self-hosters get and what the moat is. The control plane stays a
  separate proprietary service; the open server stays the pure data plane.
