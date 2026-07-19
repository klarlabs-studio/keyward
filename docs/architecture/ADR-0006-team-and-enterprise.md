# ADR-0006 — Team & Enterprise trajectory (design-only)

- Status: **Proposed — design-only; not being built yet.** This ADR records the
  shape of a future Team/Enterprise tier and, more importantly, the **seams to
  keep open now** so that shape stays reachable. Nothing here is scheduled.
- Date: 2026-07-18
- Supersedes: none
- Related: [ADR-0003](ADR-0003-ddd-hexagonal-structure.md) (DDD/hexagonal ports),
  [ADR-0004](ADR-0004-family-sharing.md) (sharing crypto, zero-knowledge stance),
  [ADR-0005](ADR-0005-managed-cloud.md) (packaging, custodial threat model,
  roadmap gates), [context-map.md](context-map.md),
  `crates/sync/src/groups.rs` (the `ShareGroup` / `GroupMember` model + port),
  `crates/sync/src/accounts.rs` (the `Plan` entitlements enum),
  `crates/sync-server/src/main.rs` (group + billing endpoints),
  `crates/passbook/src/sharing.rs` (per-recipient X25519 wrapping),
  `app/src/lib/sharing.ts` (the client flow)

## Context

The share-group primitive we built for families is, structurally, most of a team.
That fact is seductive and it is half-true, so it is worth stating precisely what
generalizes and what does not.

**What we have today, in the code:**

- `ShareGroup` (`crates/sync/src/groups.rs`) is a membership directory
  (`Vec<GroupMember>`), a list of `GroupInvite`s (SHA-256 **hashes** of codes,
  TTL'd, single-use), one `wrapped_keys: Vec<u8>` blob with its `keys_version`,
  and one `content: Vec<u8>` blob with its `content_version`. Both blobs are
  opaque to the server, both under `next_version` optimistic concurrency.
- `GroupMember` carries `member_id`, `account_id`, `name`, `public_key`,
  **`is_owner: bool`**, `added_epoch`. The authorization surface on the type is
  exactly `member_by_account`, `is_member`, `is_owner`.
- `crates/passbook/src/sharing.rs` wraps a 32-byte vault key per recipient with
  ephemeral X25519 → HKDF-SHA256 → XChaCha20-Poly1305 (`SharedVault::share_to`,
  `wrap_to`, `unwrap_for`, `grant_access`, `revoke`). Adding the N-th member is
  one more `WrappedKey` entry — **O(N) blob growth, no re-encryption of
  content.** This is why "a team is a share group with more members" is
  genuinely almost free.
- `sync-server` exposes `POST /v1/groups`, `GET /v1/groups/{id}`,
  `POST /{id}/invites`, `POST /{id}/members`, `DELETE /{id}/members/{mid}`, and
  `GET|PUT /{id}/keys` + `GET|PUT /{id}/vault`. Authorization is enforced
  server-side against the directory: member-only for get/invite/blobs,
  **owner-only for member removal** (`handle_group_remove` checks
  `g.is_owner(account)`). There is no endpoint to delete a group.
- Entitlements are a three-value `Plan` enum (`Free` / `Individual` / `Family`)
  with `can_share()` (Family only) and `device_limit()` (`Free → Some(2)`, paid
  → `None`). `POST /v1/groups` is gated on `can_share()` — **creating** a shared
  vault requires the paid plan; joining one does not. Stripe drives `set_plan`
  via a signed webhook; `GET /v1/account` reflects it to the client.
- The client (`app/src/lib/sharing.ts`) keeps a local registry of
  `{groupId, name}` pairs in `localStorage`, one member identity per device, and
  implements revoke-with-rotation: `revokeMember` deletes the directory entry,
  then generates a fresh vault key, re-wraps to the remaining members, re-seals
  the content, and pushes both blobs.

**What therefore generalizes almost for free:** more members. The crypto, the
relay, the invite protocol, the optimistic-concurrency contract, and the
zero-knowledge property are all indifferent to whether the group has 4 people or
40.

**What does not generalize at all:**

1. `is_owner: bool` is a two-valued permission model. Teams need at least three
   roles and a real permission matrix.
2. A group owns **exactly one** vault — one `wrapped_keys` set, one `content`
   blob. Teams need N vaults with **different member subsets** (engineering ≠
   finance). This is the largest deferred piece and the one with schema and URL
   consequences.
3. Identity is a device bearer token minted by `register` / `add_device`. There
   is no IdP, no SAML assertion, no SCIM directory, no concept of an
   organization that owns accounts.
4. **Deprovisioning is a cryptographic operation, not a database delete.**
   Because access is a per-member wrapped key, removing a member requires
   rotating the vault key and re-wrapping — and rotation requires *a device that
   currently holds the key*. Automated deprovisioning collides head-on with
   zero-knowledge.
5. Recovery. A family's answer is "ask your sister." An enterprise's answer must
   be "the admin can get the finance vault back after the CFO leaves," and there
   is no honest way to give that answer without a customer-held key.
6. Audit. `sync-server` today logs to `eprintln!` — operational logs, not an
   audit trail, and certainly not a non-forgeable one.
7. Billing. `Plan` is per-account and flat-rate. Teams are per-seat, prorated,
   and (at the top) invoiced.

The recommendation this ADR makes is therefore: **design the seams now, build
later.** Concretely — do the cheap, reversible things in today's schema and API
that keep multi-vault, multi-role, org-owned membership reachable, and defer
every expensive thing until B2C family sharing is validated and ADR-0005's
Gate 0 (formal external crypto review) has passed.

## Decision

### 1. Roles & permissions — replace `is_owner: bool` with a `Role` enum

*(Landing now, in parallel, as v1.37.0 — recorded here for completeness because
everything below depends on it. The depth in this ADR is deliberately spent on
§2 onward.)*

`GroupMember.is_owner: bool` becomes:

```rust
pub enum Role { Owner, Admin, Member }   // Guest added later (§1.3)
```

serialized as a **lowercase string** (`"owner"` / `"admin"` / `"member"`),
parsed permissively with an unknown value falling back to the least-privileged
role — the same pattern `Plan::parse` already uses. `is_owner()` is kept as a
derived helper (`role == Role::Owner`) so existing call sites and the
`is_owner` field in `GroupMemberView` on the client keep working during the
transition.

**Permission matrix** (server-enforced against the directory, exactly where
`handle_group_remove` enforces owner-only today):

| Operation | Owner | Admin | Member | Guest (later) |
|---|:--:|:--:|:--:|:--:|
| Create group / team | ✅ (becomes Owner) | — | — | — |
| Delete group | ✅ | ❌ | ❌ | ❌ |
| Invite a new member | ✅ | ✅ | ❌ ¹ | ❌ |
| Remove a member | ✅ | ✅ ² | ❌ | ❌ |
| Change a member's role | ✅ | ✅ ² | ❌ | ❌ |
| Transfer ownership | ✅ | ❌ | ❌ | ❌ |
| Read vault content | ✅ | ✅ ³ | ✅ | ✅ (scoped items only) |
| Write vault content | ✅ | ✅ ³ | ✅ | ❌ |
| Create / delete a vault (§2) | ✅ | ✅ | ❌ | ❌ |
| Grant vault access (wrap key to a member) | ✅ | ✅ | ❌ ⁴ | ❌ |
| Rotate a vault key | ✅ | ✅ | ❌ ⁴ | ❌ |
| Manage billing / seats | ✅ | ❌ ⁵ | ❌ | ❌ |

¹ Today **any member** may mint an invite (`handle_group_invite` checks only
`g.is_member`). Tightening this to Owner/Admin is a deliberate behavior change
for teams; families may keep the looser rule, and that difference is itself an
argument for the plan-aware policy in §6.

² An Admin must not be able to remove or demote an Owner. Enforce
`actor.role > target.role` (with Owner strictly greatest) plus a **last-Owner
invariant**: the final Owner can neither be removed nor demoted.

³ An Admin who is not a member of a given vault's subset (§2) can administer
membership without holding that vault's key. **This is a genuine and desirable
property** — org administration and cryptographic access are separable. It is
also the reason §7's admin-abuse mitigation matters: an Admin can *grant
themselves* a wrap, but only with the cooperation of someone who already holds
the key, and the act is auditable.

⁴ Cryptographic grant/rotate is bounded by physics, not policy: only a principal
who can `unwrap_for` themselves can `grant_access` to anyone else
(`SharedVault::grant_access` unwraps first, then wraps). The server can *refuse*
a `PUT /keys` from an under-privileged member, but it can never *perform* the
grant. Server-side role checks on `/keys` are an integrity guard, not the
mechanism.

⁵ Billing lives in the proprietary control plane (ADR-0005 §"Open-core
boundary"), so "manage billing" is a control-plane role, not a data-plane one.
It is listed here only to name the boundary.

**Guest** is deliberately later. A Guest is not "a Member with fewer rights over
the same vault" — it is read access to *specific items*, which requires either a
per-item key (a second layer of wrapping below the vault key) or a
single-item micro-vault. The micro-vault framing reuses §2 exactly and is the
cheaper path; per-item keys are a genuinely new crypto surface and would need
their own review. Do not conflate the two.

### 2. Per-vault access (multi-vault teams) — the big deferred piece

**Today:** one group ⇒ one vault. `ShareGroup` holds a single `wrapped_keys` /
`keys_version` pair and a single `content` / `content_version` pair, addressed
at `/v1/groups/{id}/keys` and `/v1/groups/{id}/vault`. Every member of the
directory is, modulo whether someone has wrapped to them yet, a member of the
one vault.

**Teams need:** an org with N vaults, each with

- its own random 32-byte vault key (`sharing::new_vault_key()`),
- its own `SharedVault` (per-member wrapped-key set),
- its own content blob and its own version counter,
- and crucially **its own member subset** — the engineering vault is wrapped to
  the engineering subset only, the finance vault to finance only. The org
  directory is the union; each vault's recipient list is a subset of it.

The subset is not enforced by the crypto alone (the crypto enforces it
perfectly — no wrap, no access) but must also be reflected in the server's
authorization so a non-member of a vault cannot even *fetch* its ciphertext.
Fetching ciphertext you cannot open is harmless to confidentiality but is a
metadata leak and an unnecessary attack surface.

**Schema sketch.** Split the two blobs out of the group row into a child table
keyed by `(group_id, vault_id)`:

```sql
CREATE TABLE group_vaults (
  group_id        TEXT   NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
  vault_id        TEXT   NOT NULL,          -- 'default' for a migrated family vault
  name            TEXT   NOT NULL DEFAULT '',
  wrapped_keys    BYTEA  NOT NULL DEFAULT '',
  keys_version    BIGINT NOT NULL DEFAULT 0,
  content         BYTEA  NOT NULL DEFAULT '',
  content_version BIGINT NOT NULL DEFAULT 0,
  created_epoch   BIGINT NOT NULL,
  PRIMARY KEY (group_id, vault_id)
);

-- The per-vault member subset. Absent row = no access to that vault.
CREATE TABLE group_vault_members (
  group_id   TEXT NOT NULL,
  vault_id   TEXT NOT NULL,
  member_id  TEXT NOT NULL,
  added_epoch BIGINT NOT NULL,
  PRIMARY KEY (group_id, vault_id, member_id),
  FOREIGN KEY (group_id, vault_id) REFERENCES group_vaults(group_id, vault_id)
    ON DELETE CASCADE
);
```

Note `group_vault_members` is the *authorization* record; the *cryptographic*
record is which `member_id`s appear in that vault's `SharedVault.wrapped`. These
two must be reconciled, and the client already knows how — `loadFamily`'s
auto-reconcile loop (directory members lacking a wrap get one from whoever is
online and holds the key) generalizes directly, scoped to a vault's subset
instead of the whole directory.

**Endpoint shape.** Add a vault segment, keeping the existing verbs and the
`If-Match` / `X-Vault-Version` contract verbatim:

```
GET    /v1/groups/{id}/vaults                       list vaults I can see
POST   /v1/groups/{id}/vaults                       create a vault (Owner/Admin)
DELETE /v1/groups/{id}/vaults/{vid}                 delete a vault (Owner/Admin)
GET    /v1/groups/{id}/vaults/{vid}/keys            wrapped keys  (+ X-Vault-Version)
PUT    /v1/groups/{id}/vaults/{vid}/keys            (If-Match)
GET    /v1/groups/{id}/vaults/{vid}/content         content blob  (+ X-Vault-Version)
PUT    /v1/groups/{id}/vaults/{vid}/content         (If-Match)
POST   /v1/groups/{id}/vaults/{vid}/members         add member to the vault subset
DELETE /v1/groups/{id}/vaults/{vid}/members/{mid}   remove from the subset (⇒ rotate)
```

`handle_groups`' dispatcher already splits the path into segments and matches on
`(segs.as_slice(), &method)`, so `([id, "vaults", vid, "keys"], _)` is a
mechanical addition, not a restructure.

**Migration path from today's single-vault group.** Treat the existing blobs as
**vault id `default`**:

1. The Postgres migration inserts one `group_vaults` row per existing group with
   `vault_id = 'default'`, copying `wrapped_keys`/`keys_version`/
   `content`/`content_version` across verbatim. No re-encryption, no key change,
   no client involvement — the ciphertext is copied byte-for-byte.
2. Every existing directory member gets a `group_vault_members` row for
   `default`, preserving today's "directory member ⇒ vault member" semantics.
3. **Keep `/v1/groups/{id}/keys` and `/v1/groups/{id}/vault` as permanent
   aliases** for `.../vaults/default/keys` and `.../vaults/default/content`.
   Shipped clients (`app/src/lib/sharing.ts` hardcodes both paths) keep working
   with no forced upgrade; new clients use the explicit form. Note the small
   naming wart to absorb: the singular alias is `/vault`, the new nested resource
   is `/content` — do not rename the alias.
4. `ShareGroupStore`'s `put_keys` / `put_content` / a new `list_vaults` gain a
   `vault_id: &str` parameter; the trait stays the port, the file and memory
   adapters keep working by defaulting to `"default"`. Per ADR-0003, this is an
   adapter-level change, not a domain rewrite.

**Cost note.** Rotation cost is per-vault and proportional to the vault's subset
size, not the org size — which is precisely why the subset model is worth the
schema complexity. In a single-vault-per-org design, every departure would
re-wrap to the whole company.

### 3. Identity — SSO/SAML and SCIM

**How an IdP identity maps onto what exists.** The account/device-token model
(`AccountStore::register` → one-time token, `add_device` → more tokens,
`resolve_token` → `TokenIdentity{account_id, device_id}`) is a *device
credential* model. An IdP gives us a *human* assertion. They meet at exactly one
place: the SAML/OIDC assertion, once verified, authorizes **minting a device
token** for the account the IdP identity maps to. Everything downstream —
`resolve_token`, group membership checks, the blob handlers — is unchanged.

That means SSO needs only:

- an `org_id` on the account record (nullable; `None` = an ordinary consumer
  account), so accounts can be *owned* by an org;
- an `external_id` (the IdP's stable subject identifier — **not** the email,
  which changes) on the account record, unique per org;
- an SSO endpoint in the **control plane** (ADR-0005: proprietary, and this is
  squarely control-plane work) that verifies the assertion and calls the data
  plane's device-minting path.

**The seam to keep open now:** a nullable `org_id` and a nullable `external_id`
column on the account record, and the discipline that **nothing joins on
email**. Email is already optional on `AccountRecord`; do not let it become an
identity key.

**Deprovisioning is the hard part.** SCIM's `DELETE /Users/{id}` means "this
person is gone, now." In our model that must do three things:

1. Revoke every device token for the account (`revoke_device` per device —
   already exists, and it is the only step that is purely a database write).
2. Remove the member from the org directory and from every
   `group_vault_members` subset.
3. **Rotate the vault key of every vault they had access to, and re-wrap to the
   remaining subset.** Without step 3 the offboarded employee retains a key they
   already read; steps 1 and 2 only stop them from *fetching new ciphertext from
   us*. If they kept a copy of the ciphertext, or if they can obtain it by any
   other means, an un-rotated key still opens it. We already do exactly this for
   family revoke (`revokeMember` in `app/src/lib/sharing.ts`), and ADR-0004 §5
   already states the residual "they keep what they already read" caveat.

**The genuine design problem: rotation needs an online member who holds the
key.** The server cannot rotate — it has no key, by construction, and giving it
one would end the zero-knowledge property. So an automated, server-initiated
SCIM deprovision cannot complete synchronously. The honest design:

- The SCIM handler performs steps 1 and 2 immediately and atomically, then sets
  a **`rotation_required` flag** (with a timestamp and the triggering event) on
  each affected `group_vaults` row. This is metadata; the server may write it.
- Every client that opens a vault checks the flag. **The first
  Owner/Admin online who holds that vault's key performs the rotation** — fresh
  key, re-wrap to the remaining subset, re-seal content, `PUT` both blobs with
  `If-Match`, clear the flag. This is the same code path as `revokeMember`,
  driven by a flag instead of a button.
- The flag is **surfaced, loudly and honestly**: the org admin console must show
  "3 vaults awaiting key rotation since <date>" with the plain-language
  explanation. Silence here would be a lie about the security state.
- The window between deprovision and rotation is a real, non-zero exposure and
  must be documented as such — including in the SOC 2 narrative, where "we
  cannot rotate without a member device" is a control description, not a
  weakness to hide.
- **Do not** attempt to close the window with a server-held key, a "rotation
  service account," or an escrow the server can open. Each of those turns the
  zero-knowledge claim into marketing. If a customer's compliance regime demands
  instant cryptographic revocation with no member device involved, the honest
  answer is that our architecture does not offer it, and why.

A partial mitigation worth designing for: nominate one or more **rotation
agents** — designated admin devices that are expected to be online and that
poll for `rotation_required`. This shortens the window without changing the
trust model. It does not eliminate it, and should not be described as if it
does.

### 4. Recovery / break-glass vs. zero-knowledge

Consumer recovery is a social protocol: any current member can recover the vault
key (they unwrap their own copy) and re-wrap it to a new member — this is
`SharedVault::grant_access`, and ADR-0004 §2 already accepts that a member who
loses both device and vault is simply re-invited as a new member.

Enterprises will not accept that. The demand is explicit and non-negotiable in
procurement: *an admin must be able to recover a departed employee's vault.*
State the tension plainly rather than papering over it.

**The line, stated as a rule:** any scheme where **the server can unilaterally
recover plaintext breaks the zero-knowledge promise and must not be built.** Not
behind a feature flag, not "only for Enterprise," not "only with two operator
approvals." The claim we sell — a breach of us yields only ciphertext — is
either true for every tier or it is false. A server-openable escrow makes it
false for everyone, because no customer can verify which code path their data
took.

**The honest option: an org recovery keypair, customer-held.**

- At org creation the admin generates an **org recovery keypair** (X25519, the
  same primitive `sharing.rs` already uses). The **public** half is registered
  with the org; the **private** half is exported once, to the customer, as an
  Emergency-Kit-style artifact — printed, put in a safe, split with Shamir among
  officers, or loaded into the customer's own HSM. **We never hold it.** The
  server stores the public key and nothing else.
- Every org vault wraps its key to the recovery public key as **one additional
  recipient** in the existing `SharedVault`. Mechanically this is
  `wrap_to(vault_key, recovery_public)` — no new crypto, one more `WrappedKey`
  entry, and it composes with rotation for free (a rotation re-wraps to the
  subset *plus* the recovery key).
- Break-glass = the customer physically retrieves the private half and unwraps.
  It is deliberately slow, deliberately physical, and deliberately auditable.

**Trade-offs, documented rather than minimized:**

- The recovery key is a **standing skeleton key for the whole org**. If it is
  stolen, every vault it is wrapped to is compromised — and it is wrapped to all
  of them. Its custody is the customer's single most important security
  decision, and our documentation must say so in those words.
- Losing it means losing the break-glass path (though not day-to-day access,
  which still flows through members' own wraps). Some customers will lose it.
- Employees must be **told** the recovery key exists, because "my work vault is
  private from my employer" would otherwise be a reasonable and false
  assumption. Per-vault opt-out (a vault created with no recovery recipient)
  should be supported for genuinely personal work vaults, and its consequence —
  unrecoverable if the sole member leaves — stated at creation.
- Wrapping to the recovery key must be **per-vault and visible in the UI**: a
  member of a vault should be able to see that a recovery recipient is present.
  A hidden extra recipient in a `SharedVault` is indistinguishable, to a user,
  from a backdoor.

An alternative worth considering but not deciding here: **M-of-N admin escrow**,
where the vault key is Shamir-split across admin devices so recovery needs a
quorum rather than one artifact. It removes the single skeleton key and gives a
better audit story, at the cost of significantly more client-side machinery and
a much larger review surface. It is a candidate refinement *after* the crypto
review, not a shortcut around it.

### 5. Audit log

`sync-server` today emits `eprintln!` operational lines
(`"POST /v1/groups -> 200 group=… owner_account=…"`). Useful for debugging;
worthless as evidence. A team tier needs a real audit log.

**What is recorded** (metadata plane only — never content, never key material):

- membership: invited, joined, removed, role changed, ownership transferred;
- vault lifecycle: vault created, deleted, member added to / removed from a
  vault subset;
- key lifecycle: key rotated, `rotation_required` set and cleared, recovery
  recipient added or removed;
- access: device token minted, rotated, revoked; SSO login; SCIM
  provision/deprovision;
- billing/seat changes (from the control plane).

Each entry: `{org_id, actor_member_id, actor_device_id, action, target,
vault_id?, timestamp, prev_hash}`.

**Member-signed where possible.** The server is not trusted for confidentiality,
so it should not be trusted for the audit trail either. For actions a member's
device performs (grant, rotate, role change, removal), the device signs the
canonical entry with a key bound to its member identity, and the server stores
the signature alongside. A verifier with the member directory can then check
that the server did not forge or omit entries — omission is caught by chaining
each entry to `prev_hash` of the previous one, so a deletion breaks the chain.
Server-originated entries (SCIM, billing) cannot be member-signed and must be
**marked as server-attested**, a strictly weaker class. Do not present the two
as equivalent. This directly discharges the "Repudiation" row that ADR-0004 and
ADR-0005 both left as "a later increment."

**Retention and export.** Configurable retention with a floor (SOC 2 evidence
periods typically want a year); export as JSON and CSV; a streaming/webhook
option for customers who forward to their own SIEM. Export is the feature that
actually gets bought — an audit log you cannot get out of the vendor is not an
audit log to a compliance team.

**SOC 2 tie-in.** The log is the evidence for the access-control and
change-management criteria: who had access to what, when it was granted, when it
was revoked, and that revocation actually happened (the rotation entries are the
proof). Design it *as evidence*, with the auditor as a named consumer, or it
will be rebuilt during the audit.

### 6. Billing — extend `Plan` with Team and Enterprise

```rust
pub enum Plan { Free, Individual, Family, Team, Enterprise }
```

`Plan::parse` already falls back to `Free` on anything unrecognized, and
`AccountRecord.plan` is `#[serde(default)]`, so **adding variants is backward
compatible for stored data by construction.** The work is in the entitlement
methods, which today are `can_share()` (Family only) and `device_limit()`
(`Free → Some(2)`, else `None`).

The generalization: `can_share()` is a boolean where teams need a *shape*. Grow
the entitlement surface rather than bolting on booleans:

- `can_share()` → true for `Family | Team | Enterprise`.
- `device_limit()` → unchanged for existing tiers; unlimited for Team/Enterprise.
- `max_seats() -> Option<usize>` — `Family → Some(6)`-ish (ADR-0005's "5–6"
  placeholder), Team/Enterprise → driven by the purchased seat count, not a
  constant.
- `max_vaults() -> Option<usize>` — `Family → Some(1)` (today's reality, now
  explicit), Team/Enterprise → unlimited or plan-driven.
- `can_sso()`, `can_scim()`, `can_audit_export()`, `can_org_recovery()` — the
  enterprise gates.

Note that `Plan` currently lives on the **account**, and Team/Enterprise
entitlements are properties of the **org**. The clean resolution: the plan moves
to the org for org-owned accounts, and a member's effective entitlements are
`max(own account plan, org plan)`. This mirrors the rule already in the code —
`handle_group_create` gates on the *creator's* `can_share()` while joiners need
no plan of their own ("the owner's plan covers them"). Teams are the same rule
with a directory instead of a single owner.

**Per-seat pricing with proration.** Stripe handles this natively via
subscription quantity: a seat change is a quantity update, and Stripe computes
proration. The current checkout call hardcodes `line_items[0][quantity] = "1"`
and a single `price_family`; per-seat means quantity tracks the seat count and
the price id is the team price. **No prices are proposed here** — ADR-0005
deliberately leaves them as placeholders and this ADR does not change that.

**Seat counting must be tied to the member directory**, and the binding must be
explicit about which direction wins:

- A seat is consumed by an **account in the org directory**, not by a device and
  not by a vault membership. One person on four devices and six vaults is one
  seat.
- **Invites count against seats when minted**, not when redeemed — otherwise a
  team mints unlimited invites and over-provisions at redemption time. Expired
  and revoked invites release the seat.
- Adding a member beyond the purchased seat count should **fail closed** with a
  clear, actionable error (the shape already used for the device cap and the
  402 on `POST /v1/groups`), not silently auto-upgrade the subscription. Silent
  auto-upgrade is a billing surprise, and billing surprises are a support and
  trust cost far larger than the friction they avoid.
- Removing a member frees the seat but must **not** auto-downgrade the
  subscription; downgrades are an explicit admin action, because a removal is
  often a prelude to a replacement hire.

**Invoicing / PO for Enterprise.** Above some size, procurement will not use a
credit card: annual invoicing, purchase orders, net-30/60 terms, W-9s, security
questionnaires, and a signed MSA/DPA. Stripe Invoicing covers the mechanics; the
organizational cost is the part to plan for. This is control-plane work
(ADR-0005 keeps billing proprietary and out of the AGPL server) and it is where
enterprise sales starts consuming engineering time that is not engineering — see
§9.

### 7. Threat-model deltas for multi-tenant orgs

These are *deltas* on top of ADR-0004's relay model and ADR-0005's custodial
model, not a replacement.

| Threat | Vector | Mitigation |
|---|---|---|
| **Cross-tenant isolation** | A bug or crafted request lets org A read org B's directory, vault list, or ciphertext | Every query is scoped by `org_id` / `group_id` at the store layer, never by a client-supplied identifier alone; the existing pattern — resolve the token to an `account_id`, then check membership *server-side against the directory* — must extend to `(group_id, vault_id)` for every blob route. Add explicit cross-tenant negative tests as a standing suite; this is the class of bug that ends a B2B company. Note the crypto is a second line of defense here: cross-tenant *ciphertext* leakage is not plaintext leakage. |
| **Admin abuse** | An Admin adds themselves to the finance vault's subset and has a member wrap the key to them | Cannot be prevented cryptographically — an org that grants administrative power grants it. Mitigate with **detection**: every grant, subset change, and role change is an audit entry (§5), and **members of a vault are notified out-of-band when a new recipient is added to it**. Notification is the control that makes silent self-grant impossible. Additionally: an Admin cannot grant themselves access to a vault where **no current member cooperates**, since the server holds no key — self-service admin access to an arbitrary vault is structurally impossible unless the org recovery key (§4) is used, which is itself a loud, audited event. |
| **Insider / operator risk (us)** | A Keyward operator reads the metadata plane, or a compromised control-plane credential manipulates entitlements or the directory | Plaintext remains out of reach (ADR-0005). New for orgs: the **org chart is now the metadata** — who works where, who has access to what, when people join and leave. Least-privilege DB roles, plane separation, no standing prod access, and operator-access auditing (ADR-0005 Operations) all apply, and the sensitivity of what leaks is higher. A malicious server substituting a directory entry (ADR-0004's open key-substitution item) is *more* dangerous in an org, where nobody personally knows all 200 members and out-of-band safety-number verification does not scale socially. **Member-signed directory entries move from "nice to have" to required for Team.** |
| **Blast radius** | A breached or coerced org account | A family is 4 people's personal logins. An org is production credentials, cloud root accounts, and payment systems for an entire company — and it is a *known, named* target rather than an anonymous one. The same architecture defends both, but the attacker's motivation, budget, and patience are different by orders of magnitude. This is the strongest argument for §9's sequencing: do not accept this blast radius before the crypto is reviewed. |
| **Supply chain into a customer** | We become a vendor inside a customer's trust boundary | Their auditors become our auditors. SBOM, digest-pinned images, signed releases, a published vulnerability-disclosure policy, and a contractual breach-notification SLA all become table stakes rather than good practice. |

### 8. What to keep flexible NOW — the most valuable section

These are cheap, reversible things to do (or avoid) in today's code so that
Team, if we ever build it, is additive rather than a migration. Each is a small
decision that becomes expensive to reverse once data exists.

**Do:**

1. **Role as a string column, not a bool.** Persist `role` as text with a
   permissive parser that falls back to the least privilege — mirroring
   `Plan::parse`. A `BOOLEAN is_owner` column costs a data migration *and* a
   coordinated client rollout to become a three-valued enum; a text column costs
   nothing. *(Landing in v1.37.0.)*
2. **Make `vault_id` addressable from the start, even with one vault.** Add the
   `group_vaults` table in the first Postgres migration with `vault_id` in the
   primary key and a single `'default'` row per group, rather than columns on
   the group row. Same behavior today, no table split later. Keep
   `/v1/groups/{id}/keys|vault` as aliases forever.
3. **Keep `org_id` and `external_id` nullable on the account record.** Two
   nullable columns now; adding an ownership concept to a populated accounts
   table later is a genuinely painful migration.
4. **Keep the entitlements plane a *derived* surface.** `GET /v1/account`
   already returns `can_share` and `device_limit` as **computed values** rather
   than making the client interpret the plan name. Keep that discipline for
   every new entitlement — the client should never branch on `plan == "family"`.
   Adding `Team` then changes one server-side match arm and no client code.
5. **Version every new endpoint under `/v1` and add capabilities additively.**
   Prefer a new path segment over changing an existing response shape. If a
   response must grow, add fields; shipped clients ignore unknown fields, and
   the ones already in the wild cannot be forced to upgrade.
6. **Keep the `ShareGroupStore` port the only way to touch group state.** The
   per-vault change (§2) is tractable precisely because there is one trait to
   change and two adapters behind it (ADR-0003's payoff, restated by ADR-0005).
   Any handler that reaches around the port turns a signature change into an
   archaeology exercise.
7. **Write the audit-relevant events through one function today**, even if that
   function currently only calls `eprintln!`. Retrofitting call sites is the
   expensive part of an audit log; the storage is easy.

**Avoid:**

8. **Do not assume one vault per group in client storage.** `sharing.ts` stores
   `GroupRef { groupId, name }` in `localStorage` and derives everything else
   per group. The minimal change is to make the local model a *list of vaults
   per group* (`{ groupId, name, vaults: [{ vaultId, name }] }`) with a single
   `default` entry today. Serialized client state is the hardest thing to
   migrate — there is no `ALTER TABLE` for a million browsers' `localStorage`,
   and every shape you ship must be readable forever. If only one item on this
   list gets done, make it this one.
9. **Do not key anything on email.** Not membership, not identity, not
   directory lookup. `AccountRecord.email` is optional contact metadata and must
   stay that way; SSO will supply a stable `external_id` and emails change.
10. **Do not let `is_owner`/`role` leak into the crypto layer.**
    `crates/passbook/src/sharing.rs` knows only recipients and keys, and that is
    correct. Roles are an authorization concept enforced by the server and the
    UI; the crypto must stay role-agnostic so a policy change never requires a
    re-wrap, and so a compromised server cannot fabricate access by fabricating a
    role.
11. **Do not build a server-side "group admin" bypass** of any kind — no
    server-held key, no "support can read a vault" path, not even disabled. The
    absence of that code is a reviewable property; a disabled feature flag is
    not.
12. **Do not widen the invite rule silently.** Any member can currently mint an
    invite. Whatever the team policy becomes, make it an explicit, tested
    server-side check keyed on role, not an accident of the current handler.

### 9. Sequencing and gates

**Do not build Team or Enterprise before all of these are true:**

- **Gate A — B2C validation.** Family sharing is shipped, used, and shown to
  work: real families completing invite → grant → read → revoke-with-rotation
  without support intervention. The multi-vault, multi-role design above is a
  bet on a primitive whose consumer form is not yet proven. Building the
  enterprise elaboration of an unvalidated primitive means rebuilding both.
- **Gate B — formal external crypto review** (ADR-0005's Gate 0, which already
  blocks any paying user). For enterprise this is doubly binding: **you cannot
  sell enterprise on unreviewed crypto.** The first serious security
  questionnaire asks who reviewed it and when, and "nobody yet" ends the
  conversation. The review must also close ADR-0004's key-substitution /
  directory-trust open item, which §7 argues is *more* severe at org scale.
- **Gate C — SOC 2 readiness.** Not the certificate necessarily, but the
  controls, the audit log (§5), the evidence pipeline, and a Type I in progress.
  Enterprise procurement gates on it, and retrofitting controls onto a live
  multi-tenant system is far more expensive than designing them in — which is
  exactly what §5 and §8.7 are for.

**And go in knowing enterprise sales pulls the roadmap hard.** This is not a
caution about effort; it is a caution about *direction*. The moment there is a
pipeline, the backlog reorders itself around SSO, SCIM, audit exports, custom
retention, security questionnaires, penetration-test reports, DPAs, uptime SLAs,
procurement calls, and one-off requests from the largest prospect. Each is
reasonable in isolation. Together they are a different company from the one that
ships a consumer password manager with an AI credential broker, and the consumer
product **will** stall — not because anyone decided to stall it, but because
nobody has time.

The recommendation therefore stands: **design the seams now (§8, which is nearly
free), build later, and only after Gates A, B, and C.**

## Consequences

- **Positive:** the expensive parts of Team are made *reachable* at near-zero
  cost today — a string role column, a `vault_id` in a primary key, two nullable
  account columns, one audit-event function, and a client storage shape that
  does not assume one vault per group. Each is a decision we would otherwise
  make accidentally and wrongly. Naming the multi-vault design now also
  clarifies what family sharing deliberately is *not* doing, which keeps the
  consumer feature small.
- **Negative:** this is a design document for something we are not building, and
  such documents rot. It should be re-read (and probably substantially rewritten)
  whenever Team actually starts, and treated as archaeology rather than
  specification if that is more than a year out.
- **Named honestly:** SCIM deprovisioning cannot be made instantaneous without
  breaking zero-knowledge (§3), and enterprise recovery cannot be made
  server-side without breaking it (§4). Both are real limits of the
  architecture, and both must be stated in sales and documentation rather than
  discovered by a customer. If a segment of the enterprise market requires
  either, that segment is not addressable by this product, and that is an
  acceptable answer.
- **Gated:** nothing in §§1–7 is scheduled. Only §8 is actionable now, and §1 is
  already landing independently.

## Alternatives considered

- **Treat a Team as literally "a Family with a higher seat cap."** Ship
  Team by raising `max_seats()` and doing nothing else. Tempting because it is
  nearly free and would produce revenue quickly. Rejected: without per-vault
  subsets, every team member sees every credential, which is disqualifying for
  any org with a finance or production-access vault; and without deprovisioning
  rotation, an offboarded employee retains access — a security failure we would
  be selling, not merely permitting. A team tier that quietly under-delivers on
  access control is worse than no team tier.
- **A separate `Team` aggregate parallel to `ShareGroup`.** A clean model
  unpolluted by family assumptions. Rejected: it forks the crypto path, the
  relay, the invite protocol, and the client — two implementations of the same
  zero-knowledge machinery, each needing its own review. The share group *is*
  the right primitive; it needs roles and a vault dimension, not a sibling.
- **Server-side key escrow for enterprise recovery.** The feature enterprises
  actually ask for. Rejected outright, per §4: it makes the zero-knowledge claim
  false for every customer, since none can verify which path their data took. The
  customer-held org recovery keypair delivers the recovery capability without
  moving the trust boundary.
- **Per-item keys for Guest access (instead of single-item micro-vaults).** More
  flexible and closer to what a UI would want. Deferred: it adds a second
  wrapping layer beneath the vault key and a new crypto surface requiring its own
  review, where a micro-vault reuses §2's machinery exactly. Revisit only after
  the multi-vault model is real and reviewed.
- **Build Team first and let enterprise revenue fund the consumer product.** The
  standard rationalization. Rejected on §9's reasoning: it inverts the sequencing
  gates, commits us to a blast radius before the crypto review, and converts the
  roadmap into a procurement queue at exactly the moment the consumer wedge needs
  focus.
