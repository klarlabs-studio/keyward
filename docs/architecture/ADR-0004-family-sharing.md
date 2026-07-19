# ADR-0004 — Family sharing (wiring the sharing engine into a real feature)

- Status: Proposed — implementation in progress (server relay first)
- Date: 2026-07-17
- Supersedes: none
- Related: [ADR-0003](ADR-0003-ddd-hexagonal-structure.md) (DDD/hexagonal),
  [context-map.md](context-map.md), [ubiquitous-language.md](ubiquitous-language.md),
  `crates/passbook/src/sharing.rs` (the engine), `crates/sync-server` (the relay)

## Context

Family sharing is the product's flagship B2C wedge, but today it is **a tested
cryptographic library wired to nothing**:

- `crates/passbook/src/sharing.rs` implements per-recipient sealed-box key
  wrapping (ephemeral X25519 → HKDF-SHA256 → XChaCha20-Poly1305) with
  `share_to` / `unwrap_for` / `grant_access` / `revoke`, all unit-tested. Its own
  header flags it as *"prototype crypto of the shape — needs a formal review
  before real use."* It is not re-exported, not called by the CLI, WASM, MCP, or
  Tauri, and is unknown to the sync server.
- The sync server is **single-account**: one opaque sealed blob per account,
  multiple *devices* for the *same* account, no notion of a second person.
- The Vue app shows only static "Family vault" / "FAMILY" labels; the one
  interactive share affordance was mock data and was deleted in v1.26.0.
- Crucially, the vault content is sealed **directly** with the account key
  `K_acct = SHA256(argon2id(master) || secret_key)` (see `sealing.rs::derive_key`).
  There is no random vault key to hand to a second person, so the current sealing
  model **cannot** be shared as-is.

This ADR pins the architecture so the remaining wiring can be built in reviewed
increments without a subtle mistake that would leak a family's vault.

## Decision

### 1. Vault-key indirection (the enabling change)

Introduce a random 256-bit **vault key** `K_vault` that actually encrypts the
vault content. `K_vault` is then wrapped once per member:

```
content         := XChaCha20-Poly1305(K_vault, plaintext)     # the sealed blob
owner's wrap     := seal(K_vault) under K_acct                 # owner keeps access
member_i's wrap  := SharedVault.wrap_to(K_vault, MemberPublic_i)  # X25519 sealed-box
```

- **Personal (unshared) vaults are unchanged.** The existing direct-sealed format
  (`SealedVault { salt, secret_key_protected, ciphertext }`) stays valid and is
  the default. Indirection is introduced **lazily on first share**: converting a
  personal vault to a shared one re-seals the content under a fresh `K_vault` and
  writes the owner's wrap. A version tag on the sealed envelope distinguishes the
  two formats so old vaults keep opening.
- Unlock for a member becomes: derive personal key → decrypt *your* wrap of
  `K_vault` → decrypt content. For the owner the "wrap" is `K_acct`-sealed; for an
  invited member it is their `SharedVault` entry.

> **Implementation refinement (v1.29.0).** The client crypto landed *without*
> touching the personal-vault format at all — a strictly better outcome than the
> "lazy migration" sketched above. The **owner is simply member #0** of the
> `SharedVault`, so *everyone* (owner included) recovers `K_vault` from their own
> X25519 wrap; there is no separate `K_acct`-wrap of `K_vault`. The shared
> **content** is a standalone `sharing::ContentBlob` sealed directly under
> `K_vault` (what the group relay's `/vault` stores), and each member's X25519
> **secret** rides as ordinary encrypted data *inside their existing personal
> vault*. Net: the personal `SealedVault` is byte-for-byte unchanged, no
> migration path is needed, and sharing is a fully separate keyed blob.

### 2. Member identity = a stable, per-account X25519 keypair

Each account gets a random X25519 **member keypair** generated once and stored as
an encrypted field **inside its own vault**. Only `MemberPublic { id, name,
public_key }` is ever published to a group.

Rationale: storing the secret in the vault (rather than deriving it from
`master || secret_key`) **decouples member identity from the master password**, so
a password change re-seals the vault but does not invalidate every wrap other
members made to you. This mirrors per-user keypairs in mature designs. Trade-off:
identity recovery requires the vault (which, in cloud mode, the server holds as
ciphertext); a member who loses both device and vault is re-invited as a new
member — the same UX as a lost device today.

### 3. Server relay — a zero-knowledge share group

Add a **share group** resource to the sync server. It is still zero-knowledge: the
server stores only public keys, wrapped keys (ciphertext to it), the opaque
content blob, and invite tokens (hashed). It never sees `K_vault`, any master
password, or any Secret Key.

```
POST   /v1/groups                      create a group (owner)            -> {group_id}
GET    /v1/groups/{id}                  members + SharedVault + version   (member)
POST   /v1/groups/{id}/invites          mint an invite (owner/member)    -> {invite_code}
POST   /v1/groups/{id}/members          redeem invite: publish MemberPublic (invitee)
PUT    /v1/groups/{id}/keys             upload updated SharedVault (wraps)  (member)
DELETE /v1/groups/{id}/members/{mid}    revoke a member                  (owner)
GET    /v1/groups/{id}/vault            shared content blob (+ version)   (member)
PUT    /v1/groups/{id}/vault            push shared content blob (If-Match)(member)
```

Auth reuses the existing per-device bearer tokens; group membership is checked
against the published `MemberPublic` directory. Optimistic concurrency (`If-Match`
+ version) matches the personal-vault path.

### 4. Invite / accept protocol (cloud-mediated)

1. **Owner** creates a group (its content is `K_vault`-sealed) and mints an invite
   → a short out-of-band **invite code** (server stores only its hash + a TTL).
2. **Invitee** redeems the code by publishing their `MemberPublic` to the group.
   The code proves the invitee was authorized; it carries no key material.
3. An **existing member** (owner or any member) calls `grant_access` locally to
   wrap `K_vault` to the new `MemberPublic`, then `PUT /keys` the updated
   `SharedVault`. The server relays wrapped ciphertext only.
4. **Invitee** pulls the group, `unwrap_for` their entry to recover `K_vault`,
   and decrypts the shared content. Plaintext never leaves the members' devices.

The invite code is the trust anchor; it must be delivered over a channel the
family already trusts (in person, Signal, etc.), never posted publicly.

### 5. Revocation = remove wrap **and rotate** `K_vault`

`SharedVault::revoke` only drops a member's future wrap. True revocation rotates:
generate a fresh `K_vault'`, re-seal content, re-wrap to the *remaining* members,
bump the version. The removed member keeps only data they already read (an
unavoidable property of any client-side-decryption system) — the UI must say so
plainly rather than imply instant forgetting.

## Threat model (STRIDE, on the relay + client)

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Attacker redeems an invite as a fake member | Invite codes are high-entropy, single-use, TTL'd, delivered out-of-band; redeeming only *publishes a public key* — it grants no access until an existing member wraps to it, which is a human decision. **(Was aspirational until 2026-07-18: the client auto-wrapped to any relay-supplied key on every load, with no user involvement. Now enforced by trust-on-first-use pinning plus explicit approval — see known-limitations §3.)** |
| **Tampering** | Server or MITM alters wrapped keys / blob | AEAD (XChaCha20-Poly1305) on both `K_vault` wraps and content; a tampered wrap fails `unwrap_for`. TLS in transit. (Wrap authenticity vs. a *malicious server substituting a whole member* is an open item — see below.) |
| **Repudiation** | Who added/removed whom | Group audit log of membership changes (member-signed entries — a later increment). |
| **Information disclosure** | Server breach | Zero-knowledge: only public keys, ciphertext, hashed tokens/invites. `K_vault`, master, and Secret Key never reach the server. |
| **DoS** | Invite spam / oversized blobs | Rate-limit invite mint + redeem; cap blob and `SharedVault` size; TTL invites. **(Blob caps were listed here as implemented while they were not; a 16 MiB application-layer cap now exists. Invite TTL was unbounded and caller-chosen — `u64::MAX` made expiry unreachable — now clamped to 24h.)** |
| **Elevation of privilege** | Non-owner revokes; revoked member still reads | Revoke is enforced server-side against the member directory — **Admin or Owner**, not Owner-only as originally written here (ADR-0006 introduced Admin; this row was never updated). Revocation **rotates** `K_vault`, invalidates outstanding invites, and bars the removed account from rejoining by invite; "already-read" caveat surfaced in UI. |

**Known open item (must be closed before GA):** a malicious *server* could hand an
invitee a `MemberPublic` it controls (key-substitution / confused-deputy), or show
different member directories to different members. The mitigation is
**out-of-band public-key verification** (a short authentication string / safety
number the family compares, à la Signal) and member-signed directory entries. This
is why the module is still "prototype of the shape" and why a **formal external
crypto review is a hard gate** before this is advertised as protecting real
secrets.

## Increment plan

- **v1.28.0 — server relay + this ADR.** Additive `ShareGroupStore` port
  (memory + file adapters) in `keyward-sync`, the group endpoints above in
  `sync-server`, full handler tests. No change to existing crypto → zero risk to
  shipped vaults. *(this increment)*
- **v1.29.0 — client crypto surface.** Vault-key indirection in `sealing`
  (versioned envelope, lazy migration on first share), member keypair storage,
  and `passbook-wasm` bindings (`member_public`, `share_to`, `unwrap_for`,
  `grant_access`, `revoke`, `rotate`). Round-trip + migration tests.
- **v1.30.0 — app UX.** Real invite / accept flow, member list, "Manage sharing"
  on a vault, revoke-with-rotate, and the safety-number verification step. Replace
  the static "Family vault" label with real group state.
- **Gate before GA:** formal external review of `sharing.rs` + the directory-trust
  model; close the key-substitution open item.

## Consequences

- The sharing engine stops being dead code; each layer is added behind a version
  tag so **existing personal vaults are never at risk** during the rollout.
- The zero-knowledge property is preserved end-to-end; the server's power is
  explicitly bounded and its residual risks (directory trust) are named, not
  hand-waved.
- Sharing is **opt-in**: a user who never shares runs exactly the current
  single-key path.

## Alternatives considered

- **Device-to-device / offline share (QR or local transport).** Cleaner trust (no
  server directory) but requires co-presence; rejected as the *first* path because
  families set up remotely. It layers on later using the same envelope.
- **Deriving the member keypair from `master || secret_key`.** No vault-schema
  change, recoverable from the Emergency Kit — but couples identity to the master
  password (a change breaks everyone's wraps to you). Rejected for §2's stable
  keypair.
- **Server-side re-encryption / proxy re-encryption.** Would let the server rotate
  keys, but expands server trust and crypto complexity; rejected against the
  zero-knowledge stance.
