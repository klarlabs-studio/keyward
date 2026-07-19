# Keyward — Threat Model (Passbook, family sharing, and the relay)

> **Filename note.** This document would naturally be `threat-model.md`, but on a
> case-insensitive filesystem that collides with the pre-existing
> [`THREAT-MODEL.md`](THREAT-MODEL.md) — a *different* document covering the AI
> credential broker. The two are separate and neither supersedes the other.
>
> **Scope:** the consumer vault, the family-sharing protocol, and the sync/share
> relay.
>
> **Status:** self-assessment, unreviewed. This document frames an external
> review; it does not substitute for one.

---

## 1. Assets

Ordered by what an attacker most wants.

| # | Asset | Where it lives | Compromise means |
|---|---|---|---|
| A1 | **Vault plaintext** — passwords, TOTP seeds, cards, identities | Decrypted only in client memory (WASM linear memory / Rust process) | Total loss for that user or family |
| A2 | **Master password** | User's head; transiently in a client call stack | Offline attack on A1, gated by the Secret Key (A3) |
| A3 | **Device Secret Key** (128-bit, 2SKD factor) | `localStorage` key `keyward.passbook.secretkey.v1`; printed Emergency Kit | With A2, opens A1 from ciphertext alone |
| A4 | **`K_vault`** — the shared family vault key (256-bit) | Client memory; wrapped per-member at the relay | Reads all shared content, past and present-until-rotation |
| A5 | **Member X25519 secret** | `localStorage` key `keyward.passbook.member.v1` | Unwraps every current and future wrap to that member |
| A6 | **Device bearer token** (128-bit) | `localStorage` key `keyward.passbook.sync.v1`; SHA-256 hash at relay | Full API access as that account: read/overwrite blobs, join groups, mint invites |
| A7 | **Invite code** (128-bit, single-use, 24 h) | Out-of-band message; SHA-256 hash at relay | Entry into the member directory → candidate for an automatic grant |
| A8 | **Relationship metadata** — who is in which family, device counts, sync timing, blob sizes | Relay, in the clear | Social graph disclosure; targeting |
| A9 | **Stripe webhook signing secret** | Server environment | Arbitrary plan escalation for any account |

A1–A5 are the confidentiality core. A6–A7 are access-control credentials.
**A8 is not protected at all** and is enumerated deliberately in §5.

---

## 2. Trust boundaries

```
 ┌────────────────────────────────────────────────────────────────────┐
 │ CLIENT DEVICE  (browser / Tauri)                        TRUSTED    │
 │   localStorage: sealed vault, Secret Key, member X25519 secret,    │
 │                 device token          ── all at the same level     │
 │   WASM: Argon2id, XChaCha20-Poly1305, X25519, HKDF                 │
 │   Plaintext exists ONLY here                                       │
 └───────────────────────────┬────────────────────────────────────────┘
                             │  B1: TLS (terminated at the ingress)
                             │      Bearer <device token>
 ┌───────────────────────────▼────────────────────────────────────────┐
 │ RELAY  (crates/sync-server)                       UNTRUSTED-FOR-   │
 │   Holds: opaque blobs, public keys, hashed tokens/invites,         │
 │          display names, roles, the family graph                    │
 │   Cannot: decrypt anything                                         │
 │   CAN:    lie about the member directory  ← THE central residual   │
 └───────────────────────────┬────────────────────────────────────────┘
                             │  B2: connection string / SQL
 ┌───────────────────────────▼────────────────────────────────────────┐
 │ POSTGRES / FILESYSTEM                              SAME TRUST      │
 │   Everything the relay holds, at rest                              │
 └────────────────────────────────────────────────────────────────────┘
                             │  B3: HTTPS, server-side secret key
 ┌───────────────────────────▼────────────────────────────────────────┐
 │ STRIPE                                             EXTERNAL        │
 │   Billing plane only. Never touches vault data.                    │
 └────────────────────────────────────────────────────────────────────┘

              B4: OUT-OF-BAND human channel (in person, phone, Signal)
                  carries the invite code and the safety number.
                  This is the ONLY channel the relay does not mediate.
```

**B1 — client ↔ relay.** The design's central claim: everything crossing this
boundary is either opaque ciphertext or deliberately public. The claim holds for
*confidentiality*. It does **not** hold for *authenticity of the member
directory*, which is exactly the residual ADR-0004 flags as a hard gate before GA.

**B4 — the out-of-band channel.** The entire integrity story for family sharing
rests on humans using it: once for the invite code, and again to compare safety
numbers. If neither happens, a malicious relay is unconstrained on the directory.

**Not a boundary: within the client device.** The Secret Key, the member X25519
secret, the device token, and the sealed vault all sit in `localStorage`. The code
states the position explicitly (`app/src/lib/sharing.ts:8-10`): a device
compromise is already fatal, so no attempt is made to separate these.

---

## 3. Adversaries

### ADV-1 — Malicious or compromised relay operator (**the primary adversary**)

Can read and modify everything it stores and serves; can present different views
to different members. **Cannot** decrypt any blob.

What it can actually do:

- **Substitute a public key** in the directory, or **inject an extra member**.
  Because grants are automatic (`app/src/lib/sharing.ts:511-534`), the next
  member to open the vault will wrap `K_vault` to the attacker's key with no
  human in the loop. *Detected only by out-of-band safety-number comparison —
  and only after the fact.*
- **Rename members freely.** Display names are not in the safety-number digest
  (`crates/passbook/src/sharing.rs:102-103`), so relabeling an injected member as
  "Mom" does not change the number families are told to compare.
- **Roll back a blob** to an older version. Versions are relay-assigned counters
  (`crates/sync/src/groups.rs:143, 147`) with no client-side monotonicity check,
  so a rotation can be reverted to re-expose content under a revoked key.
- **Withhold or delay** updates, indefinitely and undetectably.
- **Harvest metadata** — the entire family graph, in the clear.

Cannot: forge a wrap that a member's key opens; read plaintext; recover a master
password or Secret Key from stored data.

### ADV-2 — Network attacker (on-path)

TLS terminates at the ingress; the server speaks plain HTTP
(`crates/sync-server/src/main.rs:494`) and relies on the deployment for TLS. With
TLS intact, this adversary sees only traffic patterns and sizes. **With TLS
broken or stripped, this adversary becomes ADV-1** — bearer tokens travel in
headers, and there is no in-protocol authentication of the relay. No certificate
pinning is implemented.

### ADV-3 — Device compromise (malware, stolen unlocked device, hostile browser extension)

Reads `localStorage` and therefore obtains A3, A5, and A6 directly, and A1 once
the vault is unlocked. **Explicitly out of scope by design.** Worth stating for
the reviewer: a hostile browser extension with host permissions on the app origin
is equivalent to full compromise, and 2SKD provides no defense here — both
factors are on the same device.

Partial mitigations: device tokens can be revoked or rotated
(`crates/sync/src/accounts.rs:305-325`, `crates/sync-server/src/main.rs:779-853`),
and optional token TTLs exist (off by default).

### ADV-4 — Insider / infrastructure operator

Has ADV-1's powers plus filesystem, database, and log access. Two extras:

- **Logs.** The server writes account ids, group ids, and member ids to stderr on
  many paths (e.g. `crates/sync-server/src/main.rs:706, 1037, 1170, 1242`). Log
  retention becomes an A8 disclosure surface.
- **Billing plane.** With A9, arbitrary plan escalation; with database access,
  the same directly. Neither reaches vault data.

### ADV-5 — Other family members

The most under-modeled adversary. Within a group, the cryptography draws almost
no lines:

- **Any Member can overwrite `/keys` and `/vault`.** These handlers gate on
  membership, not role (`crates/sync-server/src/main.rs:1339-1342`). A single
  member can lock everyone else out by pushing a `SharedVault` wrapped only to
  themselves, or destroy content by pushing a blob nobody can open.
- **Any member with access can grant it to anyone.** `grant_access`
  (`crates/passbook/src/sharing.rs:383-390`) authorizes the *granter*
  cryptographically and performs no check on the *recipient*.
- **Removal does not un-read.** A removed member keeps everything they saw.
- **No attribution.** Blobs are unsigned; nothing records who wrote what.
  ADR-0004's STRIDE table lists a member-signed audit log as a later increment;
  it does not exist.

Role checks (Owner > Admin > Member, `crates/sync/src/groups.rs:48-90`) govern
*membership management* — invite, remove, role change — and nothing else.

### ADV-6 — Offline attacker holding stolen ciphertext

Has a `SealedVault` and its salt (a relay breach, or a stolen backup). Must
recover the master password **and** the 128-bit Secret Key. With 2SKD enabled the
128-bit factor makes offline search infeasible regardless of password quality —
this is the design's strongest property. **Without** a Secret Key
(`secret_key_protected = false`), security collapses to Argon2id at m=19 MiB,
t=2, p=1 over the user's password alone.

---

## 4. STRIDE

| Threat | Vector | Status | Mechanism / residual |
|---|---|---|---|
| **S**poofing | Attacker redeems an invite as a fake member | **Partial** | 128-bit single-use TTL'd codes, out-of-band delivery. But redemption lets the caller choose an arbitrary `member_id` (`main.rs:1146-1156`), and uniqueness is unenforced (`groups.rs:273-281`). |
| **S**poofing | Relay substitutes a member's public key | **Weak** | Safety number exists (`sharing.rs:93-115`) but is advisory, human-dependent, after-the-fact, and excludes display names. Automatic grants fire before any comparison. |
| **S**poofing | Stolen device token replayed | **Partial** | Hashed at rest; revocable; rotatable. TTL is opt-in and **off by default**. Bearer-only — no proof-of-possession, no channel binding. |
| **T**ampering | Relay alters a blob | **Mitigated** | XChaCha20-Poly1305 on every blob; tampering fails to open. |
| **T**ampering | Relay alters directory metadata | **Not mitigated** | `member_id`, `name`, `role` are unauthenticated server-side records. No member signatures. |
| **T**ampering | Relay rolls a blob back | **Not mitigated** | Versions are relay-assigned; no client-side monotonicity or freshness check. |
| **R**epudiation | Who added, removed, or wrote what | **Not mitigated** | No signed audit log. ADR-0004 lists it as a later increment. |
| **I**nfo disclosure | Relay/database breach → vault contents | **Mitigated** | Zero-knowledge: opaque blobs, hashed tokens/invites; keys never transit. |
| **I**nfo disclosure | Relay learns the family graph | **Accepted, not mitigated** | See §5. Names, public keys, membership, timing, and sizes are plaintext by design. |
| **I**nfo disclosure | Offline attack on a stolen vault | **Mitigated with 2SKD** | 128-bit second factor. Master-only vaults rest on Argon2id defaults. |
| **I**nfo disclosure | Key material in browser storage | **Accepted** | Secret Key, member secret, and token are `localStorage` plaintext at device trust level. |
| **D**oS | Register / invite spam | **Partial** | 30/min per-IP fixed window (`main.rs:107-174`) — but per-process, so per-replica; and redemption is not limited. |
| **D**oS | Oversized blobs | **Not mitigated** | `read_to_end` is unbounded (`main.rs:895, 1362`). ADR-0004 lists blob caps as a mitigation; they do not exist. |
| **D**oS | Slow request stalls the server | **Not mitigated** | Sequential blocking request loop (`main.rs:511-513`); the Stripe checkout call blocks it (`main.rs:1456`). |
| **E**oP | Non-Admin removes a member or mints an invite | **Mitigated** | Role checks server-side (`main.rs:1090, 1213, 1262`); Owners are unremovable and undemotable. |
| **E**oP | Any Member overwrites `/keys`, locking others out | **Not mitigated** | Blob writes gate on membership only (`main.rs:1339-1342`). |
| **E**oP | Revoked member reads future content | **Mitigated** | Client rotates `K_vault` on revoke (`app/src/lib/sharing.ts:599-628`). Already-read data is retained — inherent. |
| **E**oP | Unauthorized plan upgrade | **Mitigated** | HMAC-SHA256 over `"{t}.{body}"`, constant-time, 300 s window, fail-closed. No event-id dedupe. |

---

## 5. What this design does **not** protect against

Stated plainly, because a reviewer's time is better spent on the real perimeter.

1. **A compromised device.** Full stop. The Secret Key, the member X25519 secret,
   and the device token all sit in `localStorage` at the same trust level as the
   ciphertext they protect. 2SKD defends against a *server* breach, never a
   *device* breach.

2. **A relay that lies about the membership directory, when nobody compares
   safety numbers.** This is the acknowledged open item in ADR-0004 (*"must be
   closed before GA"*). It is worse in practice than the ADR anticipated, because
   grants are automatic rather than "a human decision".

3. **Metadata privacy.** The relay learns and retains: which accounts exist and
   their contact email if supplied; how many devices each has and when each syncs;
   the complete family graph with display names, public keys, roles, and join
   times; the size of every vault and every shared blob; and the timing of every
   read and write. None of this is encrypted, padded, or minimized.

4. **Retroactive revocation.** Rotation protects *future* content only. Anything
   a member decrypted is theirs permanently. Any system that decrypts on the
   client has this property; the requirement is that the UI say so, not that the
   crypto prevent it.

5. **Forward secrecy for stored data.** Blobs sit under a long-lived key. A
   future compromise of `K_vault` or of a member's X25519 secret opens every blob
   ever stored under it. The X25519 member keys are *static*, not ratcheted; the
   ephemeral half of each wrap gives per-wrap freshness, not forward secrecy.

6. **Rollback / freshness.** No client-side monotonicity check on versions.

7. **Traffic analysis.** No padding, no cover traffic, no constant-size blobs.

8. **Denial of service by a family member.** Any member can overwrite the shared
   blobs. There is no per-writer authorization, no attribution, and no recovery
   beyond restoring from another member's local copy.

9. **A malicious client build.** The browser app is served from a web origin;
   Subresource Integrity, code signing, and reproducible-build verification of the
   WASM bundle are not part of this model. Whoever serves the app can replace the
   cryptography.

10. **Weak master passwords on master-only vaults.** Without a Secret Key, the
    only barrier is Argon2id at library-default cost.

---

## 6. Key assumptions

1. TLS terminates correctly at the ingress and the client validates it. The
   server speaks plain HTTP and performs no certificate pinning.
2. The client device and browser are not compromised.
3. Users deliver invite codes over a channel the family already trusts, and
   compare safety numbers out of band. **Assumption 3 is the weakest link, and
   nothing in the protocol enforces or verifies it.**
4. `OsRng` / Web Crypto provide adequate entropy on every supported platform.
5. The relay operator can read all metadata; users are informed of this.
6. The Stripe webhook signing secret stays secret and Stripe's signing is sound.

---

## 7. Prioritized residual risks

| # | Risk | Severity | Status |
|---|---|---|---|
| P1 | X25519 result is not checked for contributory behaviour; a relay-supplied low-order public key yields a predictable wrapping key | **High (if exploitable)** | Open — see [`known-limitations.md`](known-limitations.md) §1; **Q2** for the reviewer |
| P2 | Automatic `grant_access` wraps `K_vault` to any relay-supplied directory entry with no human check | **High** | Open — contradicts ADR-0004 §4 |
| P3 | `member_id` is client-chosen and not unique-enforced by the relay | **Medium-High** | Open |
| P4 | HKDF `info` binds no key material (no `epk`/`rpk`/group id) | **Medium** | Open |
| P5 | Safety number is advisory, after-the-fact, and excludes display names | **Medium** | Partially mitigated |
| P6 | No blob size caps; sequential blocking server | **Medium** | Open — ADR-0005 acknowledges the server model |
| P7 | Any Member may overwrite `/keys` and `/vault` | **Medium** | Open |
| P8 | No rollback/freshness protection on blob versions | **Medium** | Open |
| P9 | `SecretKey` is not zeroized despite the module claiming otherwise | **Low-Medium** | Open |
| P10 | Argon2 parameters are library defaults, never tuned or measured | **Low-Medium** | Open — self-flagged at `crates/crypto/src/lib.rs:13-14` |
| P11 | No signed audit log for membership or blob writes | **Low** | Deferred by ADR-0004 |
| P12 | Metadata (family graph, names, sizes, timing) fully visible to the relay | **Accepted** | By design; disclosed |

---

*Related: [ADR-0004 family sharing](../architecture/ADR-0004-family-sharing.md) ·
[ADR-0005 managed cloud](../architecture/ADR-0005-managed-cloud.md) ·
[cryptography-spec.md](cryptography-spec.md) ·
[known-limitations.md](known-limitations.md) ·
[review-scope.md](review-scope.md)*
