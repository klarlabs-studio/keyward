# Proctor — Review Scope and Request

> What we are asking an external cryptography reviewer to do, in priority order,
> with the exact code in scope and what is explicitly not.

**The engagement's purpose:** ADR-0004 makes a formal external review of
`sharing.rs` and the directory-trust model a **hard gate** before family sharing
may be advertised as protecting real secrets. This document is the request that
closes that gate.

**What we are not asking for:** validation, a badge, or a sign-off we can quote.
If the answer is "this composition is not sound", that is the most valuable
outcome available and we would rather have it now than after users trust it.

---

## 1. Questions, in priority order

**If your budget covers only three, do Q1–Q3.**

### Q1 — Is the sealed-box construction sound?

The core question. `crates/passbook/src/sharing.rs:310-375`:

```
esk, epk ← X25519 keygen (fresh per recipient per wrap)
ss       ← X25519(esk, recipient_pub)          # recipient_pub comes from the relay
K_wrap   ← HKDF-SHA256(ikm = ss, salt = None, info = "proctor-passbook family-share v1", L = 32)
ct       ← XChaCha20-Poly1305(K_wrap, random_24B_nonce, K_vault)
stored   ← { member_id, epk, nonce, ct }
```

- Is this a sound anonymous sealed-box? What does it give up relative to
  `crypto_box_seal` (which binds `BLAKE2b(epk ‖ rpk)` into its nonce)?
- Is IND-CCA2 plausible here, and against which adversary?
- The recipient public key is **relay-supplied**, never obtained from the
  recipient. Does that change your answer?
- Is 24 bytes of random nonce per wrap adequate given `K_wrap` is fresh per wrap?
  (We believe the nonce is arguably redundant; we want that confirmed, not
  assumed.)
- Is the `plaintext.len() != 32` check at `sharing.rs:369-371` sufficient
  validation of the recovered key?

### Q2 — Can a relay-supplied public key subvert the wrap?

Specifically: **`was_contributory()` is never called** and the recipient public
key is never validated (`sharing.rs:315-316, 352-353`).

- If a malicious relay publishes a low-order point as a member's `public_key`,
  is the resulting `K_wrap` publicly computable, and does the relay thereby
  recover `K_vault`?
- Is there any other malformed or adversarial public key with a similar effect?
- **Please attempt a proof-of-concept.** We have not, and we consider this the
  highest-value single result of the engagement.
- If exploitable: what is the correct fix — reject non-contributory results,
  validate the point, bind `epk ‖ rpk` into the KDF, or all three?

### Q3 — Is domain separation adequate?

Three labels/derivations exist:

| Derivation | Label | Location |
|---|---|---|
| Wrapping key | `b"proctor-passbook family-share v1"` (HKDF `info`, salt `None`) | `sharing.rs:39, 403-409` |
| Safety number | `b"proctor-passbook group-safety-number v1"` (SHA-256 prefix) | `sharing.rs:77, 93-115` |
| 2SKD fold | *no label* — bare `SHA-256(argon2_out ‖ secret_key)` | `sealing.rs:30-38` |

- Is the constant `HKDF_INFO`, binding no key material and no group id,
  sufficient? Should `epk`, `rpk`, `member_id`, and/or `group_id` be in `info`?
- Is `salt = None` correct, or should the group id serve as HKDF salt?
- Is the bare SHA-256 concatenation acceptable for the 2SKD fold given both
  inputs are fixed-length (32 ‖ 16)? Would HKDF, or Argon2's `secret` (pepper)
  parameter, be materially better?
- Are the labels themselves well-formed (versioned, unambiguous, collision-free
  across contexts)?

### Q4 — Is the rotation-on-revoke protocol correct?

`app/src/lib/sharing.ts:599-628` (client) and
`crates/sync-server/src/main.rs:1211-1248` (relay).

- Is the ordering — `DELETE member` → re-read directory → `PUT /keys` →
  `PUT /vault`, each with `If-Match` — correct against a concurrent or malicious
  relay?
- The two blob writes are independent and non-transactional. What is the worst
  outcome of a partial failure, and is the "keys rotated, content not" state
  recoverable in principle?
- The relay assigns versions and there is **no client-side monotonicity check**.
  Can a relay undo a revocation by serving the pre-rotation blobs?
- Building a **fresh** `SharedVault` (rather than mutating and re-wrapping the
  old one) is intended to avoid stale wraps. Does it introduce anything worse?
- Given `revokeMember` re-seals caller-supplied `currentEntries` rather than a
  freshly-pulled blob, is silent data loss the only consequence?

### Q5 — Can the relay do anything undetectable, given safety numbers?

- Enumerate what a malicious relay can do that a family comparing safety numbers
  out of band would **not** catch. We know of: display-name changes (names are
  not hashed, `sharing.rs:102-103`), blob rollback, and withholding. What else?
- The **automatic grant** (`app/src/lib/sharing.ts:511-534`) wraps `K_vault` to
  relay-supplied directory entries with no human check, before any comparison.
  How much does that reduce the safety number's value in practice?
- Is `member_id` collision (see Q6) a practical directory attack?
- Is ~133 bits of retained digest (`mod 100_000` per 4-byte chunk,
  `sharing.rs:107-114`) adequate? Is the rendering usable enough that people
  will actually compare it?
- **What would you build instead?** Member-signed directory entries, TOFU
  pinning with change alerts, blocking on comparison before first grant, a
  transparency log — we have no commitment to the current approach.

### Q6 — Are there nonce, randomness, or uniqueness misuse risks?

- **Nonces.** All nonces are 24 random bytes from `OsRng` — personal vault
  (`sealing.rs:59`), content blob (`sharing.rs:178`), wraps (`sharing.rs:322-323`).
  Is random-nonce XChaCha20-Poly1305 safe at the volumes involved, and is there
  any path that could seal twice under one key with a colliding nonce?
- **RNG discipline.** The crypto kernel uses `OsRng`; the relay uses
  `rand::random::<u128>()` (`crates/sync/src/groups.rs:29`,
  `crates/sync/src/accounts.rs:172`); the browser client uses `Math.random()` for
  member ids (`app/src/lib/sharing.ts:128`). Which of these matter?
- **WASM entropy.** `getrandom`'s `js` feature routes to Web Crypto
  (`crates/passbook-wasm/Cargo.toml`). Any concern in service workers, sandboxed
  iframes, or non-secure contexts?
- **`member_id` uniqueness.** Client-chosen, unenforced by the relay
  (`main.rs:1146-1156`, `groups.rs:273-281`), yet it is the replacement key in
  `wrap_to` (`sharing.rs:335-340`) and the removal key in `remove_member`
  (`groups.rs:346`). Is the displacement attack in
  [`known-limitations.md`](known-limitations.md) §4 real?

### Q7 — Is 2SKD implemented soundly?

`crates/passbook/src/sealing.rs:23-40`, `crates/passbook/src/domain.rs:127-168`.

- Is **128 bits** the right size for the Secret Key? (1Password uses 128 bits of
  its 34-character key; we would like that comparison checked rather than
  assumed.)
- Argon2id at crate defaults — **m = 19456 KiB, t = 2, p = 1** — for a browser
  main-thread derivation. What would you recommend, and what does the browser
  constraint cost?
- Is folding the Secret Key *after* Argon2 (rather than as Argon2's `secret`
  parameter) a meaningful weakening?
- Does the absence of AAD over `salt`, `nonce`, and `secret_key_protected`
  (`crypto/src/lib.rs:67-76`) create any exploitable path beyond fail-closed
  decryption errors?

### Q8 — Is the recovery-contact sealed box sound, and is sharing a Secret Key wise?

**This construction landed while this package was being written and is the least
reviewed code in scope.** `crates/passbook/src/sharing.rs:126-165`,
`crates/passbook-wasm/src/lib.rs:326-344`, `app/src/lib/sharing.ts:299-397`.

A member seals their **device Secret Key** (one of the two 2SKD factors) to
another family member, so it can be handed back if the Emergency Kit is lost:

```
sealed ← seal_to(contact_public, secret_key)
       = { epk, nonce, XChaCha20-Poly1305(K_wrap, nonce, plaintext) }
       where K_wrap = derive_wrapping_key(X25519(esk, contact_public))
```

- **`seal_to` calls the *same* `derive_wrapping_key` with the *same* `HKDF_INFO`
  as the vault-key wrap** (`sharing.rs:137, 403-409`). Two distinct protocols now
  share one derivation with no separating label. Is cross-protocol confusion
  possible — e.g. can a `WrappedKey` ciphertext be presented as a `SealedBox` or
  vice versa, given neither carries a type tag and neither uses AAD?
- `seal_to` shares Q2's exposure: the contact's public key comes from the
  relay-served directory, and `was_contributory()` is not checked.
- **Design question, not just implementation:** is exporting a 2SKD factor off
  the device — into a blob stored on the relay, inside the shared content — an
  acceptable trade for recoverability? The stated safety property is that the
  contact still lacks the master password. Does that hold if the relay or the
  contact *also* obtains the master password later, and does it weaken the
  "server breach yields nothing" claim?
- The sealed blob is stored as a **reserved entry inside the shared content
  blob**, titled `__recovery__` (`app/src/lib/sharing.ts:310`), so **every**
  group member holds the ciphertext and it is re-uploaded on every save. Is
  storing it where all members (and the relay) can retain copies indefinitely a
  problem, given only the addressed contact can open it?
- Is filtering by entry *title* (`isRecoveryEntry`, `sharing.ts:325-328`) a safe
  way to hide these from the item list? What happens if a user creates a real
  entry titled `__recovery__`?

### Q9 — Is the Stripe webhook verification correct?

`crates/sync-server/src/main.rs:1561-1606`. Lower priority (billing plane only;
it never touches vault data), but it is the sole authorization for plan
escalation.

- Is the HMAC scheme (`"{t}.{body}"`, hex, any-`v1`-matches, 300 s symmetric
  window, `constant_time_eq`) correct against Stripe's specification?
- Does comparing hex strings rather than decoded bytes matter?
- Does the absence of event-id deduplication and a `livemode` check matter given
  `set_plan` is idempotent?

---

## 2. In scope — exact files and functions

### Primary (the audit target)

| File | Lines | What |
|---|---|---|
| `crates/passbook/src/sharing.rs` | **whole file (637)** | **The core.** See breakdown below. |
| `crates/crypto/src/lib.rs` | 25-29, 40-49, 55-64, 67-88 | Constants, RNG, Argon2id KDF, AEAD wrappers |
| `crates/passbook/src/sealing.rs` | 23-40, 43-50, 53-84 | 2SKD `derive_key`, `SealedVault` format, `seal`/`open` |
| `crates/passbook/src/domain.rs` | 127-168 | `SecretKey`: generation, format, parse, exposure |

`sharing.rs` breakdown:

| Lines | Item | Why |
|---|---|---|
| 39 | `HKDF_INFO` | Q3 |
| 77 | `SAFETY_NUMBER_INFO` | Q3 |
| 71-75, 174-186 | `ContentBlob`, `seal_content`, `open_content` | Q1, Q6 |
| 93-115 | `safety_number` | Q5 |
| **126-165** | **`SealedBox`, `seal_to`, `open_sealed`** — recovery contacts | **Q1, Q3, Q8 — newest, least-reviewed code** |
| 191-260 | `Member`, `MemberPublic` | Q2 |
| 264-282 | `WrappedKey`, `SharedVault` (wire format) | Q1 |
| **307-339** | **`wrap_to`** | **Q1, Q2, Q3, Q6 — the highest-value function** |
| **345-372** | **`unwrap_for`** | **Q1, Q2** |
| 380-387 | `grant_access` | Q5 — no recipient validation |
| 395-399 | `revoke` | Q4 |
| **403-409** | **`derive_wrapping_key`** | **Q3 — the whole KDF, now shared by two protocols** |

### Secondary (protocol and enforcement)

| File | Lines | What |
|---|---|---|
| `app/src/lib/sharing.ts` | **467-546** | `loadFamily` — **auto-reconcile grant at 511-534** (Q5) |
| `app/src/lib/sharing.ts` | 599-628 | `revokeMember` — rotate-on-revoke (Q4) |
| `app/src/lib/sharing.ts` | **299-397** | **Recovery contacts** — seal/open a Secret Key to a family member (Q8) |
| `app/src/lib/sharing.ts` | 101-138, 280-296, 420-459, 560-573 | Identity storage, create, join/invite, save |
| `crates/passbook-wasm/src/lib.rs` | 182-344 | Hex boundary, JSON marshalling, all sharing + recovery bindings |
| `crates/sync-server/src/main.rs` | 942-1430 | Group routing and all authorization checks |
| `crates/sync-server/src/main.rs` | 1488-1606 | Stripe webhook + HMAC (Q9) |
| `crates/sync-server/src/main.rs` | 107-174, 511-513, 587-612 | Rate limiter, request loop, token resolution |
| `crates/sync/src/groups.rs` | 28-43, 97-148, 256-283 | Id/hash generation, stored shape, `apply_redeem` (Q6) |
| `crates/sync/src/accounts.rs` | 171-181, 231-325 | Token generation, hashing, resolve/rotate |

### Also in scope

- The **protocol as a whole** — the create → invite → join → grant → read →
  revoke flow described in
  [`cryptography-spec.md`](cryptography-spec.md) §12. Design-level findings are as
  welcome as implementation-level ones.
- The **trust model** for the relay-served member directory (ADR-0004's named
  open item).
- **Our own documents.** If `cryptography-spec.md` misdescribes the code, or
  `known-limitations.md` understates something, that is a finding.

---

## 3. Explicitly out of scope

Not because these do not matter, but so your budget goes to the crypto.

1. **The AI credential broker** — `crates/broker`, `crates/mint`, `crates/mcp`,
   `crates/vault`, `crates/cli`, `crates/profiles`. Separate bounded context with
   its own (also self-assessed) threat model in
   [`THREAT-MODEL.md`](THREAT-MODEL.md).
2. **Device compromise.** Assumed fatal by design. The `localStorage` placement
   of key material is documented in
   [`known-limitations.md`](known-limitations.md) §10 — we do not need it
   re-derived, though a *better* option we have missed is welcome.
3. **Web application security** — XSS, CSP, supply chain of the Vue/Vite front
   end, dependency CVEs. Handled separately (`nox` scanning, see
   [`THREAT-MODEL.md`](THREAT-MODEL.md) §6b).
4. **Infrastructure and deployment** — Kubernetes manifests in `deploy/`, TLS
   termination, network policy, container hardening. See ADR-0005.
5. **Postgres adapter correctness** — `crates/sync-postgres`. It implements the
   same ports as the in-memory and file adapters and stores the same opaque
   bytes; SQL-level review is a separate exercise.
6. **Performance and scalability.** Known and documented in ADR-0005. We do not
   need to be told the server is single-threaded — we need to know if it is
   *insecure*.
7. **TOTP, password generation, and Watchtower** —
   `crates/passbook/src/{totp,generate,watchtower}.rs`. Available if you want
   them, but not part of the confidentiality core.
8. **Business logic and entitlements** — plans, device caps, paywalls. Metadata
   plane only; never touches vault data.

---

## 4. Artifacts provided

1. **The repository.** Rust workspace plus a Vue/TypeScript client. AGPL, so
   there is no confidentiality constraint on your notes or on publishing your
   findings.
2. **This package** — `docs/security/`:
   - `README.md` — index and reading order
   - `cryptography-spec.md` — the implementation-accurate spec (audit against this)
   - `threat-model-passbook.md` — assets, boundaries, adversaries, STRIDE
   - `known-limitations.md` — what we already believe is wrong
   - `review-scope.md` — this document
3. **The test suite.** `cargo test --workspace`. Relevant suites:
   - `crates/crypto/src/lib.rs:90-134` — KDF determinism, AEAD round-trip, tamper
   - `crates/passbook/src/sealing.rs:86-124` — 2SKD round-trip, Secret Key required
   - `crates/passbook/src/sharing.rs:415-637` — wrap/unwrap, non-member rejection,
     `grant_access` recovery, revoke, safety number
   - `crates/sync-server/src/main.rs:1613-1863` — Stripe signature, rate limiter
   - `crates/sync/tests/contract_memory.rs`, `crates/sync-postgres/tests/` —
     store contract suites
   - `app/scripts/roundtrip.test.ts` — WASM boundary round-trip
   > Note: there are **no test vectors** and **no negative tests for a malicious
   > directory or hostile public key**. Both are gaps, not omissions from this list.
4. **ADRs** — `docs/architecture/`:
   - `ADR-0004-family-sharing.md` — the sharing design, its STRIDE table, and the
     key-substitution open item it names as a GA gate
   - `ADR-0005-managed-cloud.md` — relay architecture, trust boundaries,
     operational model
   - `ADR-0003-ddd-hexagonal-structure.md` — why storage is ports and adapters
   - `context-map.md`, `ubiquitous-language.md` — vocabulary
5. **On request:** a running instance, a scripted end-to-end share, or a walkthrough
   with the implementer.

---

## 5. What a useful deliverable looks like

- **Findings with severity and exploitability**, distinguishing "unsound" from
  "unproven" from "stylistic".
- **A verdict on Q2 specifically**, ideally with a PoC either way.
- **Concrete remediation** — the construction you would write instead, not just
  the property that is missing.
- **A judgment on whether the shape is right**, separately from the
  implementation. If per-recipient sealed boxes over a relay-served directory is
  the wrong architecture for this problem, that is the finding we most need.
- **Corrections to these documents.** They are the artifact users will eventually
  be pointed at; their honesty matters as much as the code's correctness.
