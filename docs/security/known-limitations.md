# Proctor — Known Limitations

> Read this first. It is the honest list. Every item is something we already
> believe is true; a reviewer's job is to tell us which ones are *worse* than we
> think and what we have missed entirely.
>
> Nothing here has been externally reviewed.

---

## 0. The framing limitation: this is prototype crypto of the *shape*

The sharing module says so about itself, in its own header:

> *"SECURITY NOTE: prototype crypto of the **shape**. Needs a formal review
> before real use — see the threat model."*
> — `crates/passbook/src/sharing.rs:23-24`

And the kernel:

> *"SECURITY NOTE: prototype-grade parameters. A production deployment needs
> tuned Argon2 cost parameters and a formal review."*
> — `crates/crypto/src/lib.rs:13-14`

And the WASM bindings (`crates/passbook-wasm/src/lib.rs:8-10`). And ADR-0004,
which makes an external review a **hard gate** before the feature may be
advertised as protecting real secrets.

The constructions are assembled from standard, well-regarded primitives. The
*composition* is unverified. Nothing below should be read as "we think it's
fine except for these"; it should be read as "here is where we already know to
look."

---

## 1. X25519 results are not checked for contributory behaviour

`crates/passbook/src/sharing.rs:316`, `:353`, and `:136` call
`diffie_hellman(...)` and use `shared.as_bytes()` directly as HKDF input
material. `x25519-dalek`'s `SharedSecret::was_contributory()` is **never
called**, and the recipient public key is used exactly as it arrives from the
relay directory (`sharing.rs:315`) with no validation.

Why this matters here specifically: the recipient's public key is **not**
obtained from the recipient. It is obtained from the relay
(`app/src/lib/sharing.ts:269-273, 511-534`). If the relay supplies a low-order
point as a member's `public_key`, the X25519 output is the all-zero value, the
wrapping key becomes `HKDF-SHA256(ikm = 0^32, salt = None, info = HKDF_INFO)` —
a **constant any party can compute** — and the resulting `WrappedKey` is
openable by anyone, including the relay.

The safety number would change in that case, so a family that actually compares
it out of band would catch it. But the automatic grant (§3) happens *before* any
such comparison, and nothing blocks on the comparison.

**We have not written a proof-of-concept for this.** It is the single item we
most want a reviewer to confirm or refute. It is question **Q2** in
[`review-scope.md`](review-scope.md).

---

## 2. The HKDF binds nothing but a constant label

```rust
// crates/passbook/src/sharing.rs:406-412
let hk = Hkdf::<Sha256>::new(None, shared_secret);
hk.expand(HKDF_INFO, okm.as_mut())
```

`HKDF_INFO` is the fixed byte string `b"proctor-passbook family-share v1"`
(`sharing.rs:39`). The `info` parameter does **not** include the ephemeral
public key, the recipient's public key, the `member_id`, or the group id, and
the salt is `None`.

The reference construction for this shape — libsodium's `crypto_box_seal` —
binds both the ephemeral and recipient public keys into the derivation. Proctor
does not. Consequences we can see:

- A wrap is not cryptographically bound to *which* recipient it was made for.
  Recipient binding rests entirely on the unauthenticated `member_id` string
  sitting next to the ciphertext.
- There is no AEAD associated data either (`sharing.rs:324-326` passes plaintext
  only), so `member_id` and `ephemeral_public` are outside the authentication
  tag.
- The label carries no group or context identifier, so wraps are not separated
  across groups.

The practical impact may be small — mismatched material fails to decrypt — but
"fails closed" is not the same as "is bound", and we would like that judged
properly rather than assumed.

---

## 2a. One KDF now serves two protocols, with no separating label

The **recovery-contact** feature (`crates/passbook/src/sharing.rs:120-165`) —
which seals a member's device Secret Key to a family member — calls the *same*
`derive_wrapping_key` with the *same* `HKDF_INFO` as the vault-key wrap
(`sharing.rs:137` vs `sharing.rs:317`).

So two distinct protocols, carrying **different plaintext types** (a 32-byte
vault key vs. an arbitrary-length Secret Key string), now derive their keys
identically. Neither ciphertext carries a type tag, and neither uses AAD.
`SealedBox` (`sharing.rs:126-130`) and `WrappedKey` (`sharing.rs:267-276`) differ
only in that the latter has a `member_id` field — the sealed bytes are
structurally interchangeable.

We do not currently see an exploit, because the plaintexts round-trip through
different call paths and a length check guards the vault-key path
(`sharing.rs:369-371`). But "no separating label between two protocols sharing a
KDF" is exactly the precondition for cross-protocol confusion, and it should not
rest on our not having found one. This is question **Q8**.

This construction landed *while this package was being written*. It is the
newest and least-examined code in scope, and it is the only place where a 2SKD
factor deliberately leaves the device — see §10a.

---

## 3. Access grants are automatic; the safety number is not consulted

ADR-0004 §4 step 3 describes granting as a human decision — the invite proves
authorization, but "it grants no access until an existing member wraps to it,
which is a human decision."

As implemented, it is not a human decision:

```ts
// app/src/lib/sharing.ts:511-534
const missing = group.members.filter((m) => !wrappedIds.has(m.member_id));
if (missing.length > 0) {
  for (const m of missing) {
    updated = grant_group_access(updated, member.secret, member.id, JSON.stringify(m));
  }
  await putKeys(groupId, updated, keys.version);
}
```

Every time any member with access opens the family vault, their client silently
wraps `K_vault` to **every** directory entry the relay reports as lacking a wrap,
using **the public key the relay supplied**, with no prompt and no
safety-number check. `grant_access` itself
(`crates/passbook/src/sharing.rs:383-390`) authorizes only the *granter*; it
performs no validation of the recipient at all.

This is the exact key-substitution scenario ADR-0004 names as its "known open
item (must be closed before GA)", and the automation makes it materially easier
to exploit than the ADR's own description implies.

**Partial improvement, landed during the writing of this package.** `loadFamily`
now returns `justGranted: string[]` — the names of members it just admitted
(`app/src/lib/sharing.ts:95, 519, 530, 544`) — so the UI can report the grant
after the fact. That is a genuine improvement in *transparency*: a silent action
becomes a visible one. It does **not** change the security property. The wrap
still happens automatically, still uses the relay-supplied public key, still
precedes any safety-number comparison, and still cannot be declined. Reporting a
grant is not the same as authorizing it.

---

## 4. `member_id` is client-chosen and its uniqueness is unenforced

The joiner supplies `member_id`, `name`, and `public_key` in the join request
body (`crates/sync-server/src/main.rs:1146-1156`). The relay stores them verbatim.
`apply_redeem` (`crates/sync/src/groups.rs:273-281`) deduplicates on
**`account_id`**, not on `member_id`.

But `member_id` is the identity key of the cryptographic structure:

- `SharedVault::wrap_to` **replaces** an existing wrap with the same `member_id`
  (`crates/passbook/src/sharing.rs:335-340`).
- `unwrap_for` finds a member's wrap by `member_id` (`sharing.rs:349-353`).
- `ShareGroupStore::remove_member` removes **every** entry with that
  `member_id` (`crates/sync/src/groups.rs:346`).

So a holder of a valid invite code can join claiming an existing member's
`member_id` with their own public key. On the next rotation or `share_to` pass
over the directory, the later wrap overwrites the earlier one — plausibly
displacing the legitimate member's access and redirecting it to the joiner.
The client also generates member ids with `Math.random()`
(`app/src/lib/sharing.ts:128`), which is not a CSPRNG, making ids guessable.

We have not built the full exploit; we have confirmed the preconditions in the
code. It is question **Q5**.

---

## 5. Revocation cannot un-read, and rotation is not atomic

**Revocation cannot un-read.** This is inherent and is stated in the code
itself:

> *"this revokes future access to this `SharedVault` object only; it does not
> rotate the vault key, so a member who already read the key retains it."*
> — `crates/passbook/src/sharing.rs:394-397`

Rotation (`app/src/lib/sharing.ts:599-628`) protects **future** content only. A
removed member keeps: every entry they ever decrypted, and the old `K_vault`
(which opens any historical blob they retained). No client-side-decryption system
can do better. The obligation is that the UI says so plainly — ADR-0004 §5
requires it.

**Rotation is also not atomic.** The client performs four independent
operations against the relay — remove member, re-read directory, `PUT /keys`,
`PUT /vault` — with no transaction spanning them:

- Between the `DELETE` and the `PUT /vault`, the current content is still sealed
  under the **old** key, which the removed member holds.
- If `PUT /keys` succeeds and `PUT /vault` then fails or 409s, the group is left
  with wrapped keys for `K_vault'` but content sealed under `K_vault` — **every
  remaining member loses access** until someone re-pushes. There is no rollback
  and no recovery path in the code.
- `revokeMember` re-seals `currentEntries` passed in by the caller, not a
  freshly-pulled blob, so a concurrent edit by another member is silently
  overwritten.
- The relay assigns versions and has no rollback protection, so a malicious relay
  can serve the pre-rotation `/keys` and `/vault` back and undo the revocation
  entirely.

---

## 6. The safety number only helps if humans actually compare it

`safety_number` (`crates/passbook/src/sharing.rs:93-115`) is well-constructed for
what it is: order-independent, length-prefixed, domain-separated
(`SAFETY_NUMBER_INFO`, `sharing.rs:77`), and it demonstrably changes on key
substitution or silent addition (test at `sharing.rs:477-517`).

It is also:

- **Advisory.** Computed and displayed (`app/src/lib/sharing.ts:73-80, 497`).
  **Nothing in the protocol blocks on it.** No flow requires it, no state records
  that a comparison happened, and no warning appears if a previously-seen number
  changes. There is no trust-on-first-use pinning of any kind.
- **After the fact.** By the time a member sees the number, the automatic grant
  (§3) has already run.
- **Blind to display names.** Only `id` and `public_key` are hashed
  (`sharing.rs:102-103`). A relay can rename an injected member to "Mom" without
  changing the digits the family compares.
- **Truncated.** `mod 100_000` per 4-byte chunk keeps roughly 133 of 256 digest
  bits. Adequate for the threat, but it is a truncation.

Realistically, most families will never compare it. A security property that
depends on an unprompted, unenforced human ritual should be treated as absent in
the median case.

---

## 7. The relay learns a great deal of metadata

Zero-knowledge applies to *contents*, not to *relationships*. In the clear, the
relay holds and can retain indefinitely:

- **Account existence**, and the optional contact email supplied at registration
  (`crates/sync/src/accounts.rs:213-221`).
- **Device counts and labels** per account, with creation timestamps.
- **The complete family graph** — `ShareGroup.members` carries `member_id`,
  `account_id`, **display name**, **X25519 public key**, `role`, and `added_epoch`
  (`crates/sync/src/groups.rs:97-114`).
- **Invite activity** — when minted, when redeemed, and by whom
  (`groups.rs:118-128`).
- **Sync timing** — every read and write, with timestamps.
- **Blob sizes** — the personal vault and both group blobs are stored and served
  at their natural length. No padding. Vault size correlates with entry count.
- **Plan and billing state.**
- **Server logs** additionally record account, group, and member ids to stderr
  (`crates/sync-server/src/main.rs:706, 1037, 1104, 1170, 1242`).

None of this is minimized, padded, or subject to a stated retention policy in
the code.

---

## 8. The server is a sequential, blocking request loop

```rust
// crates/sync-server/src/main.rs:511-513
for request in server.incoming_requests() {
    handle(request, &app);
}
```

One request at a time, no async runtime, no thread pool. ADR-0005 documents this
honestly and makes the Postgres adapter swap the path to horizontal scaling, but
as it stands:

- **One slow client stalls every other client.**
- **Request bodies are read unbounded.** `read_to_end` at `main.rs:895` (personal
  vault) and `main.rs:1362` (group blobs) has no size cap. ADR-0004's own STRIDE
  table lists "cap blob and `SharedVault` size" as the DoS mitigation; it is not
  implemented. A single large PUT is both a memory and an availability problem.
- **Rate limiting is per-process** (`main.rs:107-174`), so it is only coherent at
  one replica — ADR-0005 states this.
- **Invite *redemption* is not rate-limited** at all; only mint and register are
  (`main.rs:512-521, 822-831`).

---

## 9. The Stripe checkout call blocks the whole server

`handle_billing_checkout` (`crates/sync-server/src/main.rs:1433-1482`) makes a
**blocking** `ureq` POST to `api.stripe.com` from inside the sequential request
loop. The code says so at `main.rs:1430-1432`. There is no timeout configured, no
retry policy, and no circuit breaker. A slow or hanging Stripe response stalls
every other request on that replica.

Related, on the webhook (`main.rs:1488-1554`):

- No **event-id deduplication** and no **`livemode` check**. Within the 300 s
  tolerance a captured event can be replayed; the operation is idempotent so the
  impact is bounded, but replay is not prevented.
- Any event type other than `customer.subscription.deleted` that carries
  `metadata.account_id` and `metadata.plan` will apply a plan.
- The comment at `main.rs:1534` says the plan metadata is *"set by the client at
  checkout"*. That is **wrong** — it is set server-side at `main.rs:1452-1454`.
  The code is safer than its comment; the comment should be fixed before a
  reviewer is misled in either direction.

---

## 10. Browser-held key material sits in `localStorage`

Three secrets, all as plaintext strings in `localStorage`, all at the same trust
level as the device:

| Key | Contents | Source |
|---|---|---|
| `proctor.passbook.secretkey.v1` | The 128-bit device Secret Key (2SKD factor) | `app/src/lib/passbook.ts:29, 80-95` |
| `proctor.passbook.member.v1` | The member **X25519 secret** (hex) | `app/src/lib/sharing.ts:29, 101-132` |
| `proctor.passbook.sync.v1` | The device bearer token | `app/src/lib/sync.ts:13, 48, 77` |

This is deliberate and documented (`app/src/lib/sharing.ts:8-10`: *"consistent
with how that 2SKD factor is already held on-device (a device compromise is
already fatal)"*). Two consequences worth naming anyway:

- **2SKD's second factor is not really separated.** Both factors live on the
  same device, so 2SKD defends a *server* breach and nothing else.
- **Any XSS or malicious browser extension on the app origin is total
  compromise.** There is no `SubtleCrypto` non-extractable key usage, no
  IndexedDB-with-`CryptoKey` storage, no OS keychain integration on the web path.

ADR-0004 §2 states the member X25519 secret is "stored as an encrypted field
**inside its own vault**", and the WASM doc at
`crates/passbook-wasm/src/lib.rs:220` repeats this. **The web client does not do
that** — it writes the secret to `localStorage` in the clear. The ADR describes
the intended design; the code implements a weaker one.

---

## 10a. Recovery contacts move a 2SKD factor off the device

The recovery-contact feature (`app/src/lib/sharing.ts:299-397`) lets a member
seal their **device Secret Key** to a family member so it can be handed back if
the Emergency Kit is lost. The stated safety property is that the contact still
cannot open the vault, because the master password is the other 2SKD factor and
is never shared. That property is real, and there is a test asserting it
(`crates/passbook/src/sharing.rs:442-476`).

What it costs, stated plainly:

- **A 2SKD factor now leaves the device.** The whole argument for 2SKD is that a
  server breach yields ciphertext plus salt and nothing else. Once a Secret Key
  is sealed into the shared content blob, the relay holds an encrypted copy of
  one factor. It cannot open it — but the claim is no longer "the server never
  holds any part of the second secret."
- **Every group member holds the ciphertext**, not just the addressed contact.
  It lives as a reserved entry inside the shared `ContentBlob`
  (`app/src/lib/sharing.ts:310`), so it is distributed to and re-uploaded by
  everyone, and persists in whatever blob history exists.
- **It compounds §1 and §2a.** `seal_to` takes the contact's public key from the
  relay-served directory and, like `wrap_to`, does not check
  `was_contributory()`. If §1 is exploitable, it is exploitable here too — and
  here the plaintext is a 2SKD factor.
- **Hiding is by title string.** `isRecoveryEntry`
  (`app/src/lib/sharing.ts:325-328`) matches `title === '__recovery__'`. A user
  who creates a real entry with that title collides with the reserved namespace;
  the behaviour is unspecified.
- **If the contact's master password is ever also compromised** — a shared
  household machine, a reused password, a phishing incident — that person holds
  both factors for the sealer's vault.

This is a deliberate usability trade against a real problem (permanent vault
loss). We are not claiming it is wrong. We are claiming it deserves an explicit
verdict from a reviewer rather than an assumption, and it is question **Q8**.

---

## 11. No forward secrecy on stored blobs

Both stored blobs sit under long-lived keys:

- The personal `SealedVault` is keyed by `K = SHA-256(argon2id(master) ‖ sk)` —
  stable for as long as the password and Secret Key are.
- The shared `ContentBlob` is keyed by `K_vault`, rotated only on an explicit
  revoke.
- Member X25519 keys are **static** (`StaticSecret`,
  `crates/passbook/src/sharing.rs:199`), deliberately so, per ADR-0004 §2.

The ephemeral key in each wrap gives per-wrap freshness, **not** forward secrecy:
compromising a member's static secret opens every wrap ever made to them, and
therefore every `K_vault` those wraps carried, and therefore every blob sealed
under those keys. There is no ratchet and no key-epoch scheme.

---

## 12. No formal proof, no test vectors, no fuzzing

What exists: unit tests covering round-trips, wrong-key failure, tampering,
non-member rejection, recovery-by-member, revocation, and the safety number
(`crates/crypto/src/lib.rs:90-134`, `crates/passbook/src/sealing.rs:86-124`,
`crates/passbook/src/sharing.rs:415-637`, plus store contract suites in
`crates/sync/tests/` and `crates/sync-postgres/tests/`).

What does not exist:

- **No known-answer / test vectors.** Nothing pins the wire format or the
  derivations to fixed expected bytes, so a refactor that silently changed a
  derivation would not necessarily fail a test. There is no cross-implementation
  interop check.
- **No formal or symbolic analysis** of the sharing protocol (no Tamarin,
  ProVerif, or equivalent).
- **No fuzzing** of the deserialization surface. `SharedVault`, `ContentBlob`,
  and `SealedVault` all deserialize attacker-controlled JSON from the relay.
- **No negative test for a malicious directory** — no test supplies a hostile or
  low-order public key.
- **No property-based testing** of the rotation/reconcile state machine.
- **No constant-time analysis** beyond the Stripe comparison. Token resolution
  compares hashes with `==` (`crates/sync/src/accounts.rs:290`), and the
  `PROCTOR_SYNC_TOKENS` fallback is a plaintext `HashMap` lookup
  (`crates/sync-server/src/main.rs:592`). Both operate on 128-bit random
  preimages, so we assess the risk as low — but it has not been analyzed.

---

## 13. Smaller items, still true

- **`SecretKey` does not zeroize.** `crates/passbook/src/domain.rs:5` claims
  "Secret-bearing fields zeroize on drop", and `Login`/`Card` do
  (`domain.rs:36-43, 54-59`). `SecretKey` (`domain.rs:130-131`) derives only
  `Clone` — no `Drop`, no `Zeroize`. Its `String` forms are not wiped either.
- **No checksum on the Secret Key.** `parse` (`domain.rs:150-161`) strips
  non-hex and requires 32 digits. A transcription error from the Emergency Kit is
  indistinguishable from a wrong key — it surfaces only as "cannot decrypt".
- **Argon2 parameters are library defaults**, never tuned or measured
  (`crates/crypto/src/lib.rs:60`). In the browser a 19 MiB, t=2 derivation runs on
  the main thread.
- **The sealed envelope is unversioned.** No format tag on `SealedVault`,
  `ContentBlob`, or `SharedVault`, so there is no in-band signal for a future
  format migration.
- **Two RNG disciplines.** The crypto kernel uses `OsRng`; the relay uses
  `rand::random::<u128>()` (`crates/sync/src/groups.rs:29`,
  `crates/sync/src/accounts.rs:172`). Both are CSPRNGs; the inconsistency is
  worth resolving so the discipline is auditable at a glance.
- **`Math.random()` for member ids** (`app/src/lib/sharing.ts:128`) — not a
  CSPRNG. Compounds §4.
- **Any Member can overwrite `/keys` and `/vault`.** Those handlers gate on
  membership, not role (`crates/sync-server/src/main.rs:1339-1342`).
- **`PROCTOR_SYNC_TOKENS`** accepts plaintext `token:account` pairs from an
  environment variable and bypasses token hashing entirely
  (`crates/sync-server/src/main.rs:516-523, 587-596`). Intended for tests; it
  ships in the production binary.
- **CORS is `Access-Control-Allow-Origin: *`** on every response
  (`crates/sync-server/src/main.rs:532`). Authentication is bearer-header, not
  cookie, so this is not CSRF-exposed — but any origin can drive the API with a
  token it obtains.
- **`/metrics` is unauthenticated** (`main.rs:645-648`), documented as
  "keep cluster-internal". The family-sharing funnel counters described in the
  module docs (`main.rs:39-45`) **were implemented during the writing of this
  package** and now exist (`Metrics`/`Funnel`, `main.rs:216-262`;
  `render_metrics`, `main.rs:335`). They are deliberately aggregate — the code
  asserts that no label carries an account, group, member, device, or IP
  dimension, with a test enforcing it. The residual is only that the endpoint has
  no authentication of its own and relies on network placement.
- **`revoke_group_member` is exposed to WASM but never called** by the app
  (`crates/passbook-wasm/src/lib.rs:341-345`); `revokeMember` rebuilds the
  `SharedVault` from scratch instead. Dead path, worth pruning or wiring.

---

*Next: [`review-scope.md`](review-scope.md) turns this list into ordered
questions. Full detail in [`cryptography-spec.md`](cryptography-spec.md) and
[`threat-model-passbook.md`](threat-model-passbook.md).*
