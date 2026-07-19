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

## 1. X25519 contributory behaviour — CLOSED (was: not checked)

**Status: fixed. This section previously described a defect the code no longer
has, and said so while the fix was already committed.**

`crates/passbook/src/sharing.rs` defines `checked_secret`, which rejects a
non-contributory X25519 result, and calls it at **all four** DH sites
(`wrap_to`, `unwrap_for`, `seal_to`, `open_sealed`). A relay-supplied low-order
point therefore fails closed with `SharingError::WeakKey` instead of producing
the all-zero shared secret and a publicly computable wrapping key. Regression
test: `low_order_public_keys_are_rejected`.

Why this entry is called out rather than quietly deleted: the fix and this
document landed in the **same commit** (`f970478`), so the review package was
stale the moment it was published. `review-scope.md` then named a
proof-of-concept for this as the single thing it most wanted a reviewer to
attempt — i.e. it directed a paid auditor at a hole that provably fails closed.
Documentation that misstates the code in the *pessimistic* direction is not
harmless: it burns engagement hours and, once an auditor finds one such claim,
they rightly stop trusting the rest of the package and re-derive everything from
source at your expense.

**The real residual is not here — it is §3.** Rejecting low-order points stops a
*degenerate* key. It does nothing about a relay that supplies a perfectly valid
public key whose secret it holds, which is the actual attack.

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

## 2a. Domain separation between the two protocols — CLOSED

**Status: fixed. As with §1, this section described a defect that was already
repaired in the same commit that published it.**

The recovery-contact seal and the vault-key wrap derive from **different**
labels: `sharing.rs` defines `SEALED_BOX_INFO` for `seal_to`/`open_sealed`,
distinct from `HKDF_INFO` used by `wrap_to`/`unwrap_for`. The separation is
asserted by test, not merely by inspection —
`recovery_and_vault_wrapping_use_separate_derivations` includes
`assert_ne!(HKDF_INFO, SEALED_BOX_INFO)`, so collapsing them back into one label
fails the build.

The residual concern in the original text still stands, though, and is NOT
closed: **neither ciphertext carries associated data.** `wrap_to` encrypts the
vault key with no AAD binding it to a group, a member id, or a key epoch, so a
wrap is not cryptographically tied to the context it was produced for. That is
tracked as part of §3a below rather than here.

---

## 3. Access grants require a human decision — CLOSED (was: automatic)

**Status: fixed.** `loadFamily` no longer wraps the vault key to whatever the
relay reports. The client pins the public key it has accepted for each member
(trust-on-first-use, `app/src/lib/sharing.ts`) and classifies every member as
`pinned`, `unknown`, or `changed`. Only `pinned` keys are granted automatically;
the other two are surfaced for an explicit decision and **nothing is uploaded**
until the user acts. `approveMember()` re-reads the directory and refuses if the
key changed since it was displayed.

The ordering bug is fixed with it: the safety number used to be computed for
display *after* the grant had already been uploaded, so a user obeying the
in-app instruction ("if it differs, stop") stopped after the key had left.

**Residual, unchanged:** TOFU takes the first key on faith. A relay hostile from
the very first load can still substitute at that moment; comparing the safety
number out of band is what closes it, and nothing forces that comparison. And
pinning does not address §3a at all, which needs no grant from us.

---

## 3a. Wraps carry no sender authentication — substitution now DETECTABLE, still not preventable

**Partially closed. Read the distinction carefully.**

`wrap_to` still requires only a recipient public key, still carries no
signature, and `safety_number` still digests only member ids and public keys —
so a relay can mint its own vault key, wrap it correctly to every genuine
member, overwrite both blobs, and every member decrypts successfully with an
unchanged safety number.

**What changed:** the client now pins a fingerprint of the vault key it has
accepted (`vaultKeyPins`). On any later load where the unwrapped key differs, it
refuses to decrypt entries, refuses to re-seal anything, and surfaces the change
for an explicit human decision. Previously the substitution was completely
invisible — nothing anywhere noticed, and the first subsequent save re-sealed
every shared credential under the attacker's key.

**What has NOT changed:** this is detection, not prevention. A relay can still
perform the substitution; it just cannot do so unobserved, and cannot obtain
plaintext without a member actively accepting the new key.

**The residual, and it is real:** a change is genuinely ambiguous. Any member
revoking someone rotates the key, and a device that did not initiate that
rotation sees exactly what an attack looks like. The UI therefore leads with the
benign explanation and asks the user to confirm out of band that someone was
removed. A user conditioned to click through will hand over the vault. Rotation
being an ordinary event is what makes this weaker than a cryptographic control.

### The signature half is now implemented (F2)

Wrapped-key sets are **signed**. A member holds an Ed25519 key alongside their
X25519 one, signs the set on every write (share, grant, revoke), and a reader
verifies against a signing key it has **pinned locally** — never one taken from
the same relay that served the blob, which would prove nothing.

That closes the forgery. A relay can no longer mint a vault key and wrap it to
everyone, because it cannot produce a signature any member's pin accepts.

**Three things are still open, and none of them are small:**

1. **Rollback — closed.** Each wrapped-key set carries a monotonic epoch
   INSIDE the signed payload, so it cannot be edited without breaking the
   signature. Every mutation advances it (a no-op revoke does not, or a relay
   could pump the epoch by replaying harmless removals). Revocation rotates
   *from* the current set rather than building a fresh one, which would restart
   at epoch 1 and let the relay replay the higher-ranked pre-revocation set. The
   client pins the highest VERIFIED epoch per group and refuses anything lower.

   Equal epochs are now treated as a **fork**, not a duplicate: the client pins
   the accepted set's digest alongside its epoch, and refuses a same-epoch set
   with a different digest. Without that, a relay could serve different members
   different sets at the same epoch and split the family onto two vault keys
   while every signature and epoch check passed.

   Residual: a fork is *detected*, not resolved. The user is told to reload and
   to compare the safety number if it persists.

2. **Trust-state durability — CLOSED.** Member pins, the vault-key pin, the
   epoch floor, and the "this group is signed" flag now live in the **synced,
   encrypted vault** (`app/src/lib/trust.ts`), as a reserved entry beside the
   user's items. They are therefore covered by the vault's AEAD and 2SKD: the
   relay stores them as opaque ciphertext and cannot read or edit them, they
   survive a browser wipe, and they reach every device the account unlocks on.

   That last part fixed a second problem that was never written down: a new
   device started from nothing, so the user was asked to approve people they had
   already approved elsewhere. Trust decisions that must be repeated get made
   carelessly, which turns the approval gate into a formality.

   `localStorage` remains as a cache so the UI can read synchronously and an
   unsynced device still knows what it knew. The vault is authoritative.

   **Merge rules**, since two devices can disagree. Every automatic resolution
   moves toward MORE suspicion; genuine ambiguity goes to the human path that
   already exists:
   - *epochs* — highest wins (monotonic, so safe).
   - *signed* — union; "this group uses signatures" is one-way and must never
     be un-learned, or signature-stripping stops being detectable.
   - *pins* — union, but a conflict keeps the **local** pin. Not because local
     is more trustworthy: keeping it makes the relay-served key read as
     `changed` and routes to explicit approval. Preferring the remote value
     would silently adopt a key this device never agreed to.
   - *vault keys* — same conflict rule, surfacing as "this vault's key changed".

   Residual: a device that has *never* synced still starts empty, and the
   wiped-state warning is what covers that.

3. **First contact — partly closed.** The signing key is pinned
   trust-on-first-use, same as the X25519 key, so a relay hostile from the very
   first sight of a member can substitute both at once. The safety number now
   covers signing keys as well (context label bumped to v2), so a family
   comparing it out of band WILL see a fabricated signing key — previously that
   was invisible, because the number digested only the X25519 halves and so
   matched everyone else's exactly.

   What remains is that this depends on humans actually comparing the number.
   It is detection contingent on a manual step, not prevention. Approving a
   member now requires ticking an explicit "I compared the safety number with
   them directly" confirmation, which resets whenever the directory changes —
   instructions alone were not enough, because the buttons worked whether or not
   anyone read them. A tick is not proof, but it makes approving without
   checking a deliberate act rather than the default one. Note also that
   the number changed for every existing group; the UI says so, because a family
   comparing against one they wrote down earlier would otherwise read a benign
   version bump as an attack.

3. **The legacy path.** Vaults created before signing have unsigned sets. They
   stay readable, flagged, with an explicit "sign these" action, because
   bricking existing families would be worse. To stop that being a downgrade
   channel, a client that has ever seen a signed set for a group records it and
   refuses an unsigned one for that group thereafter (HSTS-style). A device that
   has never seen the group signed has no such protection.

**Still Q2a, still unreviewed.** Implementing a signature is not the same as
having the construction validated. The canonical encoding, the decision to use a
separate Ed25519 key rather than deriving from X25519, and the pinning
lifecycle are all exactly the kind of thing an external cryptographer should
disagree with before this is relied upon.

## 4. `member_id` uniqueness — CLOSED (was: unenforced)

**Status: fixed, and the way it was broken is worth recording.**

`apply_redeem` now rejects a `member_id` already held by a different account, in
the **shared policy function**, so every adapter enforces it.

Previously the invariant held only where a storage backend happened to imply it:
Postgres declared `PRIMARY KEY (group_id, member_id)`, so a collision surfaced
there as a constraint violation and a 500, while the file and memory stores —
the self-host defaults — accepted it silently. The comment claiming both
adapters "share the exact policy" was false, and the managed instance was
protected by accident rather than by design.

Postgres also expressed redemption and removal as bespoke SQL rather than
calling the shared policy, so it skipped every invariant that policy gained.
Both now load, apply the shared function, and persist the result. The membership
invariants are asserted in the shared **contract suite**, which runs against
memory, file, and a real Postgres.

**Worth generalising for review:** look for other invariants enforced
incidentally by a storage layer rather than deliberately by the policy layer.

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
