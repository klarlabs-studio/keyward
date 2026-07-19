# Keyward — Cryptography Specification (implementation-accurate)

> **Scope:** the consumer vault (**Passbook**), **family sharing**, and the
> **sync relay**. Describes what the code does at the referenced revision, not
> what the design documents intend. Where code and ADR disagree, both are stated.
>
> **Status:** unreviewed. No external cryptographic review has been performed.

Every construction below carries `file:line` pointers. Verify rather than trust.

---

## 0. Primitive inventory and dependency versions

| Primitive | Crate | Version (Cargo.lock) | Used for |
|---|---|---|---|
| Argon2id | `argon2` | 0.5.3 | Master-password stretching |
| XChaCha20-Poly1305 | `chacha20poly1305` | 0.10.1 | All AEAD (vault, wraps, content) |
| X25519 | `x25519-dalek` | 2.0.1 (`static_secrets`, `zeroize`) | Per-recipient key wrapping |
| HKDF-SHA256 | `hkdf` | 0.12.4 | Wrapping-key derivation |
| SHA-256 | `sha2` | 0.10 | 2SKD fold, safety number, token/invite hashing |
| HMAC-SHA256 | `hmac` | 0.12 | Stripe webhook verification |
| CSPRNG | `rand` | 0.8.7 (`OsRng`); `getrandom` 0.2.17 (`js` on wasm32) | Salts, nonces, keys, ids |

The shared kernel is `crates/crypto/src/lib.rs` — a deliberately tiny surface
(`fill_random`, `random_array`, `derive_key_argon2id`, `aead_seal`, `aead_open`)
that makes no policy decisions. Constants (`crates/crypto/src/lib.rs:25-29`):

```
SALT_LEN  = 16   // bytes
NONCE_LEN = 24   // bytes (XChaCha20 extended nonce)
KEY_LEN   = 32   // bytes
```

**Randomness.** The kernel uses `OsRng` exclusively (`crates/crypto/src/lib.rs:21,
41, 47`). On `wasm32-unknown-unknown` this resolves to Web Crypto via the
`getrandom` `js` feature, opted into at
`crates/passbook-wasm/Cargo.toml` (`[target.'cfg(target_arch = "wasm32")']`).
**Note the inconsistency:** the *relay* uses `rand::random::<u128>()` instead
(`crates/sync/src/groups.rs:29`, `crates/sync/src/accounts.rs:172`), i.e. the
thread-local ChaCha12 CSPRNG rather than `OsRng`. That is still cryptographically
secure, but it is a different discipline in the same codebase.

---

## 1. Personal vault sealing, and the 2SKD key derivation

**Purpose.** Encrypt a user's entries at rest so that neither a stolen device
file nor a breached sync server yields plaintext without *both* the master
password and the device Secret Key.

**Implementation.** `crates/passbook/src/sealing.rs`.

### 1.1 Key derivation

`derive_key` (`crates/passbook/src/sealing.rs:23-40`):

```
mk  = Argon2id(password = master, salt = salt, out_len = 32)

if secret_key present:   K_vault_personal = SHA-256( mk ‖ secret_key )      // 32 ‖ 16 bytes
else:                    K_vault_personal = mk
```

**Argon2 parameters.** `Argon2::default()` (`crates/crypto/src/lib.rs:60`), i.e.
`argon2` 0.5.3's `Params::DEFAULT`: **Argon2id, version 0x13 (19), m_cost =
19456 KiB (19 MiB), t_cost = 2, p_cost = 1, output 32 bytes**, no secret key
(pepper), no associated data. These are the crate defaults, not values Keyward
chose deliberately — the kernel's own header calls them "prototype-grade
parameters" needing tuning (`crates/crypto/src/lib.rs:13-14`).

**The 2SKD fold.** The Secret Key is mixed in by a *bare SHA-256 of a
concatenation*, not by an HKDF and not under a domain-separation label. Both
inputs are fixed-length (32 and 16 bytes), so there is no concatenation
ambiguity, but there is also nothing distinguishing this hash from any other
SHA-256 use in the system.

> **Open question for the implementer:** was `SHA-256(mk ‖ sk)` chosen over
> `HKDF-SHA256(ikm = mk, salt = sk, info = "…")` or over passing `sk` as
> Argon2's `secret` (pepper) parameter for a stated reason? The code and ADR-0004
> both describe the construction but neither records the rationale.

### 1.2 Wire format

`SealedVault` (`crates/passbook/src/sealing.rs:43-50`), serialized with
`serde_json`:

| Field | Type | Notes |
|---|---|---|
| `salt` | `[u8; 16]` | Fresh per seal (`sealing.rs:58`) |
| `nonce` | `[u8; 24]` | Fresh per seal (`sealing.rs:59`) |
| `secret_key_protected` | `bool` | **Public, and not authenticated** — see below |
| `ciphertext` | `Vec<u8>` | XChaCha20-Poly1305 over `serde_json(entries)` |

`seal` (`sealing.rs:53-70`) generates a fresh salt **and** a fresh nonce on every
seal, so nonce reuse under a fixed key would require a 24-byte random collision.
There is **no AAD**: `aead_seal` (`crates/crypto/src/lib.rs:67-76`) calls
`cipher.encrypt(nonce, plaintext)` with no associated data, so `salt`,
`nonce`, and `secret_key_protected` are unauthenticated. Flipping
`secret_key_protected` causes the client to derive a different key and fail to
decrypt — fail-closed, but a reviewer should confirm no path treats that flag as
a security decision rather than a hint.

There is **no format/version tag** on `SealedVault`. ADR-0004 §1 anticipated one
("A version tag on the sealed envelope distinguishes the two formats"); the
v1.29.0 refinement note in that ADR explains why it was never needed (the
personal format was left untouched). The consequence stands: the envelope is
unversioned, so a future format change has no in-band signal.

### 1.3 Key lifetime

`derive_key` returns `Zeroizing<[u8; 32]>` and the plaintext is held in
`Zeroizing<Vec<u8>>` (`sealing.rs:29, 61, 79`), so both wipe on drop in the Rust
layer. In the browser, the derived key never leaves WASM linear memory, but WASM
memory is not zeroed by the host and the *entries JSON* crosses the JS boundary
as an ordinary string (`crates/passbook-wasm/src/lib.rs:172`) — garbage-collected,
not wiped.

---

## 2. The Secret Key

**Purpose.** The second factor in 2SKD: a device-generated secret that never
leaves the device and is not derived from anything the user knows, so a server
that holds ciphertext plus salt cannot mount an offline guessing attack against
the master password alone.

**Implementation.** `crates/passbook/src/domain.rs:127-168`.

- **Length: 16 bytes / 128 bits** (`domain.rs:131`), generated with
  `random_array::<16>()` → `OsRng` (`domain.rs:136`).
- **Emergency Kit format:** uppercase hex, grouped in 4-character chunks joined
  by `-` — 32 hex digits → 8 groups, e.g. `A3F1-9C2B-…` (`domain.rs:140-147`).
- **Parsing:** all non-hex characters are stripped, then exactly 32 hex digits
  are required (`domain.rs:150-161`). Grouping, case, and separators are ignored.
  There is **no checksum**, so a mistyped Secret Key is indistinguishable from a
  wrong one — it surfaces only as a decryption failure.
- **Exposure:** `bytes()` is `pub(crate)` (`domain.rs:165`), reachable only by
  the sealing service.

**Zeroization gap.** `domain.rs:5` states "Secret-bearing fields zeroize on
drop", and `Login`/`Card` do implement `Drop` with `zeroize()` (`domain.rs:36-43, 54-59`). **`SecretKey` does not** — it derives only `Clone`, with no `Drop`,
`Zeroize`, or `ZeroizeOnDrop` impl. The `String` forms produced by
`emergency_kit_format` and consumed by `parse` are likewise not wiped.

**Where it lives, and for how long.** In the browser app the Secret Key is
persisted as a plain string in `localStorage` under
`keyward.passbook.secretkey.v1` (`app/src/lib/passbook.ts:29, 80-95`), alongside
the sealed vault at `keyward.passbook.vault.v1` (`passbook.ts:25`). It persists
until the vault is reset (`passbook.ts:74-75`). This is a deliberate, documented
choice — the client treats a device compromise as already fatal
(`app/src/lib/sharing.ts:8-10`) — but it means the "second secret" of 2SKD sits
next to the ciphertext it protects, on the same device, at the same trust level.

---

## 3. Per-recipient vault-key wrapping (the sealed box)

**Purpose.** Distribute one symmetric **vault key** `K_vault` to N family members
without the relay ever seeing it, and without members needing a shared password.

**Implementation.** `crates/passbook/src/sharing.rs`.

### 3.1 Member identity

`Member` (`sharing.rs:194-239`) holds an X25519 `StaticSecret`:

- `Member::generate` — `StaticSecret::random_from_rng(OsRng)` (`sharing.rs:208`).
- `Member::from_secret` — rebuild from stored 32 bytes (`sharing.rs:216-222`).
- `Member::secret_bytes` — export for at-rest storage (`sharing.rs:227`).
- `MemberPublic { id: String, name: String, public_key: [u8; 32] }`
  (`sharing.rs:256-263`) is the only half ever published.
- `Debug` is hand-written to print `<redacted>` for the secret (`sharing.rs:241-250`).
- The secret zeroizes on drop via `x25519-dalek`'s `zeroize` feature
  (declared in `crates/passbook/Cargo.toml`).

The identity is **stable and independent of the master password** — ADR-0004 §2
records the rationale (a password change must not invalidate every wrap other
members made to you).

### 3.2 The wrap

`SharedVault::wrap_to` (`sharing.rs:310-342`), per recipient:

```
(esk, epk)  = X25519 keygen, fresh per recipient per wrap        # sharing.rs:312-313
ss          = X25519(esk, recipient_pub)                         # sharing.rs:316
K_wrap      = HKDF-SHA256(ikm = ss, salt = None, info = HKDF_INFO, L = 32)
                                                                 # sharing.rs:406-412
nonce       = 24 random bytes (OsRng)                            # sharing.rs:322-323
ct          = XChaCha20-Poly1305(K_wrap, nonce, K_vault)         # sharing.rs:324-326
```

**Domain-separation label** (`sharing.rs:39`):

```
HKDF_INFO = b"keyward-passbook family-share v1"
```

**HKDF salt is `None`** (`sharing.rs:407`), i.e. HKDF-Extract runs with an
all-zero salt of hash length. That is standard and permitted by RFC 5869.

**What the KDF does *not* bind.** `info` is a *constant*. It does not include
the ephemeral public key, the recipient's public key, the `member_id`, or the
group id. Compare `libsodium`'s `crypto_box_seal`, which derives its nonce as
`BLAKE2b(epk ‖ rpk)` and therefore binds both. Consequences are discussed in
[`known-limitations.md`](known-limitations.md) and are a priority question in
[`review-scope.md`](review-scope.md).

**No AAD.** The AEAD is called with plaintext only (`sharing.rs:324-326`), so
`member_id` and `ephemeral_public` in the stored record are unauthenticated
metadata. Tampering with them yields a decryption failure rather than a
substitution, but they are not covered by the tag.

### 3.3 Wire format

`WrappedKey` (`sharing.rs:267-276`) and `SharedVault` (`sharing.rs:283-285`),
serialized as JSON (`crates/passbook-wasm/src/lib.rs:284`) and stored by the
relay as an opaque `Vec<u8>` (`crates/sync/src/groups.rs:141`):

```json
{ "wrapped": [
    { "member_id": "...",           // String, client-chosen
      "ephemeral_public": [32 bytes],
      "nonce": [24 bytes],
      "ciphertext": [48 bytes]      // 32-byte key + 16-byte Poly1305 tag
    }, ... ] }
```

`wrap_to` replaces an existing entry with the same `member_id` rather than
appending (`sharing.rs:335-340`) — so `member_id` is the identity key of the
whole structure.

### 3.4 The unwrap

`SharedVault::unwrap_for` (`sharing.rs:348-375`): find the entry by `member_id`
→ `X25519(member_secret, ephemeral_public)` → same HKDF → AEAD open → assert the
plaintext is exactly 32 bytes (`sharing.rs:369-371`) → return. Errors are
distinguished as `NotAMember` (no entry) vs `Unwrap` (decryption failed), which
is an intentional, non-secret distinction.

### 3.5 Key lifetime

- `K_wrap` is `Zeroizing<[u8; 32]>` (`sharing.rs:408`).
- The unwrapped plaintext is `Zeroizing<Vec<u8>>` (`sharing.rs:361`) but the
  **returned `[u8; 32]` vault key is a bare array** (`sharing.rs:372-374`) — the
  caller owns zeroization, and the WASM binding immediately hex-encodes it into a
  JS string (`crates/passbook-wasm/src/lib.rs:299`). From that point the vault
  key is a garbage-collected JavaScript string for the lifetime of the operation.

---

## 4. The shared ContentBlob

**Purpose.** The actual shared entries, encrypted once under `K_vault` — not
per-recipient. Every member decrypts the same ciphertext with the key they
unwrapped.

**Implementation.** `crates/passbook/src/sharing.rs:71-75, 169-186`.

```
K_vault  = 32 random bytes (OsRng)                          # sharing.rs:172-174
nonce    = 24 random bytes (OsRng)                          # sharing.rs:178
ct       = XChaCha20-Poly1305(K_vault, nonce, plaintext)    # sharing.rs:179
```

Wire format (JSON): `{ "nonce": [24 bytes], "ciphertext": [...] }`.

Plaintext is `serde_json` of `Vec<Entry>` (`crates/passbook-wasm/src/lib.rs:256`).
No AAD; no version tag; no binding to the group id or to the `SharedVault` that
distributes the key. A fresh nonce is drawn on every seal, and every save
re-seals the whole set (`app/src/lib/sharing.ts:571`), so the blob size leaks the
approximate size of the shared vault to the relay.

**Deliberate design note.** ADR-0004's v1.29.0 refinement records that this blob
is *entirely separate* from the personal `SealedVault` — the personal format was
left byte-for-byte unchanged and needs no migration. The owner is simply member
#0 of the `SharedVault`; there is no `K_acct`-wrap of `K_vault`.

---

## 5. `grant_access` — recovery and completion-by-member

**Purpose.** Let *any* existing member admit a new member, without the original
vault-key holder being online. This is also the account-recovery story.

**Implementation.** `SharedVault::grant_access` (`sharing.rs:383-390`):

```
K_vault = unwrap_for(existing_member)     // proves the caller has access
wrap_to(K_vault, new_member)              // §3.2
```

`K_vault` is held in `Zeroizing` across the call (`sharing.rs:388`).

**The authorization check is purely cryptographic.** `grant_access` verifies that
the *granting* member can unwrap. It performs **no check whatsoever on the
recipient** — not the key, not the id, not who vouched for them. The recipient's
`MemberPublic` is whatever the caller passes in.

**Who calls it.** `app/src/lib/sharing.ts:511-534`, inside `loadFamily`:

```ts
const missing = group.members.filter((m) => !wrappedIds.has(m.member_id));
for (const m of missing) {
  updated = grant_group_access(updated, member.secret, member.id, JSON.stringify(m));
}
```

Any member's client, on any load of the family vault, silently wraps `K_vault` to
**every** directory entry the relay reports as lacking a wrap. No prompt, no
confirmation, no safety-number comparison first. ADR-0004 §4 step 3 describes
this step as "a human decision"; as implemented it is an automatic background
reconciliation. This is called out in
[`known-limitations.md`](known-limitations.md) §3 and is question Q4 in
[`review-scope.md`](review-scope.md).

---

## 5b. Recovery contacts (the `SealedBox`)

> **Recency warning.** This construction landed *while this document was being
> written*. It is the newest and least-examined code in scope, and it is the only
> place where a 2SKD factor deliberately leaves the device.

**Purpose.** Losing the Emergency Kit otherwise means losing the vault forever. A
member seals their **device Secret Key** to another family member, who can hand
it back later. The stated safety property (`crates/passbook/src/sharing.rs:121-124`)
is that the contact still cannot open the vault, because the Secret Key is only
one of the two 2SKD factors and the master password is never shared.

**Implementation.** `crates/passbook/src/sharing.rs:120-165`.

```
esk, epk = X25519 keygen (fresh)                              # sharing.rs:134-135
ss       = X25519(esk, contact_public)                        # sharing.rs:136
K_wrap   = derive_wrapping_key(ss)                            # sharing.rs:137  ← SAME as §3.2
nonce    = 24 random bytes (OsRng)                            # sharing.rs:141-142
ct       = XChaCha20-Poly1305(K_wrap, nonce, plaintext)       # sharing.rs:143-145
```

Wire format — `SealedBox` (`sharing.rs:126-130`), JSON:
`{ "ephemeral_public": [32], "nonce": [24], "ciphertext": [...] }`.

Note it carries **no `member_id`**, unlike `WrappedKey` (§3.3). `open_sealed`
(`sharing.rs:156-165`) simply attempts decryption with the member's secret.

**This reuses `derive_wrapping_key` verbatim** — the same HKDF-SHA256 with the
same constant `HKDF_INFO` (`b"keyward-passbook family-share v1"`) as the
vault-key wrap. Two distinct protocols, carrying different plaintext types, now
share one derivation with **no separating label** and no type tag or AAD on
either ciphertext. See [`known-limitations.md`](known-limitations.md) §2a and
question **Q8** in [`review-scope.md`](review-scope.md).

**Where the blob lives.** Not at a new endpoint. The client stores it as a
**reserved entry inside the shared ContentBlob**, titled `__recovery__`
(`app/src/lib/sharing.ts:310`), carrying a JSON payload
`{ for, forName, to, toName, sealed }` in a `SecureNote`
(`app/src/lib/sharing.ts:313-322, 359-389`). Consequences:

- It syncs with the family automatically and needs no server change.
- **Every group member holds the ciphertext**, and so does the relay; only the
  addressed contact can open it.
- It is re-uploaded on every content save, and old copies persist wherever any
  member's blob history does.
- Recovery entries are hidden from the item list by **title match**
  (`isRecoveryEntry`, `app/src/lib/sharing.ts:325-328`;
  `visibleEntries`, `:330-332`).

**Bindings.** `seal_recovery` / `open_recovery`
(`crates/passbook-wasm/src/lib.rs:326-344`). `open_recovery` reconstructs a
`Member` with an **empty id and name** (`lib.rs:341`), which is sound here only
because `SealedBox` is not addressed by id.

> **Open question for the implementer:** was reusing `HKDF_INFO` across the
> vault-key wrap and the recovery sealed box deliberate? And what is the intended
> behaviour if a user creates a genuine entry titled `__recovery__`?

---

## 6. Revocation and key rotation

Two mechanisms exist, at different layers.

### 6.1 `SharedVault::revoke` — wrap removal only

`sharing.rs:398-402` drops the member's `WrappedKey` and returns whether one was
removed. Its own doc comment (`sharing.rs:394-397`) states the limit plainly:
this "does not rotate the vault key, so a member who already read the key retains
it." Exposed to WASM as `revoke_group_member`
(`crates/passbook-wasm/src/lib.rs:341-345`) — **but the app never calls it.**

### 6.2 The client's rotate-on-revoke protocol

`app/src/lib/sharing.ts:599-628`, in order:

1. `DELETE /v1/groups/{id}/members/{mid}` — relay drops the directory entry.
2. `GET /v1/groups/{id}` — re-read the directory; filter out the removed id.
3. `generate_vault_key()` — a **fresh** `K_vault'`.
4. `share_vault_key(K_vault', remaining)` — build a **brand-new** `SharedVault`
   from scratch (not a mutation of the old one).
5. `seal_group_content(currentEntries, K_vault')` — re-seal the caller's
   in-memory entries.
6. `PUT /keys` with `If-Match: keys.version`, then `PUT /vault` with
   `If-Match: content.version`.

**The two writes are not atomic and not transactional.** There is no server-side
notion of "rotate"; the relay sees two independent optimistically-concurrent blob
writes. Failure modes are enumerated in
[`known-limitations.md`](known-limitations.md) §5.

**Server-side authorization** (`crates/sync-server/src/main.rs:1211-1248`):
removal requires Admin or Owner (`Role::can_manage_members`,
`crates/sync/src/groups.rs:82-84`), and an Owner can never be removed by anyone
(`main.rs:1215-1221`). The relay explicitly does **not** rotate anything — its
doc comment says so (`main.rs:1208-1210`).

---

## 7. The safety number

**Purpose.** The mitigation for the key-substitution / directory-trust risk that
ADR-0004 names as its "known open item (must be closed before GA)". A short
human-comparable fingerprint of the group's *public* membership.

**Implementation.** `safety_number` (`crates/passbook/src/sharing.rs:93-115`).

```
sorted = members sorted by id (ascending)               # order-independent
h = SHA-256( SAFETY_NUMBER_INFO
           ‖ for each m in sorted:
                 be_u32(len(m.id)) ‖ m.id_bytes ‖ m.public_key )
render: for each 4-byte chunk c of the 32-byte digest:
             printf("%05d", be_u32(c) mod 100000)
        joined by spaces → 8 groups of 5 digits
```

**Domain-separation label** (`sharing.rs:77`):

```
SAFETY_NUMBER_INFO = b"keyward-passbook group-safety-number v1"
```

Properties, all covered by the test at `sharing.rs:477-517`:

- **Order-independent** — members are sorted by id first (`sharing.rs:94-95`).
- **Length-prefixed ids** — so `("ab","c")` and `("a","bc")` cannot collide by
  concatenation ambiguity (`sharing.rs:101`).
- **Detects substitution and silent addition** — changing any member's public
  key, or adding a recipient, changes the number.

**Two properties worth a reviewer's attention:**

1. **`name` is not hashed.** Only `id` and `public_key` enter the digest
   (`sharing.rs:102-103`). A relay may therefore relabel a member's display name
   arbitrarily — e.g. present an attacker-controlled member as "Mom" — without
   changing the safety number that the family compares.
2. **Truncation.** `mod 100_000` keeps ~16.6 bits per 4-byte chunk; 8 chunks give
   roughly **133 bits** of the 256-bit digest. That is ample for the threat
   (second-preimage on a directory), but it *is* a truncation and should be
   judged as one.

**Where it surfaces.** Computed client-side from the directory the relay just
served (`app/src/lib/sharing.ts:73-80, 497`) and carried on `FamilyVault.safety`
(`sharing.ts:93`). It is displayed; **it is not enforced anywhere**, and nothing
in the protocol blocks on it.

---

## 8. Invite codes

**Generated server-side.** `crates/sync-server/src/main.rs:1114` calls
`groups::new_id()`:

```rust
// crates/sync/src/groups.rs:28-30
pub fn new_id() -> String { format!("{:032x}", rand::random::<u128>()) }
```

So an invite code is **128 bits of CSPRNG output rendered as 32 lowercase hex
characters** — from `rand::random` (thread-local ChaCha12), not `OsRng`.

**Stored hashed.** `groups::hash_code` (`crates/sync/src/groups.rs:35-43`) is a
plain, **unsalted, single-round SHA-256**, hex-encoded. Because the preimage is
128 bits of uniform randomness, an unsalted fast hash is appropriate here — there
is nothing to brute-force. `GroupInvite` (`groups.rs:118-128`) stores
`{ code_hash, created_epoch, expires_epoch, redeemed_by }` — never the code.

**Lifecycle.**

- Minted by Admin or Owner only (`main.rs:1088-1108`); a plain Member gets 403.
- TTL from the request body, default **24 h**, must be `> 0`
  (`main.rs:1109-1113`); the client sends 24 h explicitly
  (`app/src/lib/sharing.ts:450`).
- Returned in plaintext **once**, in the mint response (`main.rs:1105-1108`).
- **Single-use**, enforced atomically in the store via `apply_redeem`
  (`crates/sync/src/groups.rs:256-283`): already-redeemed → `InvalidOrUsed`;
  `now >= expires_epoch` → `Expired`.
- Shared out of band as `"{group_id}.{code}"` (`app/src/lib/sharing.ts:399-411`).

**What redemption grants.** Redeeming publishes a `MemberPublic` into the
directory and nothing more (`main.rs:1144-1180`). It carries **no key material**.
Access requires a subsequent `grant_access` by an existing member (§5).

**Note on `member_id`.** The redeemer supplies `member_id`, `name`, and
`public_key` in the request body (`main.rs:1146-1156`). The relay does **not**
validate `member_id` for uniqueness; `apply_redeem` deduplicates on `account_id`
only (`crates/sync/src/groups.rs:273-281`). See
[`known-limitations.md`](known-limitations.md) §4.

---

## 9. Device tokens

**Generated server-side**, 128-bit hex, same generator as invite codes:
`random_hex_id()` (`crates/sync/src/accounts.rs:171-174`).

**Stored hashed** — unsalted single-round SHA-256, hex (`accounts.rs:178-181`).
Same reasoning as invite codes: the preimage is 128 uniform bits. The plaintext
token is returned exactly once, at register or add-device
(`accounts.rs:231-256`), and never persisted server-side.

**Lifecycle** (`crates/sync/src/accounts.rs`):

- `register` — new account id + first device (`accounts.rs:259-273`).
- `add_device` — mint an additional token for the same account
  (`accounts.rs:276-284`), gated by the plan's device limit at
  `crates/sync-server/src/main.rs:733-753` (Free = 2, paid = unlimited,
  `accounts.rs:109-114`).
- `resolve_token` — linear scan over accounts/devices comparing token hashes
  with `==` (`accounts.rs:285-303`); expired tokens do not resolve.
- `rotate_token` — same device id/label/expiry, fresh secret
  (`accounts.rs:305-325`).
- `revoke_device` — the lost-device story.
- **Expiry is optional and off by default** — `KEYWARD_SYNC_TOKEN_TTL` unset or
  `0` means tokens never expire (`main.rs:246-253`).

**Where the token lives on the client.** `localStorage`, under
`keyward.passbook.sync.v1` (`app/src/lib/sync.ts:13, 48, 77`). It is the bearer
credential for both the personal vault and every group endpoint
(`app/src/lib/sharing.ts:167-182`).

**A pre-seed fallback exists.** `KEYWARD_SYNC_TOKENS` maps plaintext
`token:account` pairs from an environment variable, consulted when the registry
does not resolve (`main.rs:587-596, 516-523`). Intended for tests and
bootstrapping; it bypasses hashing entirely.

---

## 10. The Stripe webhook HMAC

**Implementation.** `verify_stripe_signature`
(`crates/sync-server/src/main.rs:1561-1594`).

```
header format: "t=<unix>,v1=<hex>[,v1=<hex>...]"
signed string: "{t}.{raw_body}"
tag          : HMAC-SHA256(key = KEYWARD_STRIPE_WEBHOOK_SECRET, msg = signed string)
compare      : lowercase hex, constant-time, any v1 candidate may match
```

- **Replay window:** `tolerance = 300` seconds, applied as
  `now.abs_diff(t) > tolerance` — symmetric, so both stale *and* future-dated
  timestamps are rejected (`main.rs:1582`). `tolerance = 0` disables the check.
- **Constant-time comparison:** `constant_time_eq` (`main.rs:1597-1606`) — a
  length check followed by an XOR-accumulate. Correct for its purpose, though it
  compares the *hex strings* rather than decoded bytes.
- **Unconfigured → 503**, never open (`main.rs:1489-1492`).
- **Bad signature → 400**, before any parsing of the event (`main.rs:1509-1512`).

**What a verified event can do** (`main.rs:1514-1553`): read
`data.object.metadata.account_id` and `metadata.plan`, then `set_plan`. Event
type `customer.subscription.deleted` forces `Plan::Free`; any other type takes
the plan from metadata, defaulting to `free` on absence (`Plan::parse` fails
closed, `crates/sync/src/accounts.rs:95-101`).

**Three observations for a reviewer:**

1. There is **no event-id deduplication** and **no `livemode` check**. Within the
   300 s window a captured valid event can be replayed; the operation is
   idempotent, so the impact is bounded, but it is not prevented.
2. The metadata is trusted for the plan value. It is set **server-side** at
   checkout (`main.rs:1452-1454`) — but the code comment at `main.rs:1534` says
   *"set by the client at checkout"*, which is wrong and would mislead a reader
   into thinking the input is attacker-influenced. (It isn't, via this path.)
3. Any event type other than `subscription.deleted` that carries both metadata
   keys will apply a plan. Authorization for the entire billing plane therefore
   rests solely on the webhook signing secret.

**Checkout session creation** (`main.rs:1433-1482`) is a **blocking** `ureq` POST
to `api.stripe.com` on the single-threaded request loop. The code says so
(`main.rs:1430-1432`).

---

## 11. What the relay stores, and what it can see

`ShareGroup` (`crates/sync/src/groups.rs:132-148`):

| Field | Server-visible content |
|---|---|
| `group_id` | Random 128-bit hex, unrelated to any key |
| `members[]` | `member_id`, `account_id`, **display name**, **X25519 public key** (hex), `role`, `added_epoch` |
| `invites[]` | SHA-256 **hash** of the code, timestamps, `redeemed_by` |
| `wrapped_keys` | Opaque bytes (serialized `SharedVault`) + `keys_version` |
| `content` | Opaque bytes (serialized `ContentBlob`) + `content_version` |

The relay never holds `K_vault`, any master password, any Secret Key, or any
member X25519 secret. It **does** hold the full family graph, display names, and
public keys in the clear, and it observes blob sizes and write timing.

Authorization is enforced per handler against the public directory:
group read/keys/content require membership (`main.rs:1070-1073, 1339-1342`);
invite and remove require Admin+ (`main.rs:1090, 1213`); role changes require
Owner (`main.rs:1262`); creating a group requires the paid Family plan
(`main.rs:1002-1016`). **Note that `PUT /keys` and `PUT /vault` are gated on
membership only, not role** — any Member can overwrite either blob
(`main.rs:1359-1385`).

Blob writes use optimistic concurrency: `If-Match: <version>` in, `X-Vault-Version`
out, 409 on conflict (`main.rs:1359-1384`). Versions for keys and content are
independent (`groups.rs:143, 147`).

**Rate limiting** (`main.rs:107-174`) is an in-memory fixed-window limiter keyed
by client IP, default 30/min, applied to `POST /v1/register` and
`POST /v1/groups/{id}/invites` only. It is per-process, so it is coherent only at
one replica — ADR-0005 states this explicitly.

---

## 12. End-to-end data flow: create → invite → join → grant → read → revoke

Notation: **A** = owner Alice, **B** = joiner Bob, **R** = relay.

### Create (`app/src/lib/sharing.ts:280-296`)

1. A ensures a member identity: fresh X25519 keypair, stored in `localStorage`
   under `keyward.passbook.member.v1` (`sharing.ts:29, 112-128`).
2. A → R `POST /v1/groups {member_id, name, public_key}`. R checks A's plan is
   Family (402 otherwise), mints a group id, records A as `Role::Owner`
   (`main.rs:999-1045`).
3. A generates `K_vault` (32 random bytes) locally.
4. A builds `SharedVault` wrapping `K_vault` to **A herself** (owner is member
   #0) and a `ContentBlob` sealing `[]` under `K_vault`.
5. A → R `PUT /keys` (no `If-Match`) and `PUT /vault` (no `If-Match`).
   R stores both as opaque bytes at version 1.

*R has learned: a group exists, A owns it, A's public key, two blob sizes.*

### Invite (`sharing.ts:446-459`, `main.rs:1088-1115`)

6. A → R `POST /v1/groups/{id}/invites {ttl_seconds: 86400}`. R checks A is
   Admin+, mints a 128-bit code, stores `SHA-256(code)` with a 24 h expiry,
   returns the plaintext code once.
7. A gives B the string `"{group_id}.{code}"` over a channel the family already
   trusts. **This is the protocol's trust anchor** (ADR-0004 §4).

### Join (`sharing.ts:420-443`, `main.rs:1144-1180`)

8. B (authenticating with **B's own** device token) → R
   `POST /v1/groups/{id}/members {code, member_id, name, public_key}`.
9. R hashes the code, atomically checks existence/expiry/single-use, and appends
   B to the directory with `Role::Member`.

*B is now in the directory and can fetch the blobs — but cannot decrypt them.
Redemption conveys no key material.*

### Grant (`sharing.ts:511-534`, `sharing.rs:383-390`)

10. Next time **any** member with access (say A) calls `loadFamily`, her client
    fetches the directory and the `SharedVault`, unwraps `K_vault` with her own
    secret, computes `wrappedMemberIds`, and finds B missing.
11. Her client calls `grant_access(A, B_public)` → a fresh ephemeral keypair,
    DH against B's public key, HKDF, AEAD-wrap of `K_vault`.
12. A → R `PUT /keys` with `If-Match: <keys_version>`. R bumps to v2.

**No human confirms step 11.** B's public key came from R.

### Read (`sharing.ts:504-546`)

13. B calls `loadFamily`: fetch directory → compute safety number → fetch
    `/keys` → `unwrap_for(B)` recovers `K_vault` → fetch `/vault` →
    `open_content` → entries.
14. B is shown the safety number and *may* compare it with A out of band.
    Nothing requires it, and by this point the grant has already happened.

### Write (`sharing.ts:560-573`)

15. Any member re-seals the **entire** entry set under `K_vault` with a fresh
    nonce and `PUT /vault` with `If-Match: <content_version>`.

### Revoke + rotate (`sharing.ts:599-628`)

16. A → R `DELETE /v1/groups/{id}/members/{B}`. R checks Admin+, refuses if B is
    an Owner, drops the directory row. **R rotates nothing.**
17. A re-reads the directory, generates `K_vault'`, builds a **new**
    `SharedVault` over the remaining members, re-seals the current entries.
18. A → R `PUT /keys` (If-Match), then `PUT /vault` (If-Match).

*B retains: everything B already decrypted, plus the old `K_vault`. B loses:
future content. This is inherent to client-side decryption and ADR-0004 §5 says
the UI must state it plainly.*

---

## 13. Consolidated constants and labels

| Constant | Value | Location |
|---|---|---|
| `SALT_LEN` | 16 | `crates/crypto/src/lib.rs:25` |
| `NONCE_LEN` | 24 | `crates/crypto/src/lib.rs:27` |
| `KEY_LEN` | 32 | `crates/crypto/src/lib.rs:29` |
| `VAULT_KEY_LEN` | 32 | `crates/passbook/src/sharing.rs:42` |
| Secret Key length | 16 (128 bits) | `crates/passbook/src/domain.rs:131` |
| `HKDF_INFO` | `b"keyward-passbook family-share v1"` | `crates/passbook/src/sharing.rs:39` |
| `SAFETY_NUMBER_INFO` | `b"keyward-passbook group-safety-number v1"` | `crates/passbook/src/sharing.rs:77` |
| HKDF salt | `None` (zero-filled) | `crates/passbook/src/sharing.rs:407` |
| Argon2 params | crate default: Argon2id v19, m=19456 KiB, t=2, p=1 | `crates/crypto/src/lib.rs:60` |
| Invite / token / group id entropy | 128 bits, hex | `crates/sync/src/groups.rs:29`, `crates/sync/src/accounts.rs:172` |
| Invite TTL default | 86400 s | `crates/sync-server/src/main.rs:1113` |
| Stripe replay tolerance | 300 s | `crates/sync-server/src/main.rs:1509` |
| Rate limit default | 30/min per IP, 60 s window | `crates/sync-server/src/main.rs:141, 129` |
| Free-plan device cap | 2 | `crates/sync/src/accounts.rs:111` |

---

## 14. Open questions for the implementer

Collected from the sections above — these are places where the code did not make
the intent legible, and the spec declines to guess.

1. **§1.1** Why `SHA-256(mk ‖ sk)` rather than HKDF or Argon2's `secret`
   (pepper) parameter for the 2SKD fold?
2. **§1.1** Are the Argon2 defaults intentional for the browser target? A 19 MiB,
   t=2 derivation runs on the main thread in WASM; was that measured?
3. **§3.2** Was the omission of `epk`/`rpk` from `HKDF_INFO` a considered
   deviation from the `crypto_box_seal` pattern, or an oversight?
4. **§3.2** Is `was_contributory()` deliberately not checked on the X25519
   result, or was it not considered? (See `known-limitations.md` §1.)
5. **§2** Is the absence of a Secret Key checksum intentional (to keep the
   Emergency Kit short), given a typo is indistinguishable from a wrong key?
6. **§7** Should `name` be included in the safety-number digest?
7. **§8** Should the relay enforce `member_id` uniqueness within a group?
8. **§11** Should `PUT /keys` require Admin+ rather than any Member?
9. **§6.2** Is there an intended recovery procedure when `PUT /keys` succeeds and
   `PUT /vault` then fails during rotation?
