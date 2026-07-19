---
updated: 2026-07-19
tags: [architecture]
---
# Keyward architecture

## Repo split
- `klarlabs-studio/keyward` — public, AGPL-3.0. All code: 13 Rust crates, the
  Vue web vault, and a portable `deploy/k8s` base.
- `klarlabs-studio/keyward-cloud` — private. Cluster topology only: the klarlabs
  kustomize overlay and the RollOps definition. It pins the public base by
  commit SHA.

The boundary is **deployment vs. product**. The server code is public because
privatising it would remove the free self-host tier rather than protect
anything: `keyward-sync-server` is one binary whose cloud features are
env-gated — no `KEYWARD_SYNC_PG` means a file store, no `KEYWARD_STRIPE_*` means
billing endpoints return 503.

## Crypto
- Personal vault: Argon2id + XChaCha20-Poly1305, 2SKD
  `key = SHA-256(argon2id(master) ‖ secret_key)`.
- Family sharing: per-recipient X25519 → HKDF-SHA256 → XChaCha20-Poly1305
  sealed boxes, wrapping a shared vault key.
- Wrapped-key sets are Ed25519-signed (separate key from the X25519 one) and
  carry a monotonic epoch inside the signed payload.

## The family-sharing trust model, and why it is shaped this way
The relay is untrusted. Three distinct attacks, three distinct defences:

1. **Substitution** — the relay lists a fabricated member and gets the vault key
   wrapped to it. Defence: TOFU member-key pinning; nothing is wrapped to an
   unpinned key without explicit human approval.
2. **Forgery** — wrapping needs only a PUBLIC key, so the relay can mint its own
   vault key and wrap it to everyone; all members decrypt happily. Defence:
   signatures, verified against a **locally pinned** key. Verifying against a key
   the same relay served would prove nothing.
3. **Rollback** — a signature says who wrote a set, not which is current, so the
   relay replays an older validly-signed set. Defence: monotonic epochs with a
   client-pinned floor.

Revocation **rotates from** the current set rather than building a fresh one. A
fresh set restarts at epoch 1, which the pre-revocation set outranks — the
subtle way to get this wrong.

## Trust state
Member pins, vault-key pin, epoch floor and the signed-group flag live in the
**synced encrypted vault** as a reserved entry, with localStorage as a cache.
Merge rules resolve only toward more suspicion: epochs take the max, signed-group
flags union (one-way), and a pin conflict keeps the LOCAL pin so the relay's key
reads as `changed` and routes to human approval.

## Frozen identifiers
Four crypto domain-separation labels and all `proctor.passbook.*` localStorage
keys keep the old product name permanently. They are wire and storage
identifiers; renaming breaks decryption or orphans trust state. Marked `FROZEN`.
