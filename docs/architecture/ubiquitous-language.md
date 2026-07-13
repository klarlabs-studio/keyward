# Ubiquitous Language

The shared vocabulary of Proctor. Every term here maps to a concrete type or
module so business and code speak the same words. Terms are grouped by bounded
context (see [context-map.md](context-map.md)).

## Passbook context (the consumer credential manager)

| Term | Meaning | In code |
| --- | --- | --- |
| **Vault** | A person's/family's collection of credentials. | the set of `Entry` values |
| **Entry** | One titled, tagged, categorized credential. The context's *entity* (has an `id`). | `domain::Entry` |
| **Login / Card / Identity / Secure Note** | The four kinds of entry content. *Value objects*. | `domain::{Login, Card, Identity}`, `Content::SecureNote` |
| **Category** | Which kind an entry is. | `domain::Category` |
| **Master Password** | The secret the user types to unlock. Never stored. | `master: &[u8]` argument |
| **Secret Key** | A 128-bit device-generated second factor, folded into key derivation (2SKD) so a stolen sealed vault is uncrackable without it. | `domain::SecretKey` |
| **2SKD** | Two-Secret Key Derivation: `key = SHA256(argon2id(master) ‖ secret_key)`. | `sealing::derive_key` |
| **Emergency Kit** | The human-readable rendering of the Secret Key the user must save. | `SecretKey::emergency_kit_format` |
| **Sealed Vault** | The encrypted-at-rest blob (salt + nonce + ciphertext). | `sealing::SealedVault` |
| **Seal / Open** | The sealing *domain service* — encrypt entries to / decrypt from a Sealed Vault. | `sealing::{seal, open}` |
| **Watchtower** | The security analysis *domain service* (weak / reused passwords, strength). | `watchtower::{watchtower, Issue, strength_bits}` |
| **Sharing / Shared Vault / Member** | The family-sharing *aggregate*: a vault key wrapped per-recipient via sealed-box, with recovery. | `sharing::{SharedVault, Member, MemberPublic}` |
| **TOTP** | Time-based one-time codes (RFC 6238) shown for a login. | `totp` |
| **Bridge** | The Chrome native-messaging host the browser extension talks to. An *adapter*. | `passbook-cli` `bridge` module |
| **Vault Repository** | The *port* for persisting a Sealed Vault (file, browser, server…). | `ports::VaultRepository` |

## Credential Broker context (the developer wedge)

| Term | Meaning | In code |
| --- | --- | --- |
| **Item** | A brokered credential (contains the secret; never handed to the model). | `proctor-vault` `Item` |
| **Item Ref** | The secret-free projection the broker may see. | `proctor-vault` `ItemRef` |
| **Origin-binding** | An item is usable only against its declared origins (anti-confused-deputy). | `Item::bound_origins` |
| **Capability** | A scoped, time-boxed grant to *use* (not read) a credential. | `proctor-broker` |
| **Propose-not-commit** | The broker proposes an action for user approval; it never acts unattended. | `proctor-broker` |
| **Mint / Minter** | Produce a short-lived scoped token instead of exposing the durable secret. | `proctor-mint` |
| **Profile** | External, pluggable provider config (aws, github, …) — a supporting subdomain. | `proctor-profiles`, `profiles/*.toml` |
| **Audit** | The hash-chained (optionally HMAC-signed) record of every brokered action. | `proctor-broker` audit |

## Shared Kernel

| Term | Meaning | In code |
| --- | --- | --- |
| **Crypto kernel** | The primitives both vault contexts agree on: Argon2id KDF + XChaCha20-Poly1305 AEAD + CSPRNG. | `proctor-crypto` |
