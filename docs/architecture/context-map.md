# Context Map

Proctor is two **bounded contexts** over one **shared kernel**. Each context is a
set of Cargo crates; the compiler enforces the boundary (you cross it only
through published APIs, which act as anti-corruption layers).

```
                         ┌───────────────────────────────┐
                         │        Shared Kernel          │
                         │        proctor-crypto         │
                         │  Argon2id KDF · XChaCha20-     │
                         │  Poly1305 AEAD · CSPRNG        │
                         └───────────────┬───────────────┘
                       depends on        │        depends on
             ┌──────────────────────────┘        └──────────────────────────┐
             ▼                                                               ▼
┌───────────────────────────────────┐             ┌───────────────────────────────────┐
│    Passbook context (Phase A)      │             │  Credential Broker context (B)     │
│  consumer / family credential mgr  │             │  "give agents hands, not secrets"  │
│                                    │             │                                    │
│  Domain core:  proctor-passbook    │             │  Domain:  proctor-vault,           │
│    domain · sealing · watchtower · │             │           proctor-broker,          │
│    sharing · totp · ports          │             │           proctor-mint             │
│                                    │             │                                    │
│  Adapters:                         │             │  Adapters / supporting:            │
│    passbook-cli  (file repo, CLI,  │             │    proctor-mcp   (MCP server)      │
│                   native bridge)   │             │    proctor-cli   (broker CLI)      │
│    passbook-wasm (browser)         │             │    proctor-profiles (external      │
│    app/          (Vue web vault)   │             │      provider config — supporting  │
│    extension/    (autofill)        │             │      generic subdomain)            │
└───────────────────────────────────┘             └───────────────────────────────────┘
```

## Contexts

### Passbook (consumer credential manager — Phase A)
The core domain for individuals and families. **Domain core** in
`proctor-passbook`, organized into `domain` (entities + value objects), `sealing`
(the sealing service + `SealedVault` aggregate), `watchtower` (analysis service),
`sharing` (the family-sharing aggregate), `totp`, and `ports` (driven ports). The
domain is pure; all I/O lives behind ports, implemented by adapters:
`passbook-cli` (filesystem `VaultRepository`, `SystemClock`, and the native
bridge), `passbook-wasm` + `app/` (browser), and the `extension/`.

### Sync (zero-knowledge cloud sync)
A **supporting context** for the Passbook context. `proctor-sync` is the domain
(the `SyncStore` port + `MemoryStore`/`FileStore` adapters + optimistic-concurrency
rule); `proctor-sync-server` is a tiny HTTP adapter exposing it. The server stores
an **opaque** sealed-vault blob per account and never sees plaintext, the master
password, or the Secret Key — a stolen server yields only ciphertext (the 2SKD
promise, extended to the cloud). It shares no domain model with Passbook: the blob
is `proctor-passbook`'s `SealedVault` bytes, but to Sync it is just bytes
(Published Language = "an opaque versioned blob").

### Credential Broker (developer wedge — Phase B)
The AI-native broker: `proctor-vault` (its store), `proctor-broker` (capabilities,
origin-binding, propose-not-commit, audit), `proctor-mint` (short-lived tokens),
surfaced via `proctor-mcp` and `proctor-cli`. `proctor-profiles` is a **supporting
generic subdomain** — external, pluggable provider config.

## Relationships (DDD patterns)

- **Shared Kernel** — `proctor-crypto`. Both contexts depend on the exact same
  cryptographic construction; it is defined once and changed deliberately. Neither
  context owns it; it makes no policy decisions (each composes it — Passbook adds
  the 2SKD twist in `sealing`).
- **Separate Ways** — the two contexts do not share a domain model. A Passbook
  `Entry` and a broker `Item` are different concepts and never leak across.
- **Ports & Adapters (Hexagonal)** — within Passbook, `ports::VaultRepository` and
  `ports::Clock` are driven ports; concrete storage/time live in adapters, so the
  domain never names a file, a browser API, or `SystemTime`.
