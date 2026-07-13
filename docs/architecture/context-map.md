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
(Published Language = "an opaque versioned blob"). Identity is an `AccountStore`
with per-device bearer tokens stored **only as SHA-256 hashes** (a breached
registry yields no usable credentials), and devices can be listed and **revoked**
(the lost-device flow).

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
  domain never names a file, a browser API, or `SystemTime`. The **Broker** context
  gets the same treatment (below).

## Ports & adapters in the Broker context

`proctor-broker` is the domain core of the developer-wedge context — capabilities,
origin-binding, propose-not-commit, the risk-tiered policy, and the hash-chained
audit trail. Its *driven* dependencies are inverted behind `proctor-broker::ports`,
mirroring Passbook:

- **`ports::Clock`** — wall-clock time. `Broker::request_use` already takes the
  instant as a `now: SystemTime` argument (time is inverted at the call boundary);
  the `Clock` trait names that seam and `adapters::SystemClock` is its real
  adapter, so neither the domain nor its tests reach for ambient
  `SystemTime::now()`.
- **`ports::AuditSink`** — the durable destination of the audit trail. The chain
  construction (SHA-256 hashing, optional HMAC signing, tamper-evidence) stays
  domain logic in `audit::AuditLog`; *where* each serialized line is persisted is
  the adapter's concern. `adapters::FileAuditSink` is the append-only JSON-lines
  file adapter, wired unchanged by `AuditLog::with_file` / `with_file_signed`, so
  the public API and on-disk format are identical. Any other sink (syslog, an
  object store) is just another adapter via `AuditLog::with_sink`.

The **Minter** and **Executor** are ports the broker only *names* rather than owns:
they are traits in `proctor-mint` (`Minter`, `Executor`, `HttpClient`, …). The
broker selects the `Primitive::Minted` outcome; the executing host (`proctor-mcp`,
`proctor-cli`) supplies the concrete minter/executor adapter. This keeps the broker
core free of provider HTTP and signing code (the anti-corruption boundary to
`proctor-mint` and `proctor-profiles`).
