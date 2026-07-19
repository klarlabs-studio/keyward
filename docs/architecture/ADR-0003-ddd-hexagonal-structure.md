# ADR-0003 — DDD / Hexagonal structure

- Status: Accepted
- Date: 2026-07-13
- Supersedes: none
- Related: [context-map.md](context-map.md), [ubiquitous-language.md](ubiquitous-language.md),
  ADR-0001 (broker security model), ADR-0002 (scaling credential use)

## Context

The codebase grew feature-first (vault → broker → passbook → web app → bridge).
The domain concepts were sound but implicit: crypto was duplicated between the two
vault contexts, `keyward-passbook` was a single 400-line `lib.rs` mixing entities,
crypto, and analysis, and I/O (files, time) was reached for directly inside what
should be domain logic. We want the architecture to make its Domain-Driven Design
explicit, without adding ceremony that Rust does not already express naturally.

## Decision

Adopt DDD tactical patterns + hexagonal (ports & adapters), mapped onto Rust's own
constructs:

1. **Bounded contexts = crates.** Passbook and the Credential Broker are separate
   contexts (Separate Ways); the crate boundary is the anti-corruption layer.
2. **Shared Kernel = `keyward-crypto`.** The Argon2id + XChaCha20-Poly1305 + CSPRNG
   primitives, previously duplicated in `keyward-vault` and `keyward-passbook`, are
   extracted to one crate that both depend on. Byte formats are unchanged — the
   extraction moved code, it did not alter the construction (verified: a vault
   sealed before the refactor still opens after).
3. **Domain model in modules.** `keyward-passbook` is split into `domain`
   (entities + value objects), `sealing` (sealing service + `SealedVault`
   aggregate), `watchtower` (analysis service), `sharing`, `totp`, and `ports`.
   The crate root re-exports the public API, so downstream code is unchanged.
4. **Ports & adapters.** `ports::VaultRepository` and `ports::Clock` are driven
   ports. The CLI provides `FileVaultRepository` and `SystemClock`
   (`passbook-cli::adapters`); the browser (WASM + localStorage) and any future
   server are just other adapters. The domain never names a file or `SystemTime`.
5. **Ubiquitous language** is pinned in `ubiquitous-language.md`; the context map
   in `context-map.md`.

## Why Rust fits DDD

- **Make illegal states unrepresentable** — sum types. `Content` (Login | Card |
  Identity | SecureNote) means a card-with-TOTP cannot be constructed.
- **Value objects** — the newtype pattern (`SecretKey([u8;16])`) with no public
  field and self-validating `parse`.
- **Aggregates** — ownership enforces the invariant boundary; the borrow checker
  even nudges toward the correct DDD rule of referencing other aggregates by id.
- **Domain services** — free functions (`seal`, `watchtower`).
- **Repositories / ports** — traits, with adapters as impls.
- **Domain errors** — `thiserror` enums as ubiquitous-language failures.

## Consequences

- **Positive:** one cryptographic construction to review; a pure, testable domain
  core; storage/time are swappable; the vocabulary is documented and enforced by
  module names. All tests stayed green through the refactor (17 suites) and the
  sealed-vault format is unchanged.
- **Negative / cost:** one more crate (`keyward-crypto`) and a light indirection
  (ports) in the CLI. Judged worth it for the review surface and clarity.
- **Deliberately not done:** we did not introduce a DI framework, application
  services layer, or CQRS — they would be ceremony here. Ports are plain traits.
- **Follow-ups:** the same port/adapter treatment has since been applied inside the
  broker context (`keyward-broker::ports::{Clock, AuditSink}` with in-crate
  `adapters::{SystemClock, FileAuditSink}`; the Minter/Executor remain ports owned
  by `keyward-mint`) — see [context-map.md](context-map.md). Consider a
  shared-kernel home for common serde/zeroize helpers if duplication reappears.
