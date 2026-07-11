# Proctor

**The credential manager that's as polished as 1Password, as open as Bitwarden, and as private as you want it — because you decide where your vault lives.**

Proctor is an **open-source, B2C credential manager** (passwords + passkeys + TOTP + email aliases + identities) built to close the two gaps the market leaves open:

- The best UX (**1Password**) is proprietary, has no free tier, and just got more expensive.
- The best open option (**Bitwarden**) has a degraded browser extension and weak connectivity.

Proctor refuses that trade-off, and adds three things no competitor offers together:

- 🔐 **Choosable & migratable trust model** — keep your vault **on-device only**, in our **managed cloud**, on your **own self-hosted server**, or in **your own storage** (iCloud/Dropbox/WebDAV) — and **migrate between them seamlessly**, with no destructive re-encryption.
- 👨‍👩‍👧 **Family-first sharing** — private + shared vaults, guest sharing, account recovery, mixed-skill onboarding.
- 🤖 **AI credential broker** — an MCP server + CLI that lets your agents **use** credentials (fill a login, run an authenticated command) **without the plaintext ever entering the model context, chat, or history**. *Give your agents hands, not your secrets.*

Built open-core: fully open-source clients + server, **self-host free forever**; revenue from managed cloud, family/premium features, and the broker.

## Documentation

- 📊 **[Market & Feature Research](docs/research/market-and-feature-research.md)** — market sizing, competitive teardown, feature matrix, pain points, trends, and the opening.
- 📐 **[Product Specification (PRD)](docs/product/product-spec.md)** — vision, personas, differentiation, architecture, the AI credential broker, feature set, pricing, roadmap, and GTM.
- 🏛️ **[ADR-0001 — Broker security model](docs/architecture/ADR-0001-broker-security-model.md)** — the design the prototype implements.

## Prototype (Phase B wedge)

A runnable Rust workspace implementing the **credential broker security model** —
the riskiest, most-differentiating piece — validating it with real tests before
building outward.

```
crates/
  vault/    proctor-vault   encrypted vault core (Argon2id + XChaCha20-Poly1305) — PROTOTYPE
  broker/   proctor-broker  the security model: capabilities, origin-binding,
                            propose-not-commit, risk-tiered policy, hash-chained audit
  cli/      proctor         end-to-end demo
```

```bash
cargo test --workspace          # 15 tests: origin-binding, propose-not-commit, TTL, audit chain…
cargo run -p proctor-cli -- demo  # watch the model block a confused-deputy attack, etc.
```

The demo shows a manipulated agent being refused when it tries to use GitHub
creds on `evil.example.com`, a ship-to-prod request downgraded to a pull request,
unattended money-movement denied, and a tamper-evident audit trail.

> **Security note:** this is a prototype of the *shape*, not an audited build. Real
> minting integrations, MCP transport, and a formal review come before any real use.

## Status

Research + spec complete; the broker security model is prototyped and tested.
Next: real minting (GitHub/STS/OAuth token-exchange), MCP transport wiring, and
the vault/sync surfaces. Implementation follows the roadmap in the PRD.

## License

Open-core (planned): AGPL-3.0 server + GPL/MPL clients. See the PRD's decisions log.
