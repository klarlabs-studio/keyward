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

## v0.1.0 — the Phase B wedge, working

A runnable Rust workspace: a real encrypted vault, the credential-broker security
model, minting ("mint, don't inject"), and an MCP server an agent can drive — all
tested end-to-end.

```
crates/
  vault/    proctor-vault   encrypted vault (Argon2id + XChaCha20-Poly1305), file-backed — PROTOTYPE
  broker/   proctor-broker  the security model: capabilities, origin-binding,
                            propose-not-commit, risk-tiered policy, hash-chained audit
  mint/     proctor-mint    mint short-lived scoped tokens; MockMinter + real GitHub App minter
  mcp/      proctor-mcp     the broker+vault+minting exposed as an MCP server (stdio) via rmcp
  cli/      proctor         manage the vault (init/add/list) + broker demo
```

```bash
cargo test --workspace              # 24 tests: origin-binding, propose-not-commit, mint no-leak, audit chain…
cargo run -p proctor-cli -- demo    # watch the model block a confused-deputy attack, etc.
```

### Quickstart — dogfood it in Claude Code

```bash
# 1. Build & create a vault
cargo install --path crates/cli --path crates/mcp
export PROCTOR_VAULT=~/.proctor/vault.json PROCTOR_MASTER='your master secret'
mkdir -p ~/.proctor && proctor init
proctor add itm_github "GitHub App key" github.com true "$(cat github-app.pem)" apikey

# 2. Register the MCP server (it reads the same env)
claude mcp add proctor -- proctor-mcp

# 3. (optional) real GitHub App minting instead of the mock:
#    export PROCTOR_GH_APP_ID=... PROCTOR_GH_INSTALLATION_ID=...
```

The server exposes `list_credentials`, `use_credential`, `audit_log`. On an
allowed, mintable item it **mints a fresh, scoped, short-TTL token held
server-side** and returns only a `token_ref` + masked view — the base secret and
the minted value never reach the model. Ask your agent to use a credential
against the wrong origin, or to ship to prod unattended, and watch the broker
refuse or downgrade it.

> **Security note:** this is a prototype. The vault, minting, and broker are real
> and tested, but a **formal security review is required before any real use**.
> A secretless "perform the action" execution surface is the next step (today a
> minted token is held server-side, not yet used on the agent's behalf).

## Status

**v0.1.0** delivers the wedge end-to-end: file-backed vault + CLI, the broker
security model, minting (mock + real GitHub App), and a vault-backed MCP server —
24 passing tests. Next: secretless execution (`perform`), `elicitation`-based
step-up approval, and the vault/sync surfaces. See the [CHANGELOG](CHANGELOG.md)
and the roadmap in the PRD.

## License

Open-core (planned): AGPL-3.0 server + GPL/MPL clients. See the PRD's decisions log.
