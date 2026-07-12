# Proctor

![security grade A](docs/security/badge.svg)

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
- 🧭 **[ADR-0002 — Scaling credential use across providers](docs/architecture/ADR-0002-scaling-credential-use.md)** — why "N providers" doesn't get huge: vault-read + standard-protocol minters + one generic injector + a profile registry.
- 🛡️ **[Threat Model & Security Posture](docs/security/THREAT-MODEL.md)** — STRIDE by component, trust boundaries, residual risks, and the reviewer checklist (frames an external review; not a substitute for one).

## v1.0.0 — the Phase B wedge, complete end-to-end

A runnable Rust workspace: a real encrypted vault, the credential-broker security
model, minting and vault-read, secretless read/write execution, **interactive
step-up approval**, propose-not-commit, a persistent audit log, and a kill
switch — all driveable from Claude Code over MCP, all tested.

```
crates/
  vault/    proctor-vault   encrypted vault (Argon2id + XChaCha20-Poly1305), file-backed — PROTOTYPE
  broker/   proctor-broker  the security model: capabilities, origin-binding,
                            propose-not-commit, risk-tiered policy, hash-chained audit
  mint/     proctor-mint    mint short-lived scoped tokens + secretless execution
                            (MockMinter/MockExecutor + real GitHub App minter & executor)
  profiles/ proctor-profiles external, pluggable provider profiles (TOML) — add a
                            provider by dropping a file; no recompile
  passbook/ proctor-passbook consumer credential manager (Phase A): rich item model,
                            TOTP (RFC 6238), Secret Key (2SKD), Watchtower,
                            family sharing (X25519 sealed-box) — PROTOTYPE
  passbook-cli/ passbook    manage the consumer vault from the terminal
                            (init/add-login/list/show/totp/watchtower/emergency-kit)
  passbook-wasm/ passbook-wasm  wasm-bindgen surface so the vault crypto/TOTP/Watchtower
                            runs client-side in the browser
  mcp/      proctor-mcp     the broker+vault+minting+execution as an MCP server (stdio) via rmcp
  cli/      proctor         manage the vault (init/add/list) + list profiles + demo
```

The consumer product (**Phase A**, the 1Password equivalent) also ships a
Manifest V3 browser extension for autofill under [`extension/`](extension/) and a
polished web-vault UX prototype. The vault crypto core (`proctor-passbook`)
compiles to WebAssembly so the same tested Rust runs in the browser.

New providers are **external config**, not code. Drop a `<id>.toml` into
`$PROCTOR_PROFILES` (see [`profiles/`](profiles/)) and `proctor profiles` picks it
up — GitLab, Azure, Cloudflare, whatever arises. See
[ADR-0002](docs/architecture/ADR-0002-scaling-credential-use.md).

```bash
cargo test --workspace              # 37 tests: origin-binding, step-up, propose-not-commit exec, secretless no-leak, audit chain…
cargo run -p proctor-cli -- demo    # watch the model block a confused-deputy attack, etc.
```

### Quickstart — dogfood it in Claude Code

```bash
# 1. Build & create a vault
cargo install --path crates/cli --path crates/mcp
export PROCTOR_VAULT=~/.proctor/vault.json PROCTOR_MASTER='your master secret'
mkdir -p ~/.proctor && proctor init
# vault-read (default): store the token; Proctor reads and uses it directly
proctor add itm_github "GitHub token" github.com "$(cat token.txt)"
# or minting: store an App key and pass mintable=true
# proctor add itm_ghapp "GitHub App" github.com "$(cat app.pem)" true apikey

# 2. Register the MCP server (it reads the same env)
claude mcp add proctor -- proctor-mcp

# 3. (optional) real GitHub App minting instead of the mock:
#    export PROCTOR_GH_APP_ID=... PROCTOR_GH_INSTALLATION_ID=...
```

The server exposes `list_credentials`, `use_credential`, `audit_log`. On an
allowed **read**, the broker **performs the action itself and returns only the
sanitized result** — the credential never reaches the model (*secretless
execution*). How it gets the credential is per-item, set by the `mintable` flag:

- **`mintable = false`** → the broker **reads the token you stored in the vault**
  and uses it directly (nothing fetched or created) — `source: "vault"`.
- **`mintable = true`** → the vault holds an App key; the broker mints a fresh,
  short-lived, narrowly-scoped token, then performs — `source: "minted"`.

Either way the token is used *inside* the broker and never returned. Ask your
agent to ship to prod unattended and it's **downgraded to a pull request**; ask it
to open that PR and the broker performs it as a **draft (review required, not
merged)** — the runtime half of *propose-not-commit*. Use a credential against the
wrong origin and it's refused outright.

> **Security note:** this is a prototype. The vault, minting, broker, and
> secretless read execution are real and tested, but a **formal security review
> is required before any real use**.

## Status

**v1.0.0 — the wedge is complete end-to-end.** In one flow the broker: refuses a
confused-deputy origin, **prompts for human approval** on a step-up (via MCP
elicitation), downgrades an unattended `ShipToProduction` to a reviewable draft
PR, performs reads/writes secretlessly (vault-read *or* mint), persists a
tamper-evident audit log, and offers a kill switch — never exposing a credential
to the model. 37 passing tests across 5 crates.

Deferred (post-wedge): OAuth Token Exchange / cloud STS minters, more executable
operations, unattended out-of-band alerts, sync/self-host surfaces. See the
[CHANGELOG](CHANGELOG.md) and the PRD roadmap.

> A **formal security review is required before any real use.** GitHub network
> paths are real code, exercised offline via injected mocks.

## License

Open-core (planned): AGPL-3.0 server + GPL/MPL clients. See the PRD's decisions log.
