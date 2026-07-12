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
  mint/     proctor-mint    mint short-lived scoped tokens + secretless execution
                            (MockMinter/MockExecutor + real GitHub App minter & executor)
  mcp/      proctor-mcp     the broker+vault+minting+execution as an MCP server (stdio) via rmcp
  cli/      proctor         manage the vault (init/add/list) + broker demo
```

```bash
cargo test --workspace              # 32 tests: origin-binding, propose-not-commit exec, secretless no-leak, audit chain…
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

**v0.5.0** threads real operation params (`use_credential`'s `params`) through to
the performed action — the GitHub draft-PR write is now genuinely parameterized
(`owner/repo/head/base/title`). On top of the closed **propose-not-commit** loop
(unattended `ShipToProduction` → `OpenPullRequest` → reviewable draft), two
credential-use models (vault-read *or* mint), secretless read/write execution, the
file-backed vault + CLI, the broker security model, and the vault-backed MCP
server. 32 passing tests. Next: `elicitation`-based step-up through MCP, more
executable operations, and the vault/sync surfaces. See the
[CHANGELOG](CHANGELOG.md) and the PRD roadmap.

> A **formal security review is required before any real use.** GitHub network
> paths are real code, exercised offline via injected mocks.

## License

Open-core (planned): AGPL-3.0 server + GPL/MPL clients. See the PRD's decisions log.
