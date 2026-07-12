# Changelog

All notable changes to Proctor are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions use SemVer.

## [1.2.0] — 2026-07-12

The generic exec-injection executor (ADR-0002 Phase 1) — one engine covers the
CLI long tail via the external profiles.

### Added
- **`run_command` MCP tool** — runs a CLI command with the item's credential
  injected into the subprocess **environment (never argv)**, and returns only the
  (redacted) output. The credential never reaches the model.
  - **Command-binding** (anti-confused-deputy): the program must be authorized by
    the item's provider profile (`commands`); e.g. an AWS credential can't run
    `curl`.
  - **Risk gate**: profile classification decides — read commands run; mutating /
    unknown commands step-up (attended) or are denied (unattended).
  - **Output redaction**: injected credential values are stripped from
    stdout/stderr before returning (so even `echo $TOKEN` yields `***REDACTED***`).
- **`proctor-mint::run`** — the generic subprocess runner (`run_with_env`).
- Vault items gain an optional **`provider`** field linking them to a profile;
  `proctor add`'s new trailing `[provider]` arg sets it.

### Security (see ADR-0002)
- Env injection is hygiene, not an isolation boundary (`/proc/environ`, `ps`,
  child inheritance). This build injects via env only (never argv) and redacts the
  return channel; **OS-level isolation and short-TTL creds remain required for
  untrusted-content-driven autonomy** and are not yet implemented.



Providers become **external config** (ADR-0002 registry, made concrete).

### Added
- **`proctor-profiles`** — external, pluggable provider profiles loaded from TOML
  at runtime (`$PROCTOR_PROFILES` or `~/.proctor/profiles`). A profile declares
  how a credential is injected (`env_var` for single-token, `env_map` for
  multi-field JSON credentials) and argv risk patterns
  (`read_patterns` / `mutate_patterns`, **default-gate** when unmatched, so it's
  safe when incomplete). One profile serves every tool that shares the provider's
  env-var convention (the `aws` profile → aws-cli, Terraform, Pulumi, SDKs).
- Seed profiles ship in `profiles/` (aws, azure, github, gitlab, hetzner) plus a
  `profiles/README.md`. **Adding a provider is dropping a `<id>.toml` file — no
  recompile.**
- **`proctor profiles`** CLI command lists what's loaded (proves pluggability:
  drop a file → it appears).



## [1.0.0] — 2026-07-12

The Phase B wedge is complete end-to-end: the interactive approval loop closes
the last behavioral gap.

### Added
- **Interactive step-up via MCP elicitation** — when the risk-tiered policy
  returns a step-up (e.g. a bound-but-not-pre-approved origin, attended), the
  broker prompts the user through the client (`peer.elicit`). Approve → the
  action is performed and tagged `approved_via: human elicitation`; reject →
  denied; no elicitation support → falls back to a step-up note.
- An `Approver` abstraction (`ElicitApprover` in production, `MockApprover` in
  tests) so the whole step-up path is unit-tested (approve / reject / unavailable).
- Refactor: decision + execution logic extracted into `handle_use` + `execute`,
  making the broker's behavior fully testable independent of the MCP transport.

### Complete end-to-end (this is what "the wedge" now does)
- Origin-binding (anti confused-deputy) · risk-tiered policy · **interactive
  step-up** · propose-not-commit (refuse → downgrade → perform as a draft PR) ·
  two credential-use models (vault-read *or* mint) · secretless read + write
  execution with real params · persistent hash-chained audit · kill switch —
  all driveable from Claude Code over MCP. 37 tests.

### Still deferred (post-wedge)
- OAuth Token Exchange (RFC 8693) / cloud STS minters, more executable
  operations, unattended out-of-band alerts, anomaly detection, sync/self-host,
  and a **formal security review before any real use**.

## [0.6.0] — 2026-07-12

Accountability + capability lifecycle.

### Added
- **Persistent audit log** — set `PROCTOR_AUDIT` to append every broker decision
  to a JSON-lines file (hash-chained, tamper-evident). `AuditLog::with_file` /
  `Broker::with_audit_file`.
- **Kill switch** — `revoke_all` MCP tool revokes all server-held minted tokens
  immediately (audited); `list_minted` shows held tokens (reference + provider +
  masked, never values).

## [0.5.0] — 2026-07-12

Threads real operation parameters through the tool, making the GitHub write a
genuine, parameterized action rather than a fixed demo.

### Added
- **`use_credential` accepts a `params` object** carried through to the performed
  action — e.g. `OpenPullRequest`: `{ owner, repo, head, base, title }`. Verified
  end-to-end (the PR title/repo reach the executor).
- `ExecAction` params flow through both the minted and vault-read execution paths.

### Changed
- `GitHubExecutor::OpenPullRequest` now builds the draft PR from the supplied
  params (the real POST is fully specified; still exercised offline via mock).
- `MockExecutor` echoes the params so callers can confirm they flowed through.

### Security invariants (tested)
- Params flow to the executor while the credential still never appears in any
  response.

## [0.4.0] — 2026-07-12

Closes the **propose-not-commit** loop at runtime: an irreversible action is
downgraded to a reviewable artifact, and that artifact is actually performed.

### Added
- **Write-side secretless execution** — `ExecKind::OpenPullRequest`:
  - `ShipToProduction` (unattended) → the broker proposes `OpenPullRequest`.
  - `OpenPullRequest` → the broker performs it as a **draft pull request** (a
    reviewable artifact, never a merge), via a `pull_requests:write`-scoped
    credential (minted) or the stored token (vault-read). The credential never
    reaches the model.
  - `GitHubExecutor` posts a draft PR (`draft: true`) from supplied params;
    `MockExecutor` demonstrates it offline.
- Verb-appropriate mint scopes: `OpenPullRequest` mints `contents:read +
  pull_requests:write`; reads stay read-only.

### Changed
- `Executor` HTTP is now a single injected `HttpClient` (get + post); the real
  client is `ReqwestClient` (behind `net`).
- **CLI**: `proctor add`'s `mintable` is now an optional trailing arg defaulting
  to **false** — the vault-read model is the default (`add <id> <label>
  <origins> <secret> [mintable] [kind]`).

### Security invariants (tested)
- The proposed write executes as a **draft PR only** (`draft: true`, "not
  merged") — the never-unattended commit is never performed.
- Neither minted tokens nor stored credentials appear in any response.

## [0.3.0] — 2026-07-12

Two ways to use a credential, selected per item by the `mintable` flag — you are
not forced to mint.

### Added
- **Secretless execution from the vault** (`mintable = false`): the broker **reads
  the durable token stored in the vault and uses it directly** to perform the
  action — nothing is fetched or created. The token is used inside the broker and
  never returned to the model (`primitive: "secretless_exec"`, `source: "vault"`).
- The `Executor` now takes a bearer credential (from either source), so the same
  execution path serves both:
  - `mintable = true`  → mint a short-lived scoped token, then perform (`source: "minted"`).
  - `mintable = false` → read the stored token from the vault, then perform (`source: "vault"`).

### Changed
- `Executor::perform` takes `bearer: &str` instead of a `MintedToken`, decoupling
  execution from where the credential came from.

### Security invariants (tested)
- On a vault-read execution, the stored token never appears in the response
  (verified end-to-end); credentials are masked in summaries.

## [0.2.0] — 2026-07-12

Closes the loop: **secretless execution**. The broker mints a scoped token,
*performs the action itself*, and returns only a sanitized result — the model
gets a result, not a value.

### Added
- **`proctor-mint::exec`** — an `Executor` layer:
  - `Executor` trait + `ExecAction`/`ExecResult`; HTTP GET injected as `GetHttp`
    for offline tests.
  - `GitHubExecutor` — uses a minted installation token to list the repositories
    the installation can access (real read), returning only repo names/count.
  - `MockExecutor` for offline demos/tests.
- **`proctor-mcp`** — `use_credential` on a `Read`/`FetchData` verb now **mints +
  performs** the action and returns `primitive: "secretless_exec"` with a
  sanitized `result` — the base secret and the minted token never reach the model.
  Non-executing verbs still mint-and-hold. GitHub executor wired when configured,
  else mock.

### Security invariants (tested)
- On a secretless read, the response carries the *result* but never the base
  secret or the minted token value (verified end-to-end).

### Still not built
- More execution operations (writes via propose-not-commit artifacts), OAuth
  Token Exchange / cloud STS minters, `elicitation` step-up, sync/self-host,
  anomaly detection — and a **formal security review before any real use**.

## [0.1.0] — 2026-07-12

First working version of the **Phase B wedge**: the AI credential broker, backed
by a real vault and minting, driveable as an MCP server.

### Added
- **`proctor-broker`** — the credential-broker security model:
  - Origin-binding (defeats the confused-deputy / prompt-injection attack,
    independent of any human approval).
  - Capabilities scoped on `item × origin × verb × TTL × use-count`.
  - Risk-tiered policy: auto-allow / step-up / deny / propose-instead.
  - **Propose-not-commit** autonomy floor with a locked never-unattended list
    (delete data · move money · ship to prod · comms-as-you · rotate/revoke creds).
  - Default primitive preference: minted → secretless → (raw, hard-denied).
  - Tamper-evident, hash-chained audit log.
- **`proctor-vault`** — file-backed encrypted vault (Argon2id + XChaCha20-Poly1305);
  `seal`/`open`/`save_to_file`/`load_from_file`; secret-free `ItemRef` for the broker.
- **`proctor-mint`** — "mint, don't inject": `Minter` trait, `MockMinter`, and a
  real `GitHubAppMinter` (RS256 JWT + installation access-token flow) with signer
  and HTTP injected as traits (tested offline; real `jsonwebtoken`/`reqwest` behind
  the `net` feature). Minted values are zeroized and never model-facing.
- **`proctor-mcp`** — the broker+vault+minting exposed as an MCP server (stdio) via
  the official `rmcp` SDK. Tools: `list_credentials`, `use_credential`, `audit_log`.
  On an allowed mintable item it mints a token held server-side and returns only a
  `token_ref` + masked view. Real GitHub App minter wired when configured, else mock.
- **`proctor` CLI** — `init` / `add` / `list` to manage a real on-disk vault, plus
  a `demo` walkthrough of the broker.
- **Docs** — market & feature research, product spec (PRD), and ADR-0001 (broker
  security model).

### Security invariants (tested)
- The base secret and any minted token value never appear in a tool response.
- A credential is refused against any origin it is not bound to.
- Irreversible high-consequence actions cannot run unattended (proposed or denied).

### Not yet built
- Secretless **execution** ("perform the action" with a minted token on the
  agent's behalf) — today the minted token is held server-side, not yet used.
- `elicitation`-based human step-up approval through MCP.
- Vault sync / self-host / on-device migration surfaces.
- Anomaly detection, unattended-policy pre-authorization + out-of-band alerts.
- **Formal security review** — required before any real use.
