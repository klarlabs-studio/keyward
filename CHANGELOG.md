# Changelog

All notable changes to Proctor are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions use SemVer.

## [1.14.0] — 2026-07-12

**Secret Key (2SKD) in the browser.** The web vault is now sealed with a device
Secret Key in addition to the master password, so a stolen vault blob is
uncrackable even against a weak master. Verified end-to-end in a headless
browser: first-run generates a real Secret Key + Emergency Kit, the vault seals
and reopens with it, a locked→unlock reuses the stored key, and the Emergency Kit
is re-viewable.

### Added — `passbook-wasm`
- `seal_vault` / `open_vault` now take an optional Secret Key (Emergency-Kit
  string) — pass `null` for master-only, or the key for 2SKD. `generate_secret_key`
  and `secret_key_is_valid` round out the surface.

### Added — web vault (`app/`)
- **Device Secret Key** stored locally (a device factor, never sent anywhere) and
  mixed into key derivation via the WASM binding. First unlock generates one and
  reveals a one-time **Emergency Kit** (copy + download) that must be acknowledged.
- **Add-this-device flow:** a device holding the vault but not its Secret Key
  prompts for the key on the unlock screen; a wrong key/master is rejected cleanly.
- A **re-viewable Emergency Kit** from the top bar, and a "· 2SKD" indicator on the
  vault pill. Every reseal (add/edit/favourite) uses the Secret Key.

## [1.13.0] — 2026-07-12

**The web vault — a real Vue app on the WASM crypto core.** The polished UX
prototype is now a working application: unlock, browse, reveal, copy, live 2FA,
and a security dashboard, all backed by the same tested Rust that ships in the
CLI and MCP server. Verified running headless (real seal → open round-trip; a
117-bit strength read and a live RFC-6238 code rendered from WASM).

### Added — `app/` (Vue 3 + Vite + TypeScript + Pinia)
- **WASM-backed core:** `app/src/lib/passbook.ts` instantiates `passbook-wasm`
  once and routes all crypto through it (`seal_vault`/`open_vault`/`totp_code`/
  `watchtower_json`/`password_strength`). The vault persists as a single
  **encrypted blob in localStorage**; the master password never leaves the module.
- **Pinia store** (`app/src/stores/vault.ts`): unlock/lock, filtered category
  views, favourites, add-login, delete — every mutation reseals + repersists and
  recomputes Watchtower.
- **Component layer** (faithful port of the design prototype): unlock screen,
  3-pane shell (brand / nav with live counts / list / detail), item detail with
  password strength bar + reveal + copy, a live TOTP field with a countdown ring,
  the Watchtower score gauge + issue cards, an add-item dialog, and a copy toast.
  Teal/emerald "Passbook" identity, theme-aware.
- Build: `npm run build:wasm` (wasm-pack → `app/src/wasm/pkg/`, gitignored) then
  `npm run build` (`vue-tsc --noEmit && vite build`); the `.wasm` (97 KB gzipped)
  is bundled as a Vite asset. `npm run dev` for local development.

## [1.12.0] — 2026-07-12

**Phase A build-out — four surfaces in parallel.** Built by four isolated agents in
their own file lanes, then integrated into one green workspace (all tests pass,
clippy/fmt clean, `wasm32` build succeeds, warden gate passed).

### Added — `passbook` CLI (`crates/passbook-cli`)
- Manage the consumer vault from the terminal: `init` (generates + persists the
  device Secret Key, prints the Emergency Kit), `add-login`, `list [category]`,
  `show <id> [--reveal]`, `totp <id>` (live code + seconds remaining),
  `watchtower` (weak/reused report + 0–100 score), `emergency-kit`.
- Vault persisted as an encrypted `SealedVault` JSON; 2SKD transparently reused.
  Config via `PROCTOR_PASSBOOK`, `PROCTOR_PASSBOOK_MASTER_FILE`,
  `PROCTOR_PASSBOOK_SECRETKEY_FILE`. 4 tests (incl. a roundtrip that asserts the
  on-disk file is ciphertext, not plaintext).

### Added — family sharing (`crates/passbook/src/sharing.rs`)
- **Per-recipient sealed-box key wrapping:** the 32-byte vault key is wrapped to
  each member via ephemeral X25519 + HKDF-SHA256 + XChaCha20-Poly1305, so only a
  member's private key can unwrap it. `Member`/`MemberPublic`/`SharedVault` with
  `share_to`/`unwrap_for`/`revoke`.
- **Account recovery is intrinsic:** any existing member can `grant_access` to a
  new member without the original key-holder. Secrets held in `Zeroizing`/zeroize
  on drop. 6 tests (member unwraps, non-member rejected, recovery re-grants).

### Added — WebAssembly bindings (`crates/passbook-wasm`)
- `wasm-bindgen` surface so the tested Rust crypto runs client-side:
  `password_strength`, `totp_code`, `totp_seconds_remaining`, `watchtower_json`,
  `seal_vault`, `open_vault`. Target-gated `getrandom` `js` feature for browser
  entropy; builds clean for `wasm32-unknown-unknown`. README with a full HTML
  usage example and `wasm-pack build --target web` instructions.

### Added — browser extension (`extension/`)
- Manifest V3 autofill extension for Proctor Passbook: content script detects
  username/password fields and fills them through the native value setter with
  proper `input`/`change` events (SPA-safe); `background.js` service worker relays
  popup→tab messages; a branded, theme-aware popup lists items with a
  "matches this site" indicator. Prototype uses demo data; README documents the
  native-messaging bridge a production build would use so secrets are never bundled.

### Notes
- Prototype crypto throughout `proctor-passbook`; a formal external review remains
  before any real use (tracked in the threat model).

## [1.11.0] — 2026-07-12

**Phase A kickoff — the consumer credential manager (the "1Password equivalent").**

The broker (Phase B) is the developer wedge; this begins the mainstream family
product, sharing the crypto core.

### Added — `proctor-passbook` (foundation, tested)
- **Rich item model:** logins (username/password/URLs/TOTP/passkey), secure notes,
  cards, identities — with titles, tags, favorites.
- **Secret Key (2SKD):** a 128-bit device key combined with the master password
  (`key = SHA256(argon2id(master) || secret_key)`), so a server breach yields
  uncrackable data even against a weak master — verified: right master but no
  Secret Key can't open. Emergency-Kit format + parse.
- **TOTP (RFC 6238):** rolling 2FA codes (verified against the RFC test vectors),
  so the manager shows codes inline — no separate authenticator app.
- **Watchtower:** weak-password (entropy) + reused-password analysis with a
  security score. 9 tests.

### Added — UX prototype
- A polished, interactive **web-vault UI prototype** (design artifact): 3-pane app
  shell, category nav, search, item detail with reveal/copy/live-TOTP, and a
  Watchtower security dashboard — the visible "1Password equivalent" to steer the UX.



The last two threat-model residuals (R4, R5).

### Added / hardened
- **R4 — signed audit log.** With `PROCTOR_AUDIT_KEY` (hex), the hash chain is
  **HMAC-SHA256**-signed instead of plain SHA-256, so an attacker with only
  filesystem write (no key) cannot forge a valid chain — tamper-*resistant*, not
  just tamper-evident. (`AuditLog::with_file_signed`, `Broker::with_audit_file_signed`.)
- **R5 — real STS XML parser.** The AWS `AssumeRoleWithWebIdentity` response is now
  parsed with `roxmltree` (namespace-agnostic on local name, scoped to
  `<Credentials>`), replacing the hand-rolled tag extractor; malformed/junk XML
  yields a clean error instead of silent mis-parse.

### Threat-model status
All seven expert findings (T1–T7) and all self-review residuals except a formal
external human review are now addressed. R4/R5 fixed here; R1 (zeroize), R2 (trust
gate), R3 (shell block) fixed earlier.



Supply-chain gate + lint hygiene.

### Added
- **Warden commit/push gate** (`.warden.yaml`): pre-commit runs `fmt --check` +
  `clippy -D warnings`; pre-push additionally runs the full test suite and a
  **nox security scan** (fails on active high findings). Provides commit
  provenance/attestation (SLSA/Sigstore-style). Every commit is now gated on a
  clean build, clean lint, green tests, and a clean security scan.

### Changed
- Codebase is now `cargo fmt`-clean and `clippy -D warnings`-clean; refreshed the
  `proctor-mcp` module docs to list the current tool + config surface.

## [1.9.0] — 2026-07-12

External security-expert review — all seven findings fixed — plus nox scanning.

### Security fixes (from red-team review; see THREAT-MODEL §6a)
- **T1 network egress:** untrusted mode now denies subprocess egress by default
  (container `--network none`, bubblewrap `--unshare-net`); `run_command` reports
  the `egress` posture. Isolation now contains the network, not just /proc + FS.
- **T2 origin-binding teeth:** the GitHub executor refuses an origin it doesn't
  actually serve — the credential is bound to the request *destination*, not a label.
- **T3 master + env inheritance:** master is read from `PROCTOR_MASTER_FILE` (not
  env/`/proc`); the runner **`env_clear()`s** the child and re-adds only a minimal
  baseline + the injected credential — the broker's env (incl. the master) no
  longer leaks into subprocesses.
- **T4 minter endpoints:** must be https (reject cleartext identity exfil).
- **T5 profile trust:** group/world-writable profile files are rejected at load.
- **T6 audit fail-open:** persistent-write failures surface as `audit_warning`.
- **T7 redaction:** documented as hygiene; real defense is T1 + short-TTL.

### Dependencies
- **jsonwebtoken 9.3.1 → 10.4.0** — clears **CVE-2026-25537** (type confusion in
  claim validation; not exploitable here, we only sign).

### Tooling
- **nox** security scanning wired in: **grade A, 0 active findings**
  (`docs/security/badge.svg`). Test fixtures scrubbed of secret-shaped strings;
  verified false positives baselined in `.nox/baseline.json`.



Trust gate for the exec path (threat-model R2).

### Added
- **`PROCTOR_TRUST=untrusted`** makes the safe posture enforceable: `run_command`
  is **refused** when isolation is `none`, directing the operator to set
  `PROCTOR_ISOLATION` (`docker:<image>` / `bwrap`) or explicitly choose trusted
  mode. Default remains trusted (local interactive use). The refusal is a hard
  gate at the top of the run path, before any credential is touched.



Zeroize secrets in memory (threat-model R1, the top open risk).

### Changed / hardened
- **Vault `Item.secret` is wiped on `Drop`**, and the **decrypted vault plaintext**
  is held in `Zeroizing` during load.
- **The broker's long-lived secret map** (`AppState.secrets`) and the transient
  `secret` / `inject` handles in `run_command` / `use_credential` are now
  `Zeroizing<String>` (minted token values already were).
- Result: secrets no longer linger as plain `String` in the long-lived stores; a
  core dump exposes far less. *Residual:* a few short-lived copies and `Item`'s
  `Debug` derive can still surface plaintext (follow-ups noted in the threat model).



Security review artifact + the first hardening it surfaced.

### Added
- **[Threat Model & Security Posture](docs/security/THREAT-MODEL.md)** — a rigorous
  self-review (STRIDE by component, trust boundaries, assumptions, prioritized
  residual risks R1–R7, recommendations, reviewer checklist). Frames an external
  review; explicitly not a substitute for one.

### Changed / hardened
- **Shell interpreters are blocked by default on `run_command`** (R3). A profile
  that authorizes `sh`/`bash`/`python`/… as the run program is refused unless it
  sets `allow_shell = true`, because a shell runs arbitrary work past
  command-binding. Allowed shells still carry a `shell_warning` in the response.
- Profiles gained an `allow_shell` field (default false) and `is_shell_interpreter`
  in `proctor-profiles`.

### Top open items for the auditor (from the threat model)
- R1 secrets not zeroized in memory · R2 `isolation=none` default · R4 audit log
  unsigned · R5 minimal STS XML parse. **A formal external security review + fuzzing
  remains required before any real use.**



Multi-field minted credentials + per-provider minter routing — the two edges
left open by v1.4.0.

### Added
- **`proctor-mint::aws` — AWS STS `AssumeRoleWithWebIdentity` minter.** Exchanges a
  held OIDC web-identity token for short-lived role credentials and emits the
  **trio** (access key id / secret / session token) as JSON, so a minted cred
  composes directly into a multi-field (`env_map`) profile. HTTP injected for
  offline tests; real reqwest behind `net`; wired via `PROCTOR_AWS_ROLE_ARN`.
- **Per-provider minter routing.** Provider profiles declare their minter with a
  `mint` field (`"github-app"`, `"token-exchange"`, `"aws-sts"`). The server keeps
  a minter map keyed by kind and routes each item's mint through
  `minter_for(provider)` — so an `aws` item mints via STS while a `github` item
  mints via the App, data-driven from the profile. Seed profiles updated (aws →
  `aws-sts`, github → `github-app`).

### Result
- Minted credentials now fill both single-token (`env_var`) and multi-field
  (`env_map`) profiles, and the minter is chosen per provider from external config.
  Verified end-to-end: an AWS item routes to the STS minter, the JSON trio composes
  into `AWS_ACCESS_KEY_ID`/`_SECRET_ACCESS_KEY`/`_SESSION_TOKEN`, redacted in output.

### Still deferred
- Per-item role/audience overrides (single global role/endpoint per kind today),
  Azure/GCP-specific minters, and a **formal security review before real use**.



Protocol minters + prefer-minted on the exec path (ADR-0002 Phase 3) — the last
unbuilt axis. ADR-0002 is now fully implemented.

### Added
- **`proctor-mint::exchange` — RFC 8693 OAuth 2.0 Token Exchange minter.** Present
  a held subject token (an OIDC identity / JWT) to an STS token endpoint and get a
  short-lived scoped access token. One minter, any conforming STS — the mechanism
  behind OIDC Workload Identity Federation (GCP WIF, generic STS). HTTP injected
  for offline tests; real reqwest form-post behind `net`. Wired via
  `PROCTOR_STS_ENDPOINT` (+ `_AUDIENCE` / `_SCOPE` / `_SUBJECT_TYPE`).
- **Prefer minted short-TTL creds on the `run_command` exec path.** A mintable
  item mints a short-lived token and injects *that* into the subprocess (not the
  durable secret), bounding how long a leaked value stays useful. Falls back to
  the stored secret for non-mintable items or multi-field profiles. Responses
  report `credential_source: minted | stored`.

### Result
- The exec-path security posture is complete: **OS isolation** (v1.3.0) contains
  *where* a credential can be scanned; **short-TTL minting** (this release) bounds
  *how long* a leaked one is useful. ADR-0002's five axes are all implemented.

### Still deferred (beyond ADR-0002)
- AWS `AssumeRoleWithWebIdentity` multi-field minting (the exchange minter returns
  a single access token today; multi-field cloud creds compose from JSON later),
  per-provider minter selection, and a **formal security review before real use**.



OS-level isolation for `run_command` (ADR-0002 Phase 4) — the exec path can now
run the credential-bearing command in a container/namespace, so `/proc` and the
filesystem don't cross to the host.

### Added
- **`Isolation` backend** (`proctor-mint::run`): `none` (default), `bubblewrap`
  (Linux user/pid/mount namespaces, remounted `/proc`), and `container`
  (docker/podman: separate `/proc` + filesystem, `--rm`). Configured via
  `PROCTOR_ISOLATION` = `none` | `bwrap` | `docker:<image>` | `podman:<image>`
  (network via `PROCTOR_ISOLATION_NETWORK`, default `bridge`).
- The credential is passed with `--env NAME` (value from the runtime's env),
  **never in argv** — verified by test that the secret value never appears in the
  wrapped command line.
- `run_command` responses now report the `isolation` posture; the server logs a
  warning when isolation is `none` (safe for trusted use only).

### Verified
- Real containerized run (docker:alpine): the command ran inside the container
  (confirmed via `/etc/alpine-release`), the credential injected via `--env`, and
  the output returned redacted.

### Still deferred
- **Prefer minted short-TTL creds on the exec path** + RFC 8693 / OIDC-WIF
  protocol minters (ADR-0002 Phase 3). Isolation + short-TTL together are the full
  posture for untrusted-content-driven autonomy; only isolation is done.



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
