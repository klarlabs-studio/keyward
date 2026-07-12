# Proctor — Threat Model & Security Posture

> **Status:** v1 (self-review) · **Date:** July 2026 · **Scope:** the credential
> broker (v1.5.0). This is a self-assessment to frame an **external security
> review** — it is *not* a substitute for one. Proctor must not hold real
> credentials in production until independently audited.

## 1. What Proctor is (asset & purpose)

Proctor lets an AI agent *act* with a credential without the credential entering
the model's context. The **primary asset** is the set of stored secrets (vault
items) and any short-lived tokens derived from them. The **primary guarantee** is:
*a credential's plaintext never appears in a tool response* — the model gets a
result or a scoped handle, never a value.

## 2. Trust boundaries

```
[ model / agent ]  ──MCP (stdio/JSON-RPC)──▶  [ proctor-mcp process ]  ──▶ [ subprocess / HTTP / STS ]
   untrusted-ish                                 trusted core                target systems
   (prompt-injectable)                           holds unlocked secrets
```

- **B1 — model ↔ broker.** The model is treated as *potentially manipulated*
  (prompt injection). It may call any tool with any arguments.
- **B2 — broker ↔ vault.** Secrets are decrypted into the broker's memory on load.
- **B3 — broker ↔ target (subprocess / HTTP / STS).** The credential is used here;
  for `run_command` the target subprocess is *itself agent-controlled*.
- **B4 — broker ↔ human.** Step-up approval crosses to a human via elicitation.

## 3. STRIDE by component

### Broker decision core (`proctor-broker`)
- **Spoofing / confused deputy:** a manipulated agent uses the right credential
  against the wrong target. **Mitigated** by origin-binding (`use_credential`) and
  command-binding (`run_command`) — checked *before* policy and independent of any
  approval. *Residual:* binding is only as tight as the item's `bound_origins` /
  the profile's `commands`; authorizing a shell (§6) widens it.
- **Elevation / autonomy:** an agent runs an irreversible action unattended.
  **Mitigated** by the never-unattended floor + propose-not-commit (downgrade to a
  reviewable artifact) + risk-tiered policy. *Residual:* classification correctness
  (ADR-0001 §"where the tension relocates").
- **Repudiation:** **Mitigated** by the hash-chained audit log. *Residual:* the
  on-disk log is integrity-*evident* (chain) but not signed — an attacker with FS
  write can truncate/replace it and re-chain from a forged genesis.

### Secret handling (`proctor-vault`, broker state)
- **Information disclosure — response channel:** **Mitigated** — no allow path
  returns plaintext; minted values are `masked()`; `run_command` **redacts**
  injected values from stdout/stderr. `want_raw_secret` is hard-denied by default.
- **Information disclosure — memory:** **Mitigated (v1.7.0):** the long-lived
  stores are zeroized — vault `Item.secret` wipes on `Drop`, the decrypted vault
  plaintext is `Zeroizing`, and the broker's `secrets` map + transient
  `secret`/`inject` handles are `Zeroizing<String>` (minted token values already
  were). *Residual:* a few short-lived `String` copies (the input map handed to
  the server, and the `#[derive(Debug)]` on `Item`) can still surface plaintext;
  a same-process compromise / debugger remains out of scope (host is trusted).
- **Tampering — vault file:** AEAD detects modification (open fails). *Residual:*
  no rollback protection (an old sealed vault can be substituted).

### Minting (`proctor-mint`: github / exchange / aws)
- **Blast-radius minimization:** **Mitigated** — minted tokens are short-TTL and
  scoped (bounds a leak's usefulness); preferred on the exec path.
- **Spoofing the STS/exchange:** *Assumption* — the token endpoints are trusted and
  reached over TLS (reqwest rustls). A hostile endpoint could issue attacker tokens;
  endpoint config must be trusted input.
- **XML/JSON parsing:** the AWS STS parse is a minimal tag extractor. *Residual:*
  not a hardened XML parser; malformed/hostile STS responses are low-risk (we only
  read three fields) but should move to a real parser before production.

### Execution — HTTP (`proctor-mint::exec`)
- **Confused deputy:** origin-bound; the executor only performs the vetted op.
  **Mitigated.**

### Execution — subprocess (`proctor-mint::run`, `run_command`)
- **This is the highest-risk surface.** The agent controls the program + argv, and
  the credential is injected into the child's environment.
- **Information disclosure via /proc, ps, child inheritance:** env injection is
  *hygiene, not a boundary* (ADR-0002). **Partially mitigated** by: injecting via
  env only (never argv — `/proc/cmdline` is world-readable), preferring minted
  short-TTL creds (bounds duration), and **OS-level isolation** (namespace /
  container) that contains `/proc` + filesystem. *Residual:* the default is
  `isolation=none` (safe only for trusted use); untrusted autonomy **requires**
  `PROCTOR_ISOLATION` be set.
- **Command-binding bypass via shells:** authorizing an interpreter (`sh`, `python`,
  …) lets `sh -c '<anything>'` run past argv risk classification. **Mitigated**
  (v1.6.0): shells are **blocked by default** — a profile must set
  `allow_shell = true` to permit one, and even then the response carries a
  `shell_warning`. *Residual:* an operator who sets `allow_shell` on a
  broadly-scoped credential re-opens the bypass — a deliberate, visible choice.
- **Redaction completeness:** only injected *values* are redacted; a command that
  transforms the secret (base64, reversal) could still emit it. *Residual, low* —
  the real defense is short-TTL + not returning to the model, not string redaction.

### MCP surface (`proctor-mcp`)
- **DoS:** unbounded output is capped (8 KB/stream). Concurrent tool calls share a
  Mutex; no rate limiting. *Residual, low.*
- **Elicitation absence:** if the client can't elicit, step-up falls back to a
  *note* (safe default — the action does not proceed).

## 4. Key assumptions

1. The **host and OS user** running `proctor-mcp` are trusted (secrets are
   decrypted in this process). Proctor defends the *model/agent* boundary, not a
   compromised host.
2. **`PROCTOR_MASTER`** and the token-endpoint / role config are trusted inputs.
3. TLS to STS / provider APIs is intact (rustls).
4. For untrusted-content-driven autonomy, `PROCTOR_ISOLATION` is set to a real
   backend and profiles authorize *specific tools*, not shells.

## 5. Residual risks (prioritized for the auditor)

| # | Risk | Severity | Status |
|---|---|---|---|
| R1 | Secrets not zeroized in memory (core dump / debugger) | High | Mitigated (v1.7.0); residual transient copies + Debug derive |
| R2 | `isolation=none` default; env injection recoverable via /proc | High (untrusted) | Mitigated *if configured* |
| R3 | Shell-interpreter authorization bypasses command-binding | High | Blocked by default (v1.6.0); opt-in via `allow_shell` |
| R4 | Audit log not signed (FS-write attacker can forge) | Medium | Evident, not tamper-*proof* |
| R5 | AWS STS response parsed with a minimal extractor | Low | Works; harden before prod |
| R6 | No vault rollback protection | Low | Open |
| R7 | Classification correctness (risk patterns / never-unattended set) | Medium | Ongoing |

## 6. Recommendations before real use

1. ✅ **Done (v1.7.0):** secrets zeroized in memory (`Item.secret` `Drop` +
   `Zeroizing` for the broker's secret map, handles, and decrypted plaintext).
   Follow-up: redact `Item`'s `Debug`, and zeroize the transient input map.
2. ✅ **Done (v1.6.0):** shell-interpreter authorization is blocked unless the
   profile sets `allow_shell = true` — addresses R3.
3. **Sign the audit log** (or ship to an append-only external sink) — R4.
4. **Real XML parser** for STS — R5.
5. **External security review + fuzzing** of the parsers and the policy engine.
6. Default-deny posture check: ship with `isolation` guidance and refuse
   `run_command` for untrusted contexts when `isolation=none` (config gate).

## 7. Reviewer checklist

- [ ] Confirm no allow path can emit plaintext (grep the response builders).
- [ ] Confirm origin/command binding precedes policy and is independent of approval.
- [ ] Confirm minted values + injected env values are redacted everywhere they surface.
- [ ] Confirm `want_raw_secret` and shell authorization behave as documented.
- [ ] Exercise the isolation backends (bwrap / container) for `/proc` + FS containment.
- [ ] Fuzz: STS XML parse, profile TOML, MCP argument handling.
- [ ] Verify audit chain detects reordering/truncation; assess signing need.

---

*Referenced designs: [ADR-0001 broker security model](../architecture/ADR-0001-broker-security-model.md),
[ADR-0002 scaling credential use](../architecture/ADR-0002-scaling-credential-use.md).*
