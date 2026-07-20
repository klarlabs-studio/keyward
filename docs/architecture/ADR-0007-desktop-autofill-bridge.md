# ADR-0007 — Desktop autofill bridge (extension ↔ app)

> **Status:** Proposed · **Date:** July 2026
> **Context:** [#13](https://github.com/klarlabs-studio/keyward/issues/13) · **Builds on:** `keyward_passbook::bridge` (the shared protocol, extracted in #14)

## Context

The browser extension autofills credentials by speaking a small native-messaging
protocol (`ping` / `list` / `get`) to a host process. Today that host is the
`passbook` CLI, which unlocks the vault by **reading the master password from a
file on disk** (`KEYWARD_PASSBOOK_MASTER_FILE`). The bridge's own comments flag
this as prototype-only, and it is the weakest link across all three surfaces: a
plaintext master password at rest, readable by any process running as the user.

The desktop app (Tauri v2, shipped in 2.1.0) changes what is possible. It is a
long-running process that can hold an **unlocked session in memory**, unlocked
once via the master password or biometrics, exactly as 1Password's desktop app
anchors its browser extension. The goal of this ADR is to decide **how the
extension reaches that held session**, and — the hard part — **what trust
boundary protects it**.

### The structural obstacle

Chrome launches a native-messaging host as a **short-lived process, one per
connection**, and communicates with it over that process's stdio. But the
unlocked session lives in the **long-running GUI process**. The launched host
and the session-holder are therefore different processes; the host cannot simply
read the session out of the GUI.

So a relay is unavoidable — the same shape 1Password uses with "1Password mini":

```
Chrome extension ──native messaging (stdio)──▶ connector (short-lived, no secrets)
                                                     │  local IPC
                                                     ▼
                                          agent (in the GUI app; holds the session)
```

- **connector** — the binary Chrome launches. Reads native-messaging frames from
  Chrome, forwards the JSON to the agent, relays the reply. Holds no secrets; it
  is a dumb pipe. Uses `keyward_passbook::bridge::{read_frame, write_frame}`.
- **agent** — a listener inside the running desktop app. On each request it calls
  `keyward_passbook::bridge::handle_request` against the held session and replies.
  This is why #14 extracted the protocol into the library: both the CLI host and
  this agent answer the extension identically, from one implementation.

## The security decision

The agent hands out plaintext passwords. Whatever it listens on, **it must not
answer arbitrary local processes** — or we have replaced "master password in a
file readable by any local process" with "vault queryable by any local process,"
which is no improvement.

### What we can and cannot defend against

The honest boundary, and 1Password documents the same one: **malware running as
the user, on an unlocked machine, cannot be fully excluded.** It can read the
connector's manifest, launch the connector, and impersonate the browser. Any
static shared secret placed in the manifest is readable by that same malware, so
it is not a secret from it. This is a platform limitation, not a design failure —
every password-manager browser bridge shares it.

What we *can* do is make the bridge no weaker than the platform's own same-user
boundary, remove the standing plaintext master password, and require the vault to
be **unlocked and the user present** for a secret to cross the pipe.

### Decision

1. **Transport: a user-private local socket.** Unix domain socket under a
   `0700` directory in the user's runtime dir (`$XDG_RUNTIME_DIR` / macOS
   equivalent); a named pipe with a user-only DACL on Windows. This gives the
   OS's same-user isolation for free — cross-user access is denied by the kernel.

2. **No plaintext master password at rest, ever.** The agent holds the session
   only in the running app's memory, unlocked interactively or by biometrics
   (Touch ID / Windows Hello) via a Tauri biometric plugin. Delete the
   `KEYWARD_PASSBOOK_MASTER_FILE` path from the distributed extension flow. (The
   CLI host may keep it as a documented headless/CI option — never the default.)

3. **Locked-by-default, present-to-fill.** `list` (metadata, no secrets) may
   answer while unlocked. `get` (the actual password) requires the session
   unlocked AND is surfaced as an explicit user pick in the extension UI — never
   an automatic, silent fill. Habituation is the enemy (see ADR-0001); the human
   action is the pick, not a rubber-stamp dialog.

4. **Origin binding at the source.** The extension only ever asks `list` for the
   **current page's origin**, and `get` for an id the user picked from that list.
   The agent does not expose "dump everything." A confused/hostile connector can
   at most replay the same origin-scoped queries the page already sees — the same
   phishing-resistance principle as ADR-0001 §2.

5. **Peer verification, best-effort and layered — NOT relied upon.** Where the
   platform allows, the agent checks the connecting process (`SO_PEERCRED` uid on
   Linux; code-signature / bundle-id verification of the connector on macOS and
   Windows, as 1Password does). Documented explicitly as raising the bar against
   casual local processes, **not** as a guarantee against determined same-user
   malware — because it isn't one, and claiming otherwise would be the kind of
   security theater this project rejects.

### Explicitly out of scope

Defending an **unlocked vault on a malware-infected machine under the user's own
account.** No password manager solves this; 1Password says so plainly. The
mitigation is the same for all of them: lock the vault, and don't run malware.
We document it rather than pretend otherwise.

## Consequences

- The prototype's single worst property — a master password sitting in a
  plaintext file — is removed. That is the concrete security win, independent of
  the residual same-user question.
- The relay reuses the extracted `bridge` protocol, so the extension sees
  identical behavior from the CLI host and the desktop agent; they cannot drift.
- New moving parts: a connector binary, an agent listener in the Tauri app, a
  biometric-unlock integration, and a revised native-host manifest pointing at
  the connector. Each is its own implementation slice under #13.
- Biometric unlock is the piece with the least test automation (it needs the GUI
  and real hardware); its slice must budget for manual verification, and say so.

## Alternatives considered

- **Chrome launches the app binary directly as the host.** Fails: the launched
  process is not the one holding the session, so it would have to re-unlock per
  connection — back to prompting or a file.
- **A localhost HTTP/WebSocket server (1Password's original 2015 design).** Any
  web page can attempt to connect to `localhost`; native messaging is
  extension-id-pinned in the host manifest and not reachable from page
  JavaScript. Native messaging is the stronger default, so the relay's
  browser-facing side stays native-messaging, not HTTP.
- **Keep the master-password-file bridge.** Rejected — it is the status quo this
  ADR exists to end.
