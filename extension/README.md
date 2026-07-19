# Keyward Passbook — Browser Extension (Prototype)

A Manifest V3 browser extension that autofills login credentials into web pages,
styled to match the Keyward Passbook brand.

> **This is a PROTOTYPE.** It now reads real vault items from a local **native
> messaging bridge** (`passbook bridge`), but the host wrapper unlocks the vault
> from a master-password file, which is demo-only — see
> [`native-host/README.md`](native-host/README.md). If the bridge is not
> installed, the popup **falls back to hardcoded demo data** (GitHub, Netflix,
> Chase, Google, Amazon) so the flow still demos. See
> [Prototype note](#prototype-note).

## What it does

- Click the toolbar icon to open a popup. The popup:
  - resolves the active tab's origin and asks the local Passbook bridge for a
    **`list`** of logins that match this site (titles and usernames only — **no
    passwords** cross this boundary until fill time),
  - tags matching items with a "This site" badge, and
  - shows a "matches this site" banner (or a "login form detected" hint).
- If the bridge is unavailable, a subtle *"Passbook bridge not connected —
  showing demo items"* banner appears and the demo vault is used instead.
- Type in the search box to filter by name, username, or domain/URL.
- Click an item to autofill. For a live item the popup requests **`get`** for its
  id (fetching the secret only now, at fill time) and relays the credentials to
  the page. The content script fires proper `input`/`change` events so
  single-page-app frameworks (React, Vue, etc.) register the change.

## Load it unpacked in Chrome

1. Open `chrome://extensions` in Chrome (or any Chromium browser — Edge, Brave, Arc).
2. Toggle **Developer mode** on (top-right).
3. Click **Load unpacked**.
4. Select this `extension/` directory.
5. Pin **Keyward Passbook** from the extensions menu, then open any site with a
   login form (e.g. `github.com/login`) and click the icon.

To pick up code changes, click the **reload** (↻) button on the extension card.

### Connect the vault bridge (optional but recommended)

Out of the box the popup shows demo data. To read your real vault, install the
native-messaging host: see [`native-host/README.md`](native-host/README.md) for
per-OS install steps, building the `passbook` binary
(`cargo build -p passbook-cli --release`), and wiring the extension ID into the
host manifest's `allowed_origins`. Once installed, the popup prefers the live
bridge automatically and drops the demo banner.

### Firefox note

Firefox also supports MV3. Load via `about:debugging` → **This Firefox** →
**Load Temporary Add-on** → pick `manifest.json`. Firefox uses the `browser.*`
namespace but aliases `chrome.*`, so these scripts work as-is.

## How it works (message flow)

**Listing items (popup open) and fetching a secret (on click):**

```
popup.js  ──(runtime.sendMessage {type:"native", payload:{type:"list", origin}})──►  background.js
                                                                                          │
                          chrome.runtime.sendNativeMessage(                              │
                            "com.klarlabs.keyward.passbook", …)                          ▼
                                                                              native host: passbook bridge
                                                                                          │
                              {items:[{id,title,username,url,hasTotp}]}  (no secrets)     ▼
popup.js  ◄──────────────────────────────────────────────────────────────────────  background.js

  (on click)  {type:"native", payload:{type:"get", id}}  →  bridge  →  {id,username,password,totp}
```

**Filling the page (unchanged relay path):**

```
popup.js  ──(runtime.sendMessage {type:"relay", payload:{type:"fill",…}})──►  background.js
                                                                                   │
                                              chrome.scripting (ensure injected)   │
                                                                                   ▼
background.js  ──(tabs.sendMessage {type:"fill", username, password})──►  content.js (active tab)
                                                                                   │
                                                    fills fields, dispatches events│
                                                                                   ▼
content.js  ──(sendResponse {ok, filledUsername, filledPassword, origin})──►  background.js  ──►  popup.js
```

- **`popup.js`** never messages the tab or the native host directly. It sends
  `native` messages (vault `list`/`get`) and `relay` messages (page `fill`/
  `probe`) to the background worker.
- The **`list`** response carries **no passwords**; the secret is fetched with
  **`get`** only when the user clicks to fill, handed straight to the content
  script, and never logged or stored.
- **`background.js`** (the MV3 service worker) resolves the active tab, makes sure
  `content.js` is present (injecting it via `chrome.scripting` for pages that
  loaded before the extension), forwards the payload, and passes the response back.
- **`content.js`** finds the username field (`input[type=email]`,
  `input[name*=user|email|login]`, `autocomplete="username"`, …) and the
  `input[type=password]`, preferring fields inside the same `<form>`. It sets
  values through the native value setter and dispatches `keydown`/`keyup`/
  `input`/`change` so the site's JS notices.
- A `probe` message uses the same relay path so the popup can learn the page's
  origin/hostname and whether a login form is present.

## Files

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest: permissions, background worker, content script, action/popup, icons |
| `background.js` | Service worker — relays fill/probe to the tab and proxies `list`/`get` to the native host |
| `content.js` | Detects login fields, fills them, reports page origin |
| `popup.html` / `popup.css` / `popup.js` | The branded popup UI and vault logic (live bridge + demo fallback) |
| `native-host/` | Native-messaging host manifest template, bridge wrapper, and install guide |
| `icons/lock-*.png` | Teal lock action icon (16/32/48/128 px) |

## Permissions

| Permission | Why |
|------------|-----|
| `activeTab` | Interact with the tab the user is currently on when they click the icon |
| `storage` | Reserved for preferences (no secrets are stored) |
| `scripting` | Inject `content.js` into pages that loaded before the extension so fill still works |
| `nativeMessaging` | Talk to the local Passbook bridge (`com.klarlabs.keyward.passbook`) for `list`/`get` |
| `host_permissions: ["<all_urls>"]` | Autofill must work on any login page the user visits |

## Prototype note

The extension now reads real vault items from a **local native-messaging bridge**
(`passbook bridge`), preferring it over the demo data whenever it responds. What
still makes this a prototype:

- **Bridge unlock is demo-only.** The host wrapper unlocks the vault from a
  master-password file on disk. A production host would hold an unlocked session
  (OS keychain / agent) or prompt the user to unlock, never keeping the master
  password in a readable file. See
  [`native-host/README.md`](native-host/README.md).
- The demo fallback still ships hardcoded placeholder credentials in `popup.js`
  for when the bridge is not installed.
- A production build would additionally gate filling behind explicit per-fill
  confirmation, stronger origin checks, and saved per-item URL rules rather than
  field heuristics alone.

What is already true today:

- Secrets live in the vault, never in the extension bundle or `chrome.storage`.
- The `list` response carries no passwords; a secret is fetched with `get` only
  at fill time, handed straight to the content script, and never logged or stored.
- Native messaging (not a localhost HTTP server) means only this browser plus the
  extension ID pinned in the host's `allowed_origins` can invoke the bridge —
  arbitrary web pages cannot.
