# Proctor Passbook — Browser Extension (Prototype)

A Manifest V3 browser extension that autofills login credentials into web pages,
styled to match the Proctor Passbook brand.

> **This is a PROTOTYPE using demo data.** The vault items (GitHub, Netflix,
> Chase, Google, Amazon) and their passwords are **hardcoded placeholders** in
> `popup.js`. They are not real secrets and nothing here talks to an actual
> vault. See [Prototype note](#prototype-note) for how a production version would
> differ.

## What it does

- Click the toolbar icon to open a popup listing demo vault items.
- The popup detects the active tab's site and:
  - sorts and tags items that **match this site**, and
  - shows a "matches this site" banner (or a "login form detected" hint).
- Type in the search box to filter by name, username, or domain.
- Click an item to autofill the page's username and password fields. The content
  script fires proper `input`/`change` events so single-page-app frameworks
  (React, Vue, etc.) register the change.

## Load it unpacked in Chrome

1. Open `chrome://extensions` in Chrome (or any Chromium browser — Edge, Brave, Arc).
2. Toggle **Developer mode** on (top-right).
3. Click **Load unpacked**.
4. Select this `extension/` directory.
5. Pin **Proctor Passbook** from the extensions menu, then open any site with a
   login form (e.g. `github.com/login`) and click the icon.

To pick up code changes, click the **reload** (↻) button on the extension card.

### Firefox note

Firefox also supports MV3. Load via `about:debugging` → **This Firefox** →
**Load Temporary Add-on** → pick `manifest.json`. Firefox uses the `browser.*`
namespace but aliases `chrome.*`, so these scripts work as-is.

## How autofill works (message flow)

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

- **`popup.js`** never messages the tab directly. It sends a `relay` message to
  the background worker with the real payload.
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
| `background.js` | Service worker — relays messages, injects the content script on demand |
| `content.js` | Detects login fields, fills them, reports page origin |
| `popup.html` / `popup.css` / `popup.js` | The branded popup UI and vault logic |
| `icons/lock-*.png` | Teal lock action icon (16/32/48/128 px) |

## Permissions

| Permission | Why |
|------------|-----|
| `activeTab` | Interact with the tab the user is currently on when they click the icon |
| `storage` | Reserved for the vault-item cache / preferences (demo data is in-memory today) |
| `scripting` | Inject `content.js` into pages that loaded before the extension so fill still works |
| `host_permissions: ["<all_urls>"]` | Autofill must work on any login page the user visits |

## Prototype note

A production Passbook build would **not** hardcode credentials. Instead:

- The extension would request a decrypted secret from a **local vault bridge**
  (Chrome **native messaging** to a `proctor` host, or a `proctor-mcp`-style local
  service) only at fill time and only after explicit user action.
- Secrets would live in the encrypted vault, never inside the extension bundle or
  `chrome.storage`.
- Filling would be gated behind the vault being unlocked, with origin checks and
  optional per-fill confirmation to defend against clickjacking and phishing.
- Field matching would use saved per-item URL rules rather than heuristics alone.
