# Keyward Passbook — Native Messaging Host

This directory holds the **native-messaging host** that lets the Keyward Passbook
browser extension read real vault items from your local machine instead of the
hardcoded demo data.

Chrome talks to a local binary over stdio using its
[native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
protocol. The extension sends JSON requests; the host (`passbook bridge`) replies
with JSON.

> **Prototype.** This host is wired for a demo. In particular the wrapper unlocks
> the vault from a **master-password file on disk** — convenient, but *not*
> production-safe. See [Security caveat](#security-caveat).

## Why native messaging (not a localhost server)

Only the specific browser plus the extension ID pinned in `allowed_origins` can
launch this host. Arbitrary web pages — and other local programs — cannot invoke
it, and there is no open TCP port for anything on the machine to connect to. A
localhost HTTP server would be reachable by any page or process on the box.

## Protocol

The host reads one JSON request and writes one JSON response per message:

| Request | Response |
|---------|----------|
| `{"type":"ping"}` | `{"ok":true,"version":"<semver>"}` |
| `{"type":"list","origin":"<active tab url/origin>"}` | `{"items":[{"id","title","username","url","hasTotp"}]}` — logins whose stored URL matches the tab host. **No passwords.** |
| `{"type":"get","id":"<id>"}` | `{"id","username","password","totp":"<string\|null>"}` — secrets, fetched only at fill time. |

The extension requests `list` when the popup opens (titles/usernames only) and
`get` only when the user clicks an item to fill.

## Files

| File | Role |
|------|------|
| `com.klarlabs.keyward.passbook.json` | Native-host manifest **template**. Copy it into the browser's `NativeMessagingHosts` directory and fill in the two placeholders. |
| `keyward-passbook-bridge.sh` | Wrapper Chrome executes. Sets the vault env, then `exec`s `passbook bridge`. Already `chmod +x`. |

## Install

### 1. Build the `passbook` binary

From the repository root:

```bash
cargo build -p passbook-cli --release
```

This produces `target/release/passbook`. The wrapper script finds it via `PATH`
first, otherwise falls back to `../../target/release/passbook` relative to
itself. To use `PATH`, either copy the binary somewhere on your `PATH` or add
`target/release` to it.

### 2. Point the wrapper at your vault

Edit `keyward-passbook-bridge.sh` (or export these before Chrome launches) so the
vault environment variables match your setup:

- `KEYWARD_PASSBOOK` — path to the vault file/directory.
- `KEYWARD_PASSBOOK_MASTER_FILE` — path to a file containing the master password
  (**prototype only** — see caveat).
- `KEYWARD_PASSBOOK_SECRETKEY_FILE` — path to a file with the vault secret key, if
  your vault uses a separate key.

### 3. Fill in the host manifest

Edit `com.klarlabs.keyward.passbook.json`:

- **`path`** → the **absolute** path to `keyward-passbook-bridge.sh`, e.g.
  `/Users/you/dev/keyward/extension/native-host/keyward-passbook-bridge.sh`.
  (Chrome requires an absolute path; a relative path will silently fail.)
- **`allowed_origins`** → replace `EXTENSION_ID_HERE` with the real extension ID.
  Load the extension unpacked (see `../README.md`), open `chrome://extensions`,
  enable Developer mode, and copy the **ID** shown on the Keyward Passbook card.
  Keep the trailing slash: `chrome-extension://<id>/`.

### 4. Install the manifest for your browser + OS

Copy (or symlink) the filled-in `com.klarlabs.keyward.passbook.json` into the
browser's `NativeMessagingHosts` directory. The file's **name must match the host
name** (`com.klarlabs.keyward.passbook.json`).

**macOS**

- Chrome: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
- Chromium: `~/Library/Application Support/Chromium/NativeMessagingHosts/`
- Edge: `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/`

```bash
mkdir -p "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
cp com.klarlabs.keyward.passbook.json \
  "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/"
```

**Linux**

- Chrome: `~/.config/google-chrome/NativeMessagingHosts/`
- Chromium: `~/.config/chromium/NativeMessagingHosts/`

```bash
mkdir -p "$HOME/.config/google-chrome/NativeMessagingHosts"
cp com.klarlabs.keyward.passbook.json \
  "$HOME/.config/google-chrome/NativeMessagingHosts/"
```

### 5. Reload and test

Fully quit and reopen the browser (native-host manifests are read at startup),
then open the extension popup on a site you have a login for. If the bridge is
reachable, real vault items appear; otherwise the popup shows
*"Passbook bridge not connected — showing demo items"* and falls back to demo
data.

## Troubleshooting

- **Still seeing demo items?** Confirm the manifest filename, the absolute
  `path`, and that the `allowed_origins` ID exactly matches
  `chrome://extensions`. Restart the browser after any change.
- **Host not found / access denied.** Ensure `keyward-passbook-bridge.sh` is
  executable (`chmod +x`) and the `passbook` binary exists and is runnable.
- **Test the host directly** (native messaging frames a 4-byte little-endian
  length before the JSON):

  ```bash
  printf '\x0f\x00\x00\x00{"type":"ping"}' | ./keyward-passbook-bridge.sh
  ```

## Security caveat

The wrapper unlocks the vault from a plaintext **master-password file**
(`KEYWARD_PASSBOOK_MASTER_FILE`). This is a prototype convenience only.

A production host would instead:

- hold an **unlocked session** (an agent process, or the OS keychain) rather than
  read the master password from disk, and/or
- **prompt the user** to unlock at first use, keeping the master password out of
  any file the bridge can read;
- scope every `get` to an explicit user action, and never log or persist the
  returned secret.
