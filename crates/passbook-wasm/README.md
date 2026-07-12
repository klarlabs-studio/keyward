# passbook-wasm

WebAssembly bindings for **Proctor Passbook**, so the vault crypto, TOTP, and
Watchtower security analysis can run entirely client-side in a browser — no
server ever sees the master password or the plaintext entries.

This crate is a thin [`wasm-bindgen`] layer over [`proctor-passbook`]. The public
API takes and returns **JSON strings**, which keeps the JS interop boundary simple
and framework-agnostic.

> **Security note:** this exposes the *prototype* crypto in `proctor-passbook`
> (Argon2id, XChaCha20-Poly1305, optional Secret Key). It needs a formal review
> before real use. The browser prototype is **master-password only**; wiring the
> device Secret Key (2SKD) through these bindings is a planned follow-up.

## Exported functions

| Function | Signature (as seen from JS) | Description |
| --- | --- | --- |
| `password_strength` | `(password: string) => number` | Estimated password strength in bits (character-space × length). |
| `totp_code` | `(secret_base32: string, unix_time: number) => string \| undefined` | Current 6-digit / 30-second TOTP code. `undefined` if the secret is not valid base32. |
| `totp_seconds_remaining` | `(unix_time: number) => number` | Seconds left in the current 30-second TOTP window (for a countdown ring). |
| `watchtower_json` | `(entries_json: string) => string` | Runs Watchtower over a JSON array of entries; returns the findings as a JSON array. |
| `seal_vault` | `(entries_json: string, master: string) => string` (throws) | Seals entries under a master password; returns the `SealedVault` as JSON. Throws on error. |
| `open_vault` | `(sealed_json: string, master: string) => string` (throws) | Opens a sealed vault; returns the entries as JSON. Throws on a wrong password or tampering. |

`unix_time` is a JS `number` (seconds since the epoch); it is truncated to a whole
second inside the binding.

### Watchtower output shape

`watchtower_json` returns a JSON array of tagged issue objects:

```json
[
  { "kind": "weak", "id": "e2", "bits": 33 },
  { "kind": "reused", "ids": ["e2", "e3"] },
  { "kind": "missing2fa", "id": "e5" }
]
```

On malformed input it returns `{"error": "<message>"}` instead of throwing.

## Building

Install the wasm target once:

```bash
rustup target add wasm32-unknown-unknown
```

Plain Cargo build (produces a raw `.wasm` in `target/wasm32-unknown-unknown/`):

```bash
cargo build -p passbook-wasm --target wasm32-unknown-unknown
```

For a browser-ready package (JS glue + `.d.ts` + optimized `.wasm`), use
[`wasm-pack`]. From the workspace root:

```bash
# Install once: cargo install wasm-pack   (or: brew install wasm-pack)
wasm-pack build --target web crates/passbook-wasm
```

This writes an ES-module package to `crates/passbook-wasm/pkg/`
(`passbook_wasm.js`, `passbook_wasm_bg.wasm`, `passbook_wasm.d.ts`).

## Using it from a web page

`--target web` emits an ES module with a default `init()` export that loads the
`.wasm`. A minimal page:

```html
<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Passbook (WASM)</title></head>
  <body>
    <script type="module">
      import init, {
        password_strength,
        totp_code,
        totp_seconds_remaining,
        watchtower_json,
        seal_vault,
        open_vault,
      } from "./pkg/passbook_wasm.js";

      await init(); // loads and instantiates the .wasm module

      // Password strength (bits).
      console.log(password_strength("S7r0ng!Pass#word_2026"));

      // Current TOTP code + countdown.
      const now = Math.floor(Date.now() / 1000);
      console.log(totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now));
      console.log(totp_seconds_remaining(now));

      // A vault is a JSON array of Entry objects.
      const entries = [
        {
          id: "e1",
          title: "GitHub",
          tags: [],
          favorite: false,
          updated_epoch: 0,
          content: { Login: { username: "octo", password: "hunter2", urls: [] } },
        },
      ];

      // Watchtower security analysis.
      console.log(watchtower_json(JSON.stringify(entries)));

      // Seal, then re-open, entirely in the browser.
      const sealed = seal_vault(JSON.stringify(entries), "correct horse battery staple");
      const opened = JSON.parse(open_vault(sealed, "correct horse battery staple"));
      console.log(opened[0].title); // "GitHub"
    </script>
  </body>
</html>
```

Because a strict same-origin policy applies to ES modules and `fetch`, serve the
page over HTTP (e.g. `python3 -m http.server`) rather than opening it via
`file://`.

## Notes

- **Entropy on wasm:** salts and nonces come from `OsRng` (rand → getrandom). On
  `wasm32-unknown-unknown` there is no default entropy source, so this crate
  enables getrandom's `js` feature (Web Crypto `crypto.getRandomValues`) for wasm
  targets only. No change is needed on native targets.
- **Error handling:** `seal_vault` / `open_vault` throw a JS exception (a string)
  on failure; wrap them in `try/catch`. `watchtower_json` never throws.

[`wasm-bindgen`]: https://rustwasm.github.io/wasm-bindgen/
[`wasm-pack`]: https://rustwasm.github.io/wasm-pack/
[`proctor-passbook`]: ../passbook
