# Proctor Passbook — Desktop shell (Tauri v2)

A native desktop wrapper around the **exact same** Proctor Passbook Vue 3 + Vite
web vault that lives in `../` (the `app/` directory). It does not fork or modify
the frontend: in development it loads the Vite dev server on
`http://localhost:5173`, and in a production build it serves the compiled assets
from `../dist`. The crypto core continues to run in-browser via the
`passbook-wasm` module — this shell adds only a native window.

## Dependency advisories (known, accepted)

`cargo audit` against this crate's lockfile reports the standard **gtk-rs 0.18 /
`unic-*` / `proc-macro-error`** advisory set (RUSTSEC-2024-0411..0420, -0370,
-0429; RUSTSEC-2025-0075..0100; GHSA-wrw7-89jp-8q8g). These come **transitively
from Tauri v2's Linux GTK backend** and are all *unmaintained*/*unsound*
classifications, not remote-exploitable vulnerabilities. They affect only this
detached desktop shell (its own Cargo workspace), never the core crates
(`proctor-passbook`, `proctor-sync`, `proctor-crypto`, the broker) or the
`proctor-sync-server`. On macOS the GTK backend isn't used at all (WebKit). They
are tracked and will clear when Tauri bumps its gtk-rs pins; see the repo's nox
baseline for the recorded rationale.

## Prerequisites

- **Rust** toolchain (stable, 1.90+) — <https://rustup.rs>
- **Node.js** + the app dependencies installed (`npm install` in `app/`)
- Platform WebView / build dependencies per the Tauri v2 guide:
  <https://v2.tauri.app/start/prerequisites/>
  - macOS: Xcode Command Line Tools
  - Linux: `webkit2gtk-4.1`, `libgtk-3`, `librsvg2`, `libayatana-appindicator3`
  - Windows: WebView2 runtime + MSVC build tools

## Running

All commands are run from the **`app/` directory** (one level up), because the
`tauri` CLI is wired into `app/package.json`:

```bash
cd app
npm install            # once — installs the frontend + @tauri-apps/cli

npm run tauri dev      # launches Vite (:5173) + the native window, hot-reload
npm run tauri build    # builds the frontend (npm run build) + a native bundle
```

`npm run tauri dev` triggers `beforeDevCommand` (`npm run dev`) and points the
window at `devUrl`; `npm run tauri build` triggers `beforeBuildCommand`
(`npm run build`) and packages `frontendDist` (`../dist`).

## Icons

Placeholder teal PNG icons are checked in under `icons/` so `tauri dev` and
`cargo check` work out of the box. The macOS `.icns` and Windows `.ico` bundle
targets referenced in `tauri.conf.json` are produced from a source PNG by the
Tauri CLI — run this once (from `app/`) to (re)generate the full platform set,
including `icon.icns` and `icon.ico`, from a real logo:

```bash
npm run tauri icon src-tauri/icons/icon.png
```

## Why a standalone Cargo workspace?

`Cargo.toml` starts with an empty `[workspace]` table. That deliberately
detaches this crate from the parent Proctor workspace at the repo root, so the
desktop shell's heavy GUI dependency tree is never pulled into — and cannot
break — the parent `cargo build`. Build the desktop shell from within
`app/src-tauri/` (or via the `npm run tauri` scripts), not from the repo root.

## Layout

```
src-tauri/
├── Cargo.toml              # standalone workspace + crate (lib + bin)
├── build.rs                # tauri_build::build()
├── tauri.conf.json         # Tauri v2 config (window, build hooks, bundle)
├── capabilities/
│   └── default.json        # minimal core + window permissions
├── icons/                  # placeholder PNGs (regenerate with `tauri icon`)
└── src/
    ├── main.rs             # binary entrypoint → lib::run()
    └── lib.rs              # tauri::Builder::default().run(...)
```
