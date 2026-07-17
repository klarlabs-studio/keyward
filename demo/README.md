# Proctor Passbook — demo environment

The production app ships **no demo data**: a fresh device creates a real, empty
vault. This directory spins up a throwaway demo whose data lives entirely in a
container — the app image and code are unchanged; only the *data* is injected, at
the sync server.

## What it runs

- **sync** — the zero-knowledge `proctor-sync-server` (stores only ciphertext).
- **seeder** — a one-shot job that builds a **real 2SKD-sealed** demo vault with
  the `passbook` CLI (several logins with generated passwords + a TOTP), registers
  a demo account, and uploads the sealed blob. It writes the demo credentials to
  `demo/out/credentials.txt`.
- **web** — the built web vault served by nginx on `:8080`.

## Run

```bash
# 1. Build the web app once (needs Node + the Rust wasm toolchain on the host):
cd app && npm ci && npm run build:wasm && npm run build && cd ..

# 2. Bring up the demo:
docker compose -f demo/docker-compose.demo.yml up --build
```

Then read `demo/out/credentials.txt` and open <http://localhost:8080>. Choose
**Cloud sync ▸ Link this device**, paste the server URL + demo device token, and
unlock with the demo master password + Secret Key printed there.

## Reset / tear down

```bash
docker compose -f demo/docker-compose.demo.yml down -v
rm -f demo/out/credentials.txt
```

## Why it's structured this way

Per the project's demo-data policy: the application code stays free of mock data,
so what you demo is exactly what ships. The demo vault is sealed with the real
crypto and served over the real zero-knowledge sync path — the server never sees
the master password or Secret Key, only the opaque blob.
