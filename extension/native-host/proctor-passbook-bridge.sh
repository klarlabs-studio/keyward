#!/usr/bin/env bash
#
# Proctor Passbook — native-messaging bridge wrapper
# ==================================================
#
# Chrome launches this script (the `path` in the native-host manifest) and
# speaks the native-messaging protocol over stdin/stdout. This wrapper only sets
# up the vault environment and then hands stdio to `passbook bridge`, which
# implements the actual JSON protocol (ping / list / get).
#
# Chrome invokes the host with the calling extension's origin as the first
# argument ($1), e.g. `chrome-extension://<id>/`. The bridge does NOT need it
# (Chrome already enforces `allowed_origins` in the manifest), so we ignore it.
#
# ---------------------------------------------------------------------------
# PROTOTYPE SECURITY CAVEAT
# ---------------------------------------------------------------------------
# This wrapper unlocks the vault by pointing `passbook` at a master-password
# file on disk (PROCTOR_PASSBOOK_MASTER_FILE). That is convenient for a demo but
# is NOT how a production host should work: a real host would hold an unlocked
# session (e.g. via the OS keychain / an agent process) or interactively prompt
# the user to unlock, and would never keep the master password in a plaintext
# file readable by the bridge process. Treat the file approach as prototype-only.
# ---------------------------------------------------------------------------
#
# Environment (edit to match your setup):
#   PROCTOR_PASSBOOK             Path to the vault file/directory.
#   PROCTOR_PASSBOOK_MASTER_FILE Path to a file containing the master password
#                                (prototype only — see caveat above).
#   PROCTOR_PASSBOOK_SECRETKEY_FILE
#                                Path to a file containing the vault secret key,
#                                if your vault is protected by a separate key.

set -euo pipefail

# Chrome passes the caller origin as $1 — intentionally unused.
: "${1:-}"

# --- Vault configuration ----------------------------------------------------
# Point these at your real vault. Defaults assume a per-user layout under
# ~/.config/proctor/passbook; change as needed.
export PROCTOR_PASSBOOK="${PROCTOR_PASSBOOK:-$HOME/.config/proctor/passbook/vault}"
export PROCTOR_PASSBOOK_MASTER_FILE="${PROCTOR_PASSBOOK_MASTER_FILE:-$HOME/.config/proctor/passbook/master}"
export PROCTOR_PASSBOOK_SECRETKEY_FILE="${PROCTOR_PASSBOOK_SECRETKEY_FILE:-$HOME/.config/proctor/passbook/secretkey}"

# --- Locate the passbook binary ---------------------------------------------
# Prefer a `passbook` on PATH; otherwise fall back to a release build sitting in
# the repo's target/ directory relative to this script.
if command -v passbook >/dev/null 2>&1; then
  PASSBOOK_BIN="$(command -v passbook)"
else
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
  PASSBOOK_BIN="${SCRIPT_DIR}/../../target/release/passbook"
fi

# Hand stdio to the bridge. `exec` replaces this shell so Chrome talks directly
# to the binary (no extra process in the pipe).
exec "${PASSBOOK_BIN}" bridge
